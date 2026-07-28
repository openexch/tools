// SPDX-License-Identifier: Apache-2.0
package com.openexchange.tbbench;

import com.tigerbeetle.AccountBatch;
import com.tigerbeetle.AccountFlags;
import com.tigerbeetle.Client;
import com.tigerbeetle.CreateAccountResultBatch;
import com.tigerbeetle.CreateAccountStatus;
import com.tigerbeetle.CreateTransferResultBatch;
import com.tigerbeetle.CreateTransferStatus;
import com.tigerbeetle.TransferBatch;
import com.tigerbeetle.TransferFlags;
import com.tigerbeetle.UInt128;

import org.HdrHistogram.Histogram;

import java.util.ArrayDeque;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.LockSupport;

/**
 * Two-phase TigerBeetle benchmark driver for the Open Exchange ledger evaluation.
 *
 * <p>Measures what the built-in {@code tigerbeetle benchmark} cannot:
 * <ul>
 *   <li><b>latency</b> — open-loop, coordinated-omission-safe hold-path latency
 *       (one PENDING transfer round-trip). This is the number that decides whether
 *       TB's hold is fast enough to run synchronously and skip the co-located
 *       Aeron reservation.</li>
 *   <li><b>throughput</b> — sustained pending / post_pending / void_pending at our
 *       measured production op-mix (1 hold : ~0.39 settle : ~0.37 release).</li>
 * </ul>
 *
 * <p>Ledger model: one TB ledger per asset, one operator + one clearing + N user
 * accounts per ledger. A HOLD is a PENDING transfer user-&gt;clearing (debits_pending
 * on the user == our {@code locked}); a SETTLE is a partial POST_PENDING_TRANSFER;
 * a RELEASE is a VOID_PENDING_TRANSFER. (Accounting delivery legs are omitted — this
 * driver measures TB's cost of the lifecycle op-types at the right proportions, not
 * end-to-end conservation, which the ported durability harness checks separately.)
 */
public final class TbBench {

    // Fixed-point-ish demo amounts (8dp longs fit u64 comfortably).
    static final long FUND_PER_USER = 1_000_000_000_000L;
    static final long HOLD_AMOUNT = 1_000L;
    static final long POST_AMOUNT = 700L; // partial fill; remainder auto-voids

    // Op-mix weights (holds : settles : releases) measured live from tools/market-sim.
    static final double W_HOLD = 1.00;
    static final double W_POST = 0.39;
    static final double W_VOID = 0.37;
    static final double W_SUM = W_HOLD + W_POST + W_VOID;

    // Transfer-id space (separate namespace from account ids). Seed from wall-clock
    // so ids are unique ACROSS JVM runs against the same (persistent) data file —
    // otherwise a second run's transfers collide with the first's (Exists errors).
    static final AtomicLong ID = new AtomicLong(System.currentTimeMillis() * 1_000_000L);

    static long nextId() {
        return ID.getAndIncrement();
    }

    // Account-id scheme: ledger * 1e7 + slot. slot 0 = operator, 1 = clearing, 10.. = users.
    static long operatorId(int ledger) {
        return (long) ledger * 10_000_000L + 0;
    }
    static long clearingId(int ledger) {
        return (long) ledger * 10_000_000L + 1;
    }
    static long userId(int ledger, int u) {
        return (long) ledger * 10_000_000L + 10 + u;
    }

    public static void main(String[] args) throws Exception {
        String mode = args.length > 0 ? args[0] : "help";
        Args a = new Args(args);
        String address = a.str("address", "3033");
        long cluster = a.lng("cluster", 0);
        int ledgers = a.i("ledgers", 6);
        int users = a.i("users", 200);

        byte[] clusterId = UInt128.asBytes(cluster);
        String[] addresses = address.split(","); // full replica list for a cluster (order significant)

        System.out.printf("tb-bench mode=%s address=%s cluster=%d ledgers=%d users=%d%n",
                mode, address, cluster, ledgers, users);

        try (var client = new Client(clusterId, addresses)) {
            switch (mode) {
                case "setup" -> setup(client, ledgers, users);
                case "latency" -> {
                    setup(client, ledgers, users);
                    latency(client, ledgers, users,
                            a.i("rate", 5000), a.i("duration", 30), a.i("threads", 16));
                }
                case "throughput" -> {
                    setup(client, ledgers, users);
                    throughput(client, ledgers, users,
                            a.i("duration", 30), a.i("threads", 16), a.i("batch", 8189));
                }
                default -> {
                    System.out.println("""
                        usage: tb-bench <setup|latency|throughput> [--k v ...]
                          --address 3033   --cluster 0   --ledgers 6   --users 200
                          latency:    --rate 5000  --duration 30  --threads 16
                          throughput: --duration 30 --threads 16  --batch 8189
                        """);
                }
            }
        }
    }

    // ---- setup: create accounts + fund users (idempotent on re-run) ----
    static void setup(Client client, int ledgers, int users) throws InterruptedException {
        System.out.println("setup: creating accounts...");
        int perLedger = 2 + users;
        for (int l = 1; l <= ledgers; l++) {
            AccountBatch batch = new AccountBatch(perLedger);
            addAccount(batch, operatorId(l), l);
            addAccount(batch, clearingId(l), l);
            for (int u = 0; u < users; u++) addAccount(batch, userId(l, u), l);
            CreateAccountResultBatch res = client.createAccounts(batch);
            int failures = 0;
            while (res.next()) {
                CreateAccountStatus s = res.getStatus();
                if (s != CreateAccountStatus.Created && s != CreateAccountStatus.Exists) {
                    if (failures == 0) System.out.println("  acct error status: " + s);
                    failures++;
                }
            }
            // Fund each user from the operator (operator goes negative — unconstrained).
            TransferBatch fund = new TransferBatch(users);
            for (int u = 0; u < users; u++) {
                fund.add();
                fund.setId(nextId());
                fund.setDebitAccountId(operatorId(l));
                fund.setCreditAccountId(userId(l, u));
                fund.setAmount(FUND_PER_USER);
                fund.setLedger(l);
                fund.setCode(1);
                fund.setFlags(TransferFlags.NONE);
            }
            CreateTransferResultBatch fr = client.createTransfers(fund);
            int fundFail = 0;
            while (fr.next()) {
                CreateTransferStatus s = fr.getStatus();
                if (s != CreateTransferStatus.Created && s != CreateTransferStatus.Exists) {
                    if (fundFail == 0) System.out.println("  fund error status: " + s);
                    fundFail++;
                }
            }
            System.out.printf("  ledger %d: accounts~%d (acctErr=%d), funded=%d (fundErr=%d)%n",
                    l, perLedger, failures, users, fundFail);
        }
        System.out.println("setup done.");
    }

    static void addAccount(AccountBatch b, long id, int ledger) {
        b.add();
        b.setId(id);
        b.setLedger(ledger);
        b.setCode(1);
        b.setFlags(AccountFlags.NONE);
    }

    // ---- latency: open-loop, coordinated-omission-safe hold round-trip ----
    static void latency(Client client, int ledgers, int users, int rate, int durationSec, int threads)
            throws InterruptedException {
        boolean closed = rate <= 0;
        long totalOps = (long) rate * durationSec;
        long intervalNs = closed ? 0 : 1_000_000_000L / rate;
        long deadlineNs = System.nanoTime() + (long) durationSec * 1_000_000_000L + 50_000_000L;
        System.out.printf("latency: mode=%s rate=%s duration=%ds threads=%d%n",
                closed ? "CLOSED-LOOP (intrinsic round-trip)" : "OPEN-LOOP (CO-safe)",
                closed ? "max" : rate + "/s", durationSec, threads);

        AtomicLong seq = new AtomicLong(0);
        Histogram[] hists = new Histogram[threads];
        Thread[] workers = new Thread[threads];
        long startNs = System.nanoTime() + 50_000_000L; // 50ms lead-in so all threads are ready

        for (int t = 0; t < threads; t++) {
            final Histogram h = new Histogram(1, 60_000_000L, 3); // 1us..60s, 3 sig digits
            hists[t] = h;
            workers[t] = new Thread(() -> {
                var rnd = java.util.concurrent.ThreadLocalRandom.current();
                while (true) {
                    long targetNs;
                    if (closed) {
                        if (System.nanoTime() >= deadlineNs) break;
                        targetNs = System.nanoTime(); // measure from actual submit
                    } else {
                        long i = seq.getAndIncrement();
                        if (i >= totalOps) break;
                        targetNs = startNs + i * intervalNs;
                        long now = System.nanoTime();
                        if (now < targetNs) LockSupport.parkNanos(targetNs - now);
                    }
                    int l = 1 + rnd.nextInt(ledgers);
                    int u = rnd.nextInt(users);
                    TransferBatch b = new TransferBatch(1);
                    b.add();
                    b.setId(nextId());
                    b.setDebitAccountId(userId(l, u));
                    b.setCreditAccountId(clearingId(l));
                    b.setAmount(HOLD_AMOUNT);
                    b.setLedger(l);
                    b.setCode(1);
                    b.setFlags(TransferFlags.PENDING);
                    try {
                        client.createTransfers(b);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        break;
                    }
                    long doneNs = System.nanoTime();
                    // closed-loop: real round-trip; open-loop: CO-corrected vs intended time.
                    long usec = Math.max(1, (doneNs - targetNs) / 1000);
                    h.recordValue(Math.min(usec, 60_000_000L));
                }
            }, "lat-" + t);
            workers[t].start();
        }
        for (Thread w : workers) w.join();

        Histogram merged = new Histogram(1, 60_000_000L, 3);
        for (Histogram h : hists) merged.add(h);
        System.out.printf("---- HOLD round-trip latency (one PENDING transfer), %s ----%n",
                closed ? "closed-loop @ " + threads + " concurrent" : "open-loop CO-safe");
        report(merged);
    }

    static void report(Histogram h) {
        System.out.printf("  count   = %d%n", h.getTotalCount());
        System.out.printf("  p50     = %.3f ms%n", h.getValueAtPercentile(50) / 1000.0);
        System.out.printf("  p90     = %.3f ms%n", h.getValueAtPercentile(90) / 1000.0);
        System.out.printf("  p99     = %.3f ms%n", h.getValueAtPercentile(99) / 1000.0);
        System.out.printf("  p99.9   = %.3f ms%n", h.getValueAtPercentile(99.9) / 1000.0);
        System.out.printf("  p99.99  = %.3f ms%n", h.getValueAtPercentile(99.99) / 1000.0);
        System.out.printf("  max     = %.3f ms%n", h.getMaxValue() / 1000.0);
        System.out.printf("  mean    = %.3f ms%n", h.getMean() / 1000.0);
    }

    // ---- throughput: sustained pending/post/void at the measured op-mix ----
    static void throughput(Client client, int ledgers, int users, int durationSec, int threads, int batchSize)
            throws InterruptedException {
        System.out.printf("throughput: duration=%ds threads=%d batch=%d mix=1:%.2f:%.2f%n",
                durationSec, threads, batchSize, W_POST, W_VOID);
        long deadline = System.nanoTime() + durationSec * 1_000_000_000L;
        AtomicLong holds = new AtomicLong(), posts = new AtomicLong(),
                   voids = new AtomicLong(), fails = new AtomicLong();
        java.util.concurrent.atomic.AtomicReference<String> firstErr = new java.util.concurrent.atomic.AtomicReference<>();

        Thread[] workers = new Thread[threads];
        long start = System.nanoTime();
        for (int t = 0; t < threads; t++) {
            final int OPEN_CAP = 200_000; // bound the resting-pending set so memory stays flat
            workers[t] = new Thread(() -> {
                var rnd = java.util.concurrent.ThreadLocalRandom.current();
                ArrayDeque<Long> open = new ArrayDeque<>();
                ArrayDeque<Long> justCreated = new ArrayDeque<>();
                long h = 0, p = 0, v = 0, f = 0;
                while (System.nanoTime() < deadline) {
                    TransferBatch b = new TransferBatch(batchSize);
                    justCreated.clear();
                    int nh = 0, np = 0, nv = 0;
                    for (int s = 0; s < batchSize; s++) {
                        long id = nextId();
                        double r = rnd.nextDouble() * W_SUM;
                        boolean doPost = r >= W_HOLD && r < W_HOLD + W_POST && !open.isEmpty();
                        boolean doVoid = r >= W_HOLD + W_POST && !open.isEmpty();
                        b.add();
                        b.setId(id);
                        if (doPost) {
                            b.setPendingId(open.poll());
                            b.setAmount(POST_AMOUNT);
                            b.setFlags(TransferFlags.POST_PENDING_TRANSFER);
                            np++;
                        } else if (doVoid) {
                            b.setPendingId(open.poll());
                            b.setAmount(0);
                            b.setFlags(TransferFlags.VOID_PENDING_TRANSFER);
                            nv++;
                        } else {
                            int l = 1 + rnd.nextInt(ledgers);
                            int u = rnd.nextInt(users);
                            b.setDebitAccountId(userId(l, u));
                            b.setCreditAccountId(clearingId(l));
                            b.setAmount(HOLD_AMOUNT);
                            b.setLedger(l);
                            b.setCode(1);
                            b.setFlags(TransferFlags.PENDING);
                            justCreated.add(id); // resolvable only after this batch commits
                            nh++;
                        }
                    }
                    CreateTransferResultBatch res;
                    try {
                        res = client.createTransfers(b);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        break;
                    }
                    int batchFails = 0;
                    while (res.next()) {
                        CreateTransferStatus st = res.getStatus();
                        if (st != CreateTransferStatus.Created && st != CreateTransferStatus.Exists) {
                            batchFails++;
                            firstErr.compareAndSet(null, st.toString());
                        }
                    }
                    f += batchFails;
                    h += nh; p += np; v += nv;
                    // Only now (post-commit) are the new pendings safe to reference.
                    for (Long id : justCreated) if (open.size() < OPEN_CAP) open.add(id);
                }
                holds.addAndGet(h); posts.addAndGet(p); voids.addAndGet(v); fails.addAndGet(f);
            }, "tp-" + t);
            workers[t].start();
        }
        for (Thread w : workers) w.join();
        double elapsed = (System.nanoTime() - start) / 1e9;
        long total = holds.get() + posts.get() + voids.get();
        System.out.println("---- throughput (pending/post/void lifecycle) ----");
        System.out.printf("  elapsed     = %.2f s%n", elapsed);
        System.out.printf("  holds       = %d%n", holds.get());
        System.out.printf("  settles     = %d%n", posts.get());
        System.out.printf("  releases    = %d%n", voids.get());
        System.out.printf("  failures    = %d%s%n", fails.get(),
                firstErr.get() == null ? "" : " (first: " + firstErr.get() + ")");
        System.out.printf("  TOTAL ops   = %d%n", total);
        System.out.printf("  throughput  = %.0f tx/s%n", total / elapsed);
    }

    // ---- tiny arg parser: --key value ----
    static final class Args {
        final String[] a;
        Args(String[] a) { this.a = a; }
        String str(String k, String def) {
            for (int i = 0; i < a.length - 1; i++) if (a[i].equals("--" + k)) return a[i + 1];
            return def;
        }
        int i(String k, int def) { String s = str(k, null); return s == null ? def : Integer.parseInt(s); }
        long lng(String k, long def) { String s = str(k, null); return s == null ? def : Long.parseLong(s); }
    }
}
