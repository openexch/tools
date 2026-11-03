// SPDX-License-Identifier: Apache-2.0
import com.openexchange.assets.application.engine.order.RequestTable;
import com.openexchange.assets.auth.CoreCredentials;
import com.openexchange.assets.domain.Asset;
import com.openexchange.assets.domain.Market;
import com.openexchange.assets.infrastructure.generated.*;
import io.aeron.cluster.client.AeronCluster;
import io.aeron.cluster.client.EgressListener;
import io.aeron.cluster.codecs.EventCode;
import io.aeron.driver.MediaDriver;
import io.aeron.driver.ThreadingMode;
import io.aeron.logbuffer.Header;
import org.agrona.CloseHelper;
import org.agrona.DirectBuffer;
import org.agrona.concurrent.BackoffIdleStrategy;
import org.agrona.concurrent.UnsafeBuffer;

import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.SplittableRandom;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.concurrent.ThreadLocalRandom;
import java.util.function.Consumer;
import java.util.function.Predicate;

/**
 * RC2 S14 core probe: the fixture's only client of the OMS + ledger core (money-schema v6, RC1 a9a865d).
 * Compiled separately against the frozen AE jar and run with it on the class path; never linked into a
 * product artifact. One verb per process, one authenticated session, one JSON line on stdout (the LAST
 * line starting with '{' is the verb's answer; other lines are human-readable summaries).
 *
 * <p>Environment (all required, no defaults): CORE_AE_ADDRESSES (comma list, member order),
 * CORE_AE_PORT_BASE, CLUSTER_PORT_STRIDE, CORE_LOCAL_HOST, AE_AUTH_CREDENTIAL (keyId:CLASS:secretHex).
 * The credential's class must be one the verb allows; the core checks it again. {@code story script=funding}
 * talks to no cluster and needs none of them.</p>
 *
 * <p>RC2 S15 (contract sections 5.7, 6, 6.1): {@code story} is the seeded functional story driver (one GATEWAY
 * session for the whole load, open loop, paced by wall clock, the UNKNOWN resolution pass); {@code tap} keeps
 * its TOOL session across leader changes and session loss and reports the dispatchSeq density; {@code
 * order-dump} keeps every page (F-S15-24 / W0 amendment A13).</p>
 *
 * <p>Exit codes: 0 answered; 3 no answer before the deadline (outcome UNKNOWN), or a story whose every request
 * stayed UNKNOWN (setup failure); 4 the core refused (the JSON says why); 5 a negative control was NOT refused;
 * 64 usage.</p>
 */
public final class CoreProbe {
    private static final long DEADLINE_MS = 30_000;
    private static final int HEADER = MessageHeaderEncoder.ENCODED_LENGTH;

    final Map<String, String> args = new HashMap<>();
    private final UnsafeBuffer buffer = new UnsafeBuffer(new byte[16 * 1024]);
    private final MessageHeaderEncoder headerEncoder = new MessageHeaderEncoder();
    private final MessageHeaderDecoder header = new MessageHeaderDecoder();
    final List<String> rows = new ArrayList<>();
    private Predicate<Integer> done = t -> false;
    Listener listener;
    private AeronCluster cluster;
    private MediaDriver driver;
    private io.aeron.security.CredentialsSupplier supplier;
    private long keepAliveAt;
    private long retryAt;
    private boolean closedNoted;
    Continuity continuity = new Continuity(e -> { });

    public static void main(final String[] argv) {
        System.exit(new CoreProbe().run(argv));
    }

    private static String env(final String name) {
        final String value = System.getenv(name);
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("required environment " + name + " is missing");
        }
        return value.trim();
    }

    private String arg(final String name) {
        final String value = args.get(name);
        if (value == null) {
            throw new IllegalArgumentException("required argument " + name + "= is missing");
        }
        return value;
    }

    private long num(final String name) {
        return Long.parseLong(arg(name));
    }

    static String q(final String s) {
        final StringBuilder sb = new StringBuilder(s.length() + 2).append('"');
        for (int i = 0; i < s.length(); i++) {
            final char c = s.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> {
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        return sb.append('"').toString();
    }

    /** Minimal JSON writer for the story and tap reports: String, Number, Boolean, null, Map, Collection, long[]. */
    static String json(final Object o) {
        final StringBuilder sb = new StringBuilder();
        writeJson(sb, o);
        return sb.toString();
    }

    private static void writeJson(final StringBuilder sb, final Object o) {
        if (o == null) {
            sb.append("null");
        } else if (o instanceof String s) {
            sb.append(q(s));
        } else if (o instanceof Number || o instanceof Boolean) {
            sb.append(o);
        } else if (o instanceof long[] a) {
            sb.append('[');
            for (int i = 0; i < a.length; i++) {
                sb.append(i == 0 ? "" : ",").append(a[i]);
            }
            sb.append(']');
        } else if (o instanceof Map<?, ?> m) {
            sb.append('{');
            boolean first = true;
            for (final Map.Entry<?, ?> e : m.entrySet()) {
                sb.append(first ? "" : ",").append(q(String.valueOf(e.getKey()))).append(':');
                writeJson(sb, e.getValue());
                first = false;
            }
            sb.append('}');
        } else if (o instanceof Collection<?> c) {
            sb.append('[');
            boolean first = true;
            for (final Object v : c) {
                sb.append(first ? "" : ",");
                writeJson(sb, v);
                first = false;
            }
            sb.append(']');
        } else {
            throw new IllegalArgumentException("not a JSON value: " + o.getClass().getName());
        }
    }

    static Map<String, Object> map(final Object... kv) {
        final Map<String, Object> m = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) {
            m.put((String) kv[i], kv[i + 1]);
        }
        return m;
    }

    int run(final String[] argv) {
        if (argv.length == 0) {
            System.err.println("usage: CoreProbe <verb> [key=value ...]");
            return 64;
        }
        for (int i = 1; i < argv.length; i++) {
            final int eq = argv[i].indexOf('=');
            if (eq <= 0) {
                System.err.println("argument must be key=value: " + argv[i]);
                return 64;
            }
            if (args.put(argv[i].substring(0, eq), argv[i].substring(eq + 1)) != null) {
                System.err.println("argument given twice: " + argv[i].substring(0, eq));
                return 64;
            }
        }
        final String verb = argv[0];
        try {
            if (verb.equals("unauth")) {
                return unauthenticated();
            }
            final StoryConfig story = verb.equals("story") ? StoryConfig.parse(args) : null;
            if (story != null && story.script.equals("funding")) {
                return funding(story);   // a plan, no cluster: the fixture executes it through `deposit` (6)
            }
            if (story != null) {
                new Story(story, new RealClock(), null, m -> { });   // the plan's own refusals (per-user cap) before any session
            }
            final CoreCredentials credentials = CoreCredentials.fromSpec(env("AE_AUTH_CREDENTIAL"));
            if (!"1".equals(args.remove("negative"))) {
                requireClass(verb, credentials.sessionClass());   // negative=1: let the CORE refuse it (authority control)
            }
            connect(credentials);
            return switch (verb) {
                case "money-journal" -> moneyJournal();
                case "core-config" -> coreConfig();
                case "risk" -> risk();
                case "gate" -> gate();
                case "deposit", "withdraw" -> funding(verb.equals("deposit"));
                case "create", "cancel", "amend" -> order(verb);
                case "order-dump" -> orderDump();
                case "money-dump" -> moneyDump();
                case "pending-dump" -> pendingDump();
                case "tap" -> tap();
                case "story" -> story(story);
                default -> throw new IllegalArgumentException("unknown verb " + verb);
            };
        } catch (final IllegalArgumentException e) {
            System.err.println("CoreProbe: " + e.getMessage());
            return 64;
        } catch (final io.aeron.exceptions.TimeoutException | IllegalStateException e) {
            System.out.println("{\"verb\":" + q(verb) + ",\"outcome\":\"UNKNOWN\",\"error\":" + q(String.valueOf(e.getMessage())) + "}");
            return 3;
        } finally {
            CloseHelper.quietClose(cluster);
            CloseHelper.quietClose(driver);
        }
    }

    private static void requireClass(final String verb, final SessionClass c) {
        final boolean ok = switch (verb) {
            case "money-journal", "core-config", "risk", "gate", "order-dump" -> c == SessionClass.ADMIN;
            case "deposit", "withdraw", "money-dump" -> c == SessionClass.ADMIN || c == SessionClass.TOOL;
            case "create", "cancel", "amend", "story" -> c == SessionClass.GATEWAY;
            case "pending-dump" -> c == SessionClass.FORWARDER;
            case "tap" -> c == SessionClass.TOOL;
            default -> true;
        };
        if (!ok) {
            throw new IllegalArgumentException("verb " + verb + " may not run as " + c);
        }
    }

    private String endpoints() {
        final String[] hosts = env("CORE_AE_ADDRESSES").split(",");
        final int base = Integer.parseInt(env("CORE_AE_PORT_BASE"));
        final int stride = Integer.parseInt(env("CLUSTER_PORT_STRIDE"));
        final StringBuilder sb = new StringBuilder();
        for (int i = 0; i < hosts.length; i++) {
            sb.append(i == 0 ? "" : ",").append(i).append('=').append(hosts[i].trim()).append(':').append(base + i * stride + 2);
        }
        return sb.toString();
    }

    private void connect(final CoreCredentials credentials) {
        connect(credentials.supplier());
    }

    private void connect(final io.aeron.security.CredentialsSupplier credentialsSupplier) {
        supplier = credentialsSupplier;
        if (driver == null) {
            driver = MediaDriver.launch(new MediaDriver.Context()
                    .aeronDirectoryName("/dev/shm/core-probe-" + ProcessHandle.current().pid())
                    .threadingMode(ThreadingMode.SHARED).dirDeleteOnStart(true).dirDeleteOnShutdown(true)
                    .errorHandler(t -> t.printStackTrace(System.err)));
        }
        if (listener == null) {
            listener = new Listener();
        }
        cluster = AeronCluster.connect(new AeronCluster.Context()
                .credentialsSupplier(supplier)
                .messageTimeoutNs(java.util.concurrent.TimeUnit.SECONDS.toNanos(8))
                .aeronDirectoryName(driver.aeronDirectoryName())
                .ingressChannel("aeron:udp?term-length=4m|mtu=8192")
                .ingressEndpoints(endpoints())
                .egressChannel("aeron:udp?endpoint=" + env("CORE_LOCAL_HOST") + ":0|term-length=4m")
                .egressListener(listener)
                .errorHandler(t -> t.printStackTrace(System.err)));
        keepAliveAt = 0;
    }

    private int unauthenticated() {
        final CoreCredentials good = CoreCredentials.fromSpec(env("AE_AUTH_CREDENTIAL"));
        final byte[] secret = good.secret();
        // legacy_none: what every pre-RC1 client (OMS, legacy bridge, today's v1 fixture) presents: nothing.
        final io.aeron.security.CredentialsSupplier presented = arg("mode").equals("legacy_none")
                ? new io.aeron.security.NullCredentialsSupplier() : (switch (arg("mode")) {
            case "unknown_key" -> new CoreCredentials(good.sessionClass(), 999_999, secret);
            case "wrong_secret" -> {
                secret[0] ^= 0x5A;
                yield new CoreCredentials(good.sessionClass(), good.keyId(), secret);
            }
            case "class_mismatch" -> new CoreCredentials(good.sessionClass() == SessionClass.ADMIN ? SessionClass.GATEWAY
                    : SessionClass.ADMIN, good.keyId(), secret);
            default -> throw new IllegalArgumentException("mode must be legacy_none|unknown_key|wrong_secret|class_mismatch");
        }).supplier();
        try {
            connect(presented);
        } catch (final RuntimeException e) {
            System.out.println("{\"verb\":\"unauth\",\"mode\":" + q(arg("mode")) + ",\"refused\":true,\"error\":"
                    + q(e.getClass().getSimpleName() + ": " + e.getMessage()) + "}");
            return 0;
        }
        System.out.println("{\"verb\":\"unauth\",\"mode\":" + q(arg("mode")) + ",\"refused\":false}");
        return 5;
    }

    // ------------------------------------------------------------------ plumbing

    private void offer(final int length) {
        final long deadline = System.currentTimeMillis() + DEADLINE_MS;
        final BackoffIdleStrategy idle = new BackoffIdleStrategy();
        while (cluster.offer(buffer, 0, length) < 0) {
            if (System.currentTimeMillis() > deadline) {
                throw new IllegalStateException("could not offer to the core before the deadline");
            }
            service();
            idle.idle();
        }
    }

    private int service() {
        final long now = System.currentTimeMillis();
        if (now >= keepAliveAt) {
            cluster.sendKeepAlive();
            keepAliveAt = now + 250;
        }
        return cluster.pollEgress();
    }

    private void await(final Predicate<Integer> until) {
        done = until;
        final long deadline = System.currentTimeMillis() + DEADLINE_MS;
        final BackoffIdleStrategy idle = new BackoffIdleStrategy();
        while (!listener.finished) {
            if (System.currentTimeMillis() > deadline) {
                throw new IllegalStateException("no reply before the deadline; the outcome is UNKNOWN, not refused");
            }
            idle.idle(service());
        }
    }

    private static long corr() {
        return ThreadLocalRandom.current().nextLong(1, Long.MAX_VALUE);
    }

    private void register(final long correlationId, final SessionClass c, final boolean orders, final boolean dispatch) {
        final RegisterSessionEncoder e = new RegisterSessionEncoder().wrapAndApplyHeader(buffer, 0, headerEncoder)
                .correlationId(correlationId).sessionClass(c).readerKind((short) 0).resumable(BoolFlag.TRUE)
                .identity(0L).sourceEpoch(0L);
        e.channels().clear().acks(true).orders(orders).dispatch(dispatch).control(true);
        offer(HEADER + e.encodedLength());
        listener.expectCorrelation = correlationId;
        await(t -> t == AdminAckDecoder.TEMPLATE_ID);
        if (!listener.lastAdminResult.equals("ACCEPTED") && !listener.lastAdminResult.equals("DUPLICATE")) {
            throw new IllegalStateException("RegisterSession refused: " + listener.lastAdminResult);
        }
        listener.reset();
    }

    /**
     * One step of a long-lived session (tap, story): polls egress and heals the session (S15 5.7 rule 1): a
     * NewLeaderEvent re-registers the egress mask on the new leader; a closed session is reconnected (same
     * credentials, same driver) and re-registered. Every transition is a {@link Continuity} row with its time.
     */
    private int pump(final SessionClass c, final boolean orders, final boolean dispatch) {
        final long now = System.currentTimeMillis();
        if (cluster == null || cluster.isClosed()) {
            if (!closedNoted) {
                continuity.note("session_closed", map());
                closedNoted = true;
            }
            if (now >= retryAt) {
                try {
                    CloseHelper.quietClose(cluster);
                    connect(supplier);
                    closedNoted = false;
                    continuity.note("reconnected", map("session", cluster.clusterSessionId(), "leader", cluster.leaderMemberId()));
                    listener.reregister = true;
                } catch (final RuntimeException e) {
                    cluster = null;
                    retryAt = now + 1000;
                    continuity.note("reconnect_failed", map("error", String.valueOf(e.getMessage())));
                }
            }
            return 0;
        }
        if (listener.reregister && now >= retryAt) {
            listener.reregister = false;
            try {
                register(corr(), c, orders, dispatch);
                continuity.note("reregistered", map("session", cluster.clusterSessionId(), "leader", cluster.leaderMemberId()));
            } catch (final RuntimeException e) {
                listener.reregister = true;
                retryAt = now + 1000;
                continuity.note("reregister_failed", map("error", String.valueOf(e.getMessage())));
            }
        }
        try {
            return service();
        } catch (final RuntimeException e) {
            continuity.note("poll_error", map("error", e.getClass().getSimpleName() + ": " + e.getMessage()));
            CloseHelper.quietClose(cluster);
            return 0;
        }
    }

    private int print(final String verb) {
        final String body = String.join(",", rows);
        System.out.println("{\"verb\":" + q(verb) + ",\"replies\":[" + body + "]}");
        return listener.refused ? 4 : 0;
    }

    // ------------------------------------------------------------------ verbs

    private int moneyJournal() {
        final boolean on = arg("state").equals("on");
        final long c = corr();
        offer(HEADER + new SetMoneyJournalEncoder().wrapAndApplyHeader(buffer, 0, headerEncoder).correlationId(c)
                .enabled(on ? BoolFlag.TRUE : BoolFlag.FALSE).encodedLength());
        final long query = corr();
        offer(HEADER + new QueryFeedPositionEncoder().wrapAndApplyHeader(buffer, 0, headerEncoder).correlationId(query).encodedLength());
        listener.expectCorrelation = query;
        await(t -> t == FeedPositionReportDecoder.TEMPLATE_ID);
        listener.refused = listener.journalEnabled != on;
        return print("money-journal");
    }

    private int coreConfig() {
        final CoreConfigEncoder e = new CoreConfigEncoder().wrapAndApplyHeader(buffer, 0, headerEncoder)
                .correlationId(listener.expectCorrelation = corr()).configVersion(num("version")).behaviorVersion(num("behavior"));
        final CoreConfigEncoder.MarketsEncoder m = e.marketsCount(Market.ALL.length);
        for (final Market d : Market.ALL) {
            m.next().marketId(d.marketId()).symbol(d.symbol()).baseAssetId(d.baseAsset().id()).quoteAssetId(d.quoteAsset().id())
                    .tickSize(num("tick")).minPrice(num("min")).maxPrice(num("max")).lotSize(num("lot"));
        }
        final CoreConfigEncoder.AssetsEncoder a = e.assetsCount(Asset.values().length);
        for (final Asset d : Asset.values()) {
            a.next().assetId(d.id()).code(d.name()).scale((short) 8);
        }
        offer(HEADER + e.encodedLength());
        await(t -> t == AdminAckDecoder.TEMPLATE_ID);
        listener.refused = listener.lastAdminResult.equals("REJECTED");
        return print("core-config");
    }

    private int risk() {
        offer(HEADER + new RiskConfigSetEncoder().wrapAndApplyHeader(buffer, 0, headerEncoder)
                .correlationId(listener.expectCorrelation = corr()).configVersion(num("version")).marketId((int) num("market"))
                .minQuantity(num("min_qty")).maxQuantity(num("max_qty")).minNotional(0).maxNotional(Long.MAX_VALUE)
                .priceCollarBps(num("collar_bps")).maxOrdersPerSec((int) num("per_sec")).maxOrdersPerMin((int) num("per_sec") * 30)
                .maxOpenOrders((int) num("max_open")).maxPositionPerMarket(Long.MAX_VALUE)
                .marketBuySlippageBps(num("slippage_bps")).encodedLength());
        await(t -> t == AdminAckDecoder.TEMPLATE_ID);
        listener.refused = listener.lastAdminResult.equals("REJECTED");
        return print("risk");
    }

    private int gate() {
        offer(HEADER + new OrderEntryGateEncoder().wrapAndApplyHeader(buffer, 0, headerEncoder)
                .correlationId(listener.expectCorrelation = corr()).marketId((int) num("market"))
                .state(GateState.valueOf(arg("state"))).reason(GateReason.valueOf(arg("reason"))).encodedLength());
        await(t -> t == AdminAckDecoder.TEMPLATE_ID);
        listener.refused = listener.lastAdminResult.equals("REJECTED");
        return print("gate");
    }

    private int funding(final boolean deposit) {
        final long c = listener.expectCorrelation = corr();
        if (deposit) {
            offer(HEADER + new DepositEncoder().wrapAndApplyHeader(buffer, 0, headerEncoder).correlationId(c).userId(num("user"))
                    .assetId((int) num("asset")).amount(num("amount")).requestIdHigh(num("rh")).requestIdLow(num("rl")).encodedLength());
        } else {
            offer(HEADER + new WithdrawEncoder().wrapAndApplyHeader(buffer, 0, headerEncoder).correlationId(c).userId(num("user"))
                    .assetId((int) num("asset")).amount(num("amount")).requestIdHigh(num("rh")).requestIdLow(num("rl")).encodedLength());
        }
        await(t -> t == DepositAckDecoder.TEMPLATE_ID || t == DepositRejectDecoder.TEMPLATE_ID || t == WithdrawAckDecoder.TEMPLATE_ID
                || t == WithdrawRejectDecoder.TEMPLATE_ID || t == OrderRejectDecoder.TEMPLATE_ID);
        return print(deposit ? "deposit" : "withdraw");
    }

    private int order(final String verb) {
        register(corr(), SessionClass.GATEWAY, true, false);
        final long c = listener.expectCorrelation = corr();
        final int length;
        switch (verb) {
            case "create" -> length = new CreateOrderEncoder().wrapAndApplyHeader(buffer, 0, headerEncoder).correlationId(c)
                    .userId(num("user")).clientOrderIdHigh(num("ch")).clientOrderIdLow(num("cl"))
                    .requestIdHigh(num("rh")).requestIdLow(num("rl")).marketId((int) num("market"))
                    .side(Side.valueOf(arg("side"))).orderType(OrderType.valueOf(arg("type")))
                    .timeInForce(TimeInForce.valueOf(arg("tif"))).price(num("price")).quantity(num("qty"))
                    .budget(num("budget")).stopPrice(num("stop")).trailingDelta(num("delta")).displayQty(num("display"))
                    .expiresAtMs(num("expires")).encodedLength();
            case "cancel" -> length = new CancelOrderEncoder().wrapAndApplyHeader(buffer, 0, headerEncoder).correlationId(c)
                    .userId(num("user")).orderId(num("order")).requestIdHigh(num("rh")).requestIdLow(num("rl"))
                    .origClientOrderIdHigh(0).origClientOrderIdLow(0).encodedLength();
            default -> length = new AmendOrderEncoder().wrapAndApplyHeader(buffer, 0, headerEncoder).correlationId(c)
                    .userId(num("user")).orderId(num("order")).requestIdHigh(num("rh")).requestIdLow(num("rl"))
                    .newPrice(num("price")).newQuantity(num("qty")).encodedLength();
        }
        offer(HEADER + length);
        await(t -> t == OrderAckDecoder.TEMPLATE_ID || t == OrderRejectDecoder.TEMPLATE_ID);
        return print(verb);
    }

    private int orderDump() {
        long from = 0;
        int pages = 0;
        listener.reset();
        do {
            listener.nextPage();   // F-S15-24: rows accumulate over pages; reset() cleared them, so only the last page was printed
            offer(HEADER + new RequestOrderSnapshotEncoder().wrapAndApplyHeader(buffer, 0, headerEncoder)
                    .correlationId(listener.expectCorrelation = corr()).userId(0).fromOrderId(from).encodedLength());
            await(t -> t == OrderSnapshotEndDecoder.TEMPLATE_ID || t == OrderRejectDecoder.TEMPLATE_ID);
            if (listener.refused) {
                return print("order-dump");
            }
            from = listener.nextOrderId;
            pages++;
        } while (from != 0);
        System.out.println("{\"verb\":\"order-dump\",\"pages\":" + pages + ",\"count\":" + rows.size()
                + ",\"orders\":[" + String.join(",", rows) + "]}");
        return 0;
    }

    private int moneyDump() {
        listener.balanceCorr = corr();
        listener.holdCorr = corr();
        listener.expectCorrelation = corr();
        offer(HEADER + new RequestBalanceSnapshotEncoder().wrapAndApplyHeader(buffer, 0, headerEncoder).correlationId(listener.balanceCorr).encodedLength());
        offer(HEADER + new RequestHoldSnapshotEncoder().wrapAndApplyHeader(buffer, 0, headerEncoder).correlationId(listener.holdCorr).encodedLength());
        offer(HEADER + new QueryFeedPositionEncoder().wrapAndApplyHeader(buffer, 0, headerEncoder).correlationId(listener.expectCorrelation).encodedLength());
        await(t -> listener.balancesEnd && listener.holdsEnd && listener.positionSeen);
        System.out.println(moneyDumpLine());
        return 0;
    }

    /**
     * The money-dump answer. S16 W2 (contract 3.3): the four v7 FeedPositionReport fields the decoder already reads past
     * are exported as {@code meEpoch} (the ME epoch the core is bound to), {@code lastAppliedJournalSeq} (the feed
     * cursor), {@code feedHalted} and {@code haltReason} (the FeedHaltReason name); the fixture maps them to
     * {@code core.bound_me_epoch / feed_cursor / feed_halted / halt_reason}.
     */
    String moneyDumpLine() {
        final StringBuilder sb = new StringBuilder("{\"verb\":\"money-dump\",\"balances\":[");
        sb.append(String.join(",", listener.balances.values())).append("],\"holds\":[");
        sb.append(String.join(",", listener.holds.values())).append("],\"consumePosition\":").append(listener.consumePosition)
                .append(",\"lastAppliedTradeId\":").append(listener.lastAppliedTradeId)
                .append(",\"journalEnabled\":").append(listener.journalEnabled)
                .append(",\"meEpoch\":").append(listener.meEpoch)
                .append(",\"lastAppliedJournalSeq\":").append(listener.lastAppliedJournalSeq)
                .append(",\"feedHalted\":").append(listener.feedHalted)
                .append(",\"haltReason\":\"").append(listener.haltReason).append("\"}");
        return sb.toString();
    }

    private int pendingDump() {
        register(corr(), SessionClass.FORWARDER, false, true);
        offer(HEADER + new RequestPendingDispatchEncoder().wrapAndApplyHeader(buffer, 0, headerEncoder)
                .correlationId(listener.expectCorrelation = corr()).fromDispatchSeq(0).maxEntries(4096).encodedLength());
        await(t -> t == PendingDispatchEndDecoder.TEMPLATE_ID);
        System.out.println("{\"verb\":\"pending-dump\",\"count\":" + listener.pendingCount + ",\"head\":" + listener.pendingHead
                + ",\"entries\":[" + String.join(",", rows) + "]}");
        return 0;
    }

    /**
     * The TOOL witness (S15 5.7). Rows go to {@code out} as before (tap kinds dispatch, order_event, admission,
     * order_fault: the sample's read_tap shape is unchanged); session transitions go to {@code sessions}
     * (default {@code <out>.sessions.jsonl}, named in the summary). At exit: one line
     * {@code TAP first=F last=L rows=N gaps=[[a,b],...]} over the dispatchSeq values seen, then the JSON summary.
     * The density cannot see a missing TAIL (W0 answer 12): the drill compares {@code last} with the core head
     * ({@code pending-dump}), which a TOOL session cannot read.
     */
    private int tap() {
        final long until = System.currentTimeMillis() + num("duration_ms");
        final String out = arg("out");
        final String sessions = args.getOrDefault("sessions", out + ".sessions.jsonl");
        try (PrintWriter rowsOut = new PrintWriter(new FileWriter(out, true));
             PrintWriter sessionsOut = new PrintWriter(new FileWriter(sessions, true))) {
            continuity = new Continuity(e -> {
                sessionsOut.println(json(e));
                sessionsOut.flush();
            });
            listener.tap = rowsOut;
            register(corr(), SessionClass.TOOL, true, true);
            continuity.note("registered", map("session", cluster.clusterSessionId(), "leader", cluster.leaderMemberId()));
            final BackoffIdleStrategy idle = new BackoffIdleStrategy();
            while (System.currentTimeMillis() < until && !Thread.currentThread().isInterrupted()) {
                idle.idle(pump(SessionClass.TOOL, true, true));
                rowsOut.flush();
            }
        } catch (final IOException e) {
            throw new IllegalStateException("tap output: " + e.getMessage());
        }
        System.out.println(continuity.dispatch.tapLine());
        final Map<String, Object> summary = map("verb", "tap", "rows", listener.tapped, "sessions_file", sessions);
        summary.putAll(continuity.summary());
        System.out.println(json(summary));
        return 0;
    }

    // ------------------------------------------------------------------ story (S15 section 6)

    private int funding(final StoryConfig cfg) throws IllegalArgumentException {
        final List<Map<String, Object>> plan = Story.fundingPlan(cfg);
        final StringBuilder sb = new StringBuilder();
        for (final Map<String, Object> row : plan) {
            sb.append(json(map("story", "funding", "row", row))).append('\n');
        }
        writeAtomically(cfg.out, sb.toString());
        System.out.println(json(map("verb", "story", "script", "funding", "rows", plan.size(), "out", cfg.out)));
        return 0;
    }

    static void writeAtomically(final String path, final String text) {
        try {
            final Path target = Path.of(path);
            final Path tmp = Path.of(path + ".tmp");
            Files.writeString(tmp, text, StandardCharsets.UTF_8);
            Files.move(tmp, target, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch (final IOException e) {
            throw new IllegalStateException("story output " + path + ": " + e.getMessage());
        }
    }

    private int story(final StoryConfig cfg) {
        try (PrintWriter markersOut = new PrintWriter(new FileWriter(cfg.markers, true))) {
            final Consumer<Map<String, Object>> markers = m -> {
                markersOut.println(json(m));
                markersOut.flush();
            };
            continuity = new Continuity(e -> {
                final Map<String, Object> m = map("marker", "session");
                m.putAll(e);
                markers.accept(m);
            });
            register(corr(), SessionClass.GATEWAY, true, false);
            final Story s = new Story(cfg, new RealClock(), new AeronPort(), markers);
            listener.story = s;
            final Story.Summary summary = s.run();
            writeAtomically(cfg.out, s.requestLog());
            System.out.println(summary.storyLine());
            if (cfg.script.equals("a03-fill")) {
                System.out.println(s.a03Line());
            }
            final Map<String, Object> report = summary.json();
            report.put("sessions", continuity.summary());
            System.out.println(json(report));
            return summary.setupFailure() ? 3 : 0;
        } catch (final IOException e) {
            throw new IllegalStateException("story markers: " + e.getMessage());
        }
    }

    /** The GATEWAY transport of the story: encodes one row, never blocks (a false return keeps the row queued). */
    private final class AeronPort implements StoryPort {
        public boolean offer(final StoryRow row, final long correlationId) {
            if (cluster == null || cluster.isClosed()) {
                return false;
            }
            final int length = switch (row.list) {
                case "creates" -> {
                    final CreateOrderEncoder e = new CreateOrderEncoder().wrapAndApplyHeader(buffer, 0, headerEncoder)
                            .correlationId(correlationId).userId(row.user).clientOrderIdHigh(row.rh).clientOrderIdLow(row.rl)
                            .requestIdHigh(row.rh).requestIdLow(row.rl).marketId(row.market).side(Side.valueOf(row.side))
                            .orderType(OrderType.valueOf(row.type)).timeInForce(TimeInForce.valueOf(row.tif)).price(row.price)
                            .quantity(row.quantity).budget(row.budget).stopPrice(row.stopPrice).trailingDelta(0)
                            .displayQty(row.displayQty).expiresAtMs(row.expires);
                    e.flags().clear();   // the buffer is reused across templates: never leave a stale flag byte
                    yield e.encodedLength();
                }
                case "amends" -> new AmendOrderEncoder().wrapAndApplyHeader(buffer, 0, headerEncoder).correlationId(correlationId)
                        .userId(row.user).orderId(row.order).requestIdHigh(row.rh).requestIdLow(row.rl)
                        .newPrice(row.newPrice).newQuantity(row.newQuantity).encodedLength();
                case "cancels" -> new CancelOrderEncoder().wrapAndApplyHeader(buffer, 0, headerEncoder).correlationId(correlationId)
                        .userId(row.user).orderId(row.order).requestIdHigh(row.rh).requestIdLow(row.rl)
                        .origClientOrderIdHigh(0).origClientOrderIdLow(0).encodedLength();
                default -> throw new IllegalStateException("story row list " + row.list);
            };
            try {
                return cluster.offer(buffer, 0, HEADER + length) > 0;
            } catch (final RuntimeException e) {
                continuity.note("offer_error", map("error", e.getClass().getSimpleName() + ": " + e.getMessage()));
                return false;
            }
        }

        public int poll() {
            return pump(SessionClass.GATEWAY, true, false);
        }
    }

    /** Wall clock in epoch nanoseconds (comparable with the fixture's time.time_ns()), monotonic within the JVM. */
    static final class RealClock implements StoryClock {
        private final long baseEpochNs = System.currentTimeMillis() * 1_000_000L;
        private final long baseNano = System.nanoTime();
        private final BackoffIdleStrategy idle = new BackoffIdleStrategy();

        public long nowNs() {
            return baseEpochNs + (System.nanoTime() - baseNano);
        }

        public void idle(final int work) {
            idle.idle(work);
        }

        public boolean exists(final String path) {
            return Files.exists(Path.of(path));
        }
    }

    interface StoryClock {
        /** Epoch nanoseconds. */
        long nowNs();

        void idle(int work);

        /** A drill's gate file (hold release, resolution gate) exists. */
        boolean exists(String path);
    }

    /** What the story needs from its transport: the real one is {@link AeronPort}, the unit tests use a reply stub. */
    interface StoryPort {
        /** Offers one request; false when it was NOT offered (back pressure, no session): the row stays queued. */
        boolean offer(StoryRow row, long correlationId);

        /** Drives egress; replies and order events reach the story's {@link StorySink}. Returns the work count. */
        int poll();
    }

    interface StorySink {
        void onAck(long correlationId, long orderId, boolean duplicate, int holdAsset, long holdAmount, String status);

        void onReject(long correlationId, String reason, int meReason, long detail, long orderId);

        void onEvent(long orderId, String kind, String status, long filled);
    }

    /** Arguments of {@code story}, refused when ambiguous (contract C7: unknown script, non-integer seed). */
    static final class StoryConfig {
        static final List<String> SCRIPTS = List.of("a01-mix", "a02-lifecycle", "funding", "a03-fill");
        static final List<String> MOMENTS = List.of("iceberg", "replace", "maker_replace", "stop", "ioc_fok", "gtd", "markets");
        static final List<String> HOLDS = List.of("slice1_exhausting_fill", "replace_open:1", "replace_open:2", "replace_open:3");
        static final Set<String> STORY_KEYS = Set.of("script", "seed", "seconds", "rate", "users", "out", "markers", "without",
                "hold", "gate_dir", "hold_ms", "resolve_gate", "resolve_gate_ms", "ioc_burst_on");
        /** S16 W2 (contract 5.5, 20.1 lines 2, 3): a03-fill is a rate / fill_s / reopen_s story with no cancels and no seconds=. */
        static final Set<String> A03_KEYS = Set.of("script", "seed", "users", "out", "markers", "rate", "fill_s", "reopen_s",
                "marker_timeout_s", "signal_dir");
        static final int A03_DEFAULT_RATE = 100;
        static final int A03_DEFAULT_FILL_S = 30;
        static final int A03_DEFAULT_REOPEN_S = 10;
        static final int A03_DEFAULT_MARKER_TIMEOUT_S = 60;
        static final Set<String> FUNDING_KEYS = Set.of("script", "seed", "users", "out", "for");
        /** Section 0: a functional story stays at or under 200 commands/s; a02 at or under 50/s (section 4). */
        static final int A01_MAX_COMMANDS_PER_S = 200;
        static final int A02_MAX_RATE = 50;

        String script;
        /** script=funding: the story it funds (a01-mix trades market 1 only, a02-lifecycle markets 1..5). */
        String fundsFor;
        long seed;
        int seconds;
        int rate;
        long[] users;
        String out;
        String markers;
        Set<String> without = Set.of();
        Set<String> holds = Set.of();
        String gateDir;
        long holdMs;
        String resolveGate;
        long resolveGateMs;
        /** a01-mix: a file the fixture creates; for 2 s after it appears every create is IOC crossing (fwdring). */
        String iocBurstOn;
        /** a03-fill: seconds of phase 1, seconds of phase 3, the wait bound of phase 2, the directory the fixture signals in. */
        int fillS;
        int reopenS;
        int markerTimeoutS;
        String signalDir;

        static StoryConfig parse(final Map<String, String> a) {
            final StoryConfig c = new StoryConfig();
            c.script = required(a, "script");
            if (!SCRIPTS.contains(c.script)) {
                throw new IllegalArgumentException("unknown story script " + c.script + " (scripts: " + SCRIPTS + ")");
            }
            final Set<String> allowed = c.script.equals("funding") ? FUNDING_KEYS : c.script.equals("a03-fill") ? A03_KEYS : STORY_KEYS;
            for (final String k : new TreeSet<>(a.keySet())) {
                if (!allowed.contains(k)) {
                    throw new IllegalArgumentException("story " + c.script + " does not take " + k + "=");
                }
            }
            try {
                c.seed = Long.parseLong(required(a, "seed"));
            } catch (final NumberFormatException e) {
                throw new IllegalArgumentException("seed must be an integer in 0..4294967295, got " + a.get("seed"));
            }
            if (c.seed < 0 || c.seed > 0xFFFF_FFFFL) {
                throw new IllegalArgumentException("seed must be an integer in 0..4294967295, got " + c.seed);
            }
            c.users = parseUsers(required(a, "users"));
            c.out = required(a, "out");
            if (c.script.equals("funding")) {
                c.fundsFor = required(a, "for");
                if (!c.fundsFor.equals("a01-mix") && !c.fundsFor.equals("a02-lifecycle")) {
                    throw new IllegalArgumentException("funding for= must be a01-mix or a02-lifecycle, got " + c.fundsFor);
                }
                return c;
            }
            c.markers = required(a, "markers");
            if (c.script.equals("a03-fill")) {
                c.rate = a.containsKey("rate") ? positiveInt(a, "rate", false) : A03_DEFAULT_RATE;
                c.fillS = a.containsKey("fill_s") ? positiveInt(a, "fill_s", false) : A03_DEFAULT_FILL_S;
                c.reopenS = a.containsKey("reopen_s") ? positiveInt(a, "reopen_s", false) : A03_DEFAULT_REOPEN_S;
                c.markerTimeoutS = a.containsKey("marker_timeout_s") ? positiveInt(a, "marker_timeout_s", false)
                        : A03_DEFAULT_MARKER_TIMEOUT_S;
                c.signalDir = required(a, "signal_dir");
                if (c.rate > A01_MAX_COMMANDS_PER_S) {
                    throw new IllegalArgumentException("a03-fill rate " + c.rate + " is above the functional bound " + A01_MAX_COMMANDS_PER_S);
                }
                if (c.users.length < 2) {
                    throw new IllegalArgumentException("a03-fill needs at least two users");
                }
                return c;
            }
            c.seconds = positiveInt(a, "seconds", true);
            c.rate = positiveInt(a, "rate", false);
            if (a.containsKey("ioc_burst_on") && !c.script.equals("a01-mix")) {
                throw new IllegalArgumentException("story " + c.script + " does not take ioc_burst_on=");
            }
            c.iocBurstOn = a.get("ioc_burst_on");
            if (c.script.equals("a01-mix")) {
                if (c.seconds == 0) {
                    throw new IllegalArgumentException("a01-mix needs seconds > 0");
                }
                if (c.rate + c.rate / 5 > A01_MAX_COMMANDS_PER_S) {
                    throw new IllegalArgumentException("a01-mix rate " + c.rate + " sends " + (c.rate + c.rate / 5)
                            + " commands/s, above the functional bound " + A01_MAX_COMMANDS_PER_S);
                }
                if (c.users.length < 2 || c.users.length % 2 != 0) {
                    throw new IllegalArgumentException("a01-mix needs an even number of users (buyers at even, sellers at odd positions)");
                }
                if (a.containsKey("without") || a.containsKey("hold")) {
                    throw new IllegalArgumentException("without= and hold= are a02-lifecycle switches");
                }
            } else {
                if (c.rate > A02_MAX_RATE) {
                    throw new IllegalArgumentException("a02-lifecycle rate " + c.rate + " is above " + A02_MAX_RATE + "/s");
                }
                if (c.users.length < 2) {
                    throw new IllegalArgumentException("a02-lifecycle needs at least two users");
                }
                c.without = names(a.get("without"), MOMENTS, "moment");
                c.holds = names(a.get("hold"), HOLDS, "hold");
            }
            if (!c.holds.isEmpty()) {
                c.gateDir = required(a, "gate_dir");
                c.holdMs = positiveInt(a, "hold_ms", false);
            } else if (a.containsKey("gate_dir") || a.containsKey("hold_ms")) {
                throw new IllegalArgumentException("gate_dir= and hold_ms= need hold=");
            }
            if (a.containsKey("resolve_gate")) {
                c.resolveGate = a.get("resolve_gate");
                c.resolveGateMs = positiveInt(a, "resolve_gate_ms", false);
            } else if (a.containsKey("resolve_gate_ms")) {
                throw new IllegalArgumentException("resolve_gate_ms= needs resolve_gate=");
            }
            return c;
        }

        private static String required(final Map<String, String> a, final String k) {
            final String v = a.get(k);
            if (v == null || v.isBlank()) {
                throw new IllegalArgumentException("story needs " + k + "=");
            }
            return v;
        }

        private static int positiveInt(final Map<String, String> a, final String k, final boolean zeroOk) {
            final int v;
            try {
                v = Integer.parseInt(required(a, k));
            } catch (final NumberFormatException e) {
                throw new IllegalArgumentException(k + " must be an integer, got " + a.get(k));
            }
            if (v < 0 || (v == 0 && !zeroOk)) {
                throw new IllegalArgumentException(k + " must be " + (zeroOk ? ">= 0" : "> 0") + ", got " + v);
            }
            return v;
        }

        private static long[] parseUsers(final String s) {
            final String[] parts = s.split(",");
            final long[] users = new long[parts.length];
            final Set<Long> seen = new java.util.HashSet<>();
            for (int i = 0; i < parts.length; i++) {
                try {
                    users[i] = Long.parseLong(parts[i].trim());
                } catch (final NumberFormatException e) {
                    throw new IllegalArgumentException("users must be a comma list of positive integers, got " + s);
                }
                if (users[i] <= 0 || !seen.add(users[i])) {
                    throw new IllegalArgumentException("users must be distinct positive integers, got " + s);
                }
            }
            return users;
        }

        private static Set<String> names(final String value, final List<String> known, final String what) {
            if (value == null) {
                return Set.of();
            }
            final Set<String> out = new LinkedHashSet<>();
            for (final String n : value.split(",")) {
                if (!known.contains(n.trim())) {
                    throw new IllegalArgumentException("unknown " + what + " " + n + " (known: " + known + ")");
                }
                out.add(n.trim());
            }
            return out;
        }
    }

    /** One request of the story: the sample's creates / amends / cancels row (OM docstring, CS:121-136). */
    static final class StoryRow {
        int id;
        String list;
        String moment;
        long rh;
        long rl;
        long user;
        int market;
        String side = "";
        String type = "";
        String tif = "";
        long price;
        long quantity;
        long budget;
        long stopPrice;
        long displayQty;
        long expires;
        /** amend/cancel: the core order id; target: the create row it names. */
        long order;
        long newPrice;
        long newQuantity;
        StoryRow target;
        /** a02: GTD expiry relative to the send time (the absolute ms is fixed when the row is built). */
        long expiresInMs;
        long scheduledNs;
        long sentNs = -1;
        long replyNs = -1;
        Map<String, Object> reply;
        Map<String, Object> lateReply;
        Integer resolves;
        Integer resolvedBy;
        /** Marker written when the row is OFFERED (the moment of 6: "amend sent, outcome not yet seen"). */
        Map<String, Object> markerOnSend;

        StoryRow copy() {
            final StoryRow r = new StoryRow();
            r.list = list;
            r.moment = moment;
            r.user = user;
            r.market = market;
            r.side = side;
            r.type = type;
            r.tif = tif;
            r.price = price;
            r.quantity = quantity;
            r.budget = budget;
            r.stopPrice = stopPrice;
            r.displayQty = displayQty;
            r.expires = expires;
            r.order = order;
            r.newPrice = newPrice;
            r.newQuantity = newQuantity;
            r.target = target;
            r.expiresInMs = expiresInMs;
            r.markerOnSend = markerOnSend;
            r.rh = rh;
            r.rl = rl;
            return r;
        }

        String outcome() {
            return reply == null ? null : (String) reply.get("outcome");
        }

        long ackedOrder() {
            return "ACK".equals(outcome()) ? (Long) reply.get("order") : 0L;
        }

        Map<String, Object> toJson() {
            final Map<String, Object> m = map("id", id, "request", new long[] {rh, rl}, "user", user);
            switch (list) {
                case "creates" -> {
                    m.put("market", market);
                    m.put("side", side);
                    m.put("type", type);
                    m.put("tif", tif);
                    m.put("price", price);
                    m.put("quantity", quantity);
                    m.put("budget", budget);
                    m.put("stop_price", stopPrice);
                    m.put("display_qty", displayQty);
                    m.put("expires", expires);
                }
                case "amends" -> {
                    m.put("order", order);
                    m.put("new_price", newPrice);
                    m.put("new_quantity", newQuantity);
                    m.put("target", target == null ? null : target.id);
                }
                default -> {
                    m.put("order", order);
                    m.put("target", target == null ? null : target.id);
                }
            }
            m.put("moment", moment);
            m.put("scheduled_ns", scheduledNs);
            m.put("sent_ns", sentNs < 0 ? null : sentNs);
            m.put("reply_ns", replyNs < 0 ? null : replyNs);
            m.put("reply", reply == null ? map("outcome", "UNKNOWN") : reply);
            if (resolves != null) {
                m.put("resolves", resolves);
            }
            if (resolvedBy != null) {
                m.put("resolved_by", resolvedBy);
            }
            if (lateReply != null) {
                m.put("late_reply", lateReply);
            }
            return m;
        }
    }

    /**
     * The seeded story (contract 6, 6.1). Pure scheduling logic: the transport is a {@link StoryPort}, the clock a
     * {@link StoryClock}, so the unit tests run it against a reply stub with a fake clock and no cluster.
     *
     * <p>Open loop: timed rows (every a01 row, the a02 market filler) are queued when due and offered without
     * waiting for any reply. The a02 moments are ordered steps on market 1: a step that names an earlier order waits
     * for that order's ACK, and the moment's await steps wait for an order event, each bounded; an expired bound is
     * a marker, never a silent skip.</p>
     */
    static final class Story implements StorySink {
        static final long SECOND = 1_000_000_000L;
        static final long DEADLINE_NS = 30 * SECOND;        // the story's reply deadline (6: "UNKNOWN")
        static final long RESOLVE_BOUND_NS = 30 * SECOND;   // 6.1 rule 5: the re-send pass is bounded 30 s
        static final long AWAIT_NS = 30 * SECOND;           // one a02 await step (covers an election and a thaw)
        static final long ONE = 100_000_000L;               // 1.0 in 1e-8 units
        static final long CENT = 1_000_000L;                // 0.01: the ME tick of every market (T1M:269)
        static final Set<String> TERMINAL = Set.of("FILLED", "CANCELLED", "REJECTED", "EXPIRED");
        static final long USD_PER_USER = 1_000_000L * ONE;
        static final long BASE_PER_USER = 10_000L * ONE;

        final StoryConfig cfg;
        final StoryClock clock;
        final StoryPort port;
        final Consumer<Map<String, Object>> markerOut;
        final long requestHigh;

        final List<Timed> timeline = new ArrayList<>();
        final List<Step> steps = new ArrayList<>();
        final List<StoryRow> rows = new ArrayList<>();
        final List<StoryRow> unsent = new ArrayList<>();
        final ArrayDeque<StoryRow> queue = new ArrayDeque<>();
        final ArrayDeque<StoryRow> outstanding = new ArrayDeque<>();
        final Map<Long, StoryRow> byCorrelation = new HashMap<>();
        final Map<Long, Track> tracks = new HashMap<>();
        final Map<Long, StoryRow> createByOrder = new HashMap<>();
        final Map<Long, TreeSet<Long>> liveByUser = new HashMap<>();
        final Set<Long> cancelSent = new java.util.HashSet<>();
        final Map<Integer, StoryRow> handles = new HashMap<>();
        final SplittableRandom cancelRng;
        final Set<String> markersWritten = new java.util.HashSet<>();

        long t0;
        long nextCorrelation = 1;
        int nextId = 1;
        int pc;
        long stepStartNs = -1;
        long nextForegroundNs;
        long foregroundSpacingNs;
        int skippedCancels;
        int awaitExpired;
        int holdsExpired;
        int skippedSteps;

        static final class Timed {
            long atNs;
            StoryRow create;      // a01 create or a02 filler create
            int cancelIndex = -1; // a01 cancel slot: the target is chosen at send time
        }

        /** One a02 step. op: create | amend | cancel | await | hold | marker. */
        static final class Step {
            String op;
            String moment;
            StoryRow spec;
            int handle = -1;
            int target = -1;
            String cond;
            long arg;
            String name;
        }

        static final class Track {
            String status = "";
            long filled;
            final Map<String, Integer> kinds = new HashMap<>();

            int count(final String kind) {
                return kinds.getOrDefault(kind, 0);
            }
        }

        Story(final StoryConfig cfg, final StoryClock clock, final StoryPort port, final Consumer<Map<String, Object>> markerOut) {
            this.cfg = cfg;
            this.clock = clock;
            this.port = port;
            this.markerOut = markerOut;
            this.requestHigh = requestHigh(cfg);
            this.cancelRng = new SplittableRandom(cfg.seed ^ 0x5EED_CA9CL);
            this.foregroundSpacingNs = 2 * SECOND / cfg.rate;
            if (cfg.script.equals("a01-mix")) {
                planA01();
            } else if (cfg.script.equals("a03-fill")) {
                planA03();
            } else {
                planA02();
            }
            checkPerUserCap();
        }

        /** requestId high word: (15 << 40) | script << 32 | seed; the low word is the row id (unique per JVM, W0 answer 11). */
        static long requestHigh(final StoryConfig cfg) {
            return (15L << 40) | ((long) (StoryConfig.SCRIPTS.indexOf(cfg.script) + 1) << 32) | cfg.seed;
        }

        /**
         * The deposit table of the users (6 `funding`): per user USD and the base asset of every market the funded
         * script trades (a01-mix: BTC; a02-lifecycle: the bases of markets 1..5), one deposit each. Fixed amounts far
         * above any plan's holds: a01 at the per-user cap holds at most 256 x 3 x 99.99 USD or 256 x 3 BTC.
         */
        static List<Map<String, Object>> fundingPlan(final StoryConfig cfg) {
            final long high = requestHigh(cfg);
            final List<Map<String, Object>> plan = new ArrayList<>();
            long low = 1;
            for (final long user : cfg.users) {
                plan.add(map("request", new long[] {high, low++}, "kind", "deposit", "user", user, "asset", Asset.USD.id(),
                        "amount", USD_PER_USER));
                for (final Market m : cfg.fundsFor.equals("a01-mix") ? new Market[] {Market.BTC_USD} : Market.ALL) {
                    plan.add(map("request", new long[] {high, low++}, "kind", "deposit", "user", user,
                            "asset", m.baseAsset().id(), "amount", BASE_PER_USER));
                }
            }
            return plan;
        }

        // ---------------------------------------------------------- plans (pure functions of the seed)

        static StoryRow create(final String moment, final long user, final int market, final String side, final String type,
                               final String tif, final long price, final long quantity) {
            final StoryRow r = new StoryRow();
            r.list = "creates";
            r.moment = moment;
            r.user = user;
            r.market = market;
            r.side = side;
            r.type = type;
            r.tif = tif;
            r.price = price;
            r.quantity = quantity;
            return r;
        }

        /**
         * a01-mix: rate creates/s of LIMIT on market 1 (users at even positions BUY, odd positions SELL): 50 % resting
         * (BUY 80.00..84.99, SELL 95.00..99.99), 40 % crossing GTC against the other side's resting band, 10 % IOC
         * crossing; plus rate/5 cancels/s of a random live own order of the slot's user.
         */
        private void planA01() {
            final SplittableRandom rng = new SplittableRandom(cfg.seed);
            final int creates = cfg.rate * cfg.seconds;
            final int cancels = cfg.rate / 5 * cfg.seconds;
            final List<Timed> a = new ArrayList<>();
            for (int i = 0; i < creates; i++) {
                final long user = cfg.users[i % cfg.users.length];
                final boolean buy = (i % cfg.users.length) % 2 == 0;
                final int roll = rng.nextInt(100);
                final long qty = (1 + rng.nextInt(3)) * ONE;
                final StoryRow r;
                if (roll < 50) {
                    final long cents = buy ? 8000 + rng.nextInt(500) : 9500 + rng.nextInt(500);
                    r = create("rest", user, 1, buy ? "BUY" : "SELL", "LIMIT", "GTC", cents * CENT, qty);
                } else {
                    final long cents = buy ? 9999 : 8000;
                    r = create(roll < 90 ? "cross" : "ioc", user, 1, buy ? "BUY" : "SELL", "LIMIT", roll < 90 ? "GTC" : "IOC",
                            cents * CENT, qty);
                }
                final Timed t = new Timed();
                t.atNs = i * SECOND / cfg.rate;
                t.create = r;
                a.add(t);
            }
            final List<Timed> b = new ArrayList<>();
            for (int j = 0; j < cancels; j++) {
                final Timed t = new Timed();
                t.atNs = (2 * j + 1) * 5 * SECOND / (2L * cfg.rate);   // midway between create slots
                t.cancelIndex = j;
                b.add(t);
            }
            int i = 0;
            int j = 0;
            while (i < a.size() || j < b.size()) {
                if (j >= b.size() || (i < a.size() && a.get(i).atNs <= b.get(j).atNs)) {
                    timeline.add(a.get(i++));
                } else {
                    timeline.add(b.get(j++));
                }
            }
        }

        // ---------------------------------------------------------- a03-fill (S16 W2, contract 5.5 and 20.1 lines 2, 3)

        static final int PHASE_NONE = 0;      // not an a03 story: nothing waits
        static final int PHASE_FILL = 1;      // phase 1: non-crossing creates, both forwarders on the no-release build
        static final int PHASE_WAIT = 2;      // phase 2: nothing is sent; the drill swaps the forwarders, the gate drains and reopens
        static final int PHASE_REOPEN = 3;    // phase 3: creates again, so the reopen is proved by admits
        static final int PHASE_DONE = 4;
        static final long SIGNAL_POLL_NS = 50_000_000L;   // the signal files are looked at every 50 ms, not on every spin

        private int phase = PHASE_NONE;
        private final List<Timed> reopenPlan = new ArrayList<>();
        private long waitStartNs;
        private long lastSignalPollNs;
        boolean capacityClosed;
        boolean capacityOpened;
        // a01-mix --ioc-burst-on: the burst window starts when the marker file is first seen and lasts 2 s
        static final long IOC_BURST_NS = 2 * SECOND;
        private long burstStartNs = -1;
        private boolean burstEnded;
        int iocBurstRows;

        /**
         * a03-fill: phase 1 is rate x fill_s non-crossing LIMIT GTC creates on market 1 (users at even positions BUY
         * 80.00..84.99, odd positions SELL 95.00..99.99: the a01 resting bands, never crossing), no cancels. Phase 3
         * (rate x reopen_s creates of the same shape) is planned now, so the per-user cap sees it, and released at run
         * time. The fixture signals through files in {@code signal_dir}: {@code capacity_closed} when the tap shows
         * [SUSPENDED, ME_CAPACITY], {@code capacity_open} when it shows [OPEN, ADMIN] after the swap.
         */
        private void planA03() {
            final SplittableRandom rng = new SplittableRandom(cfg.seed);
            phase = PHASE_FILL;
            for (int i = 0; i < cfg.rate * cfg.fillS; i++) {
                final Timed t = new Timed();
                t.atNs = i * SECOND / cfg.rate;
                t.create = a03Create("fill", i, rng);
                timeline.add(t);
            }
            for (int i = 0; i < cfg.rate * cfg.reopenS; i++) {
                final Timed t = new Timed();
                t.atNs = i * SECOND / cfg.rate;   // relative to the start of phase 3
                t.create = a03Create("reopen", i, rng);
                reopenPlan.add(t);
            }
        }

        private StoryRow a03Create(final String moment, final int i, final SplittableRandom rng) {
            final long user = cfg.users[i % cfg.users.length];
            final boolean buy = (i % cfg.users.length) % 2 == 0;
            final long qty = (1 + rng.nextInt(3)) * ONE;
            final long cents = buy ? 8000 + rng.nextInt(500) : 9500 + rng.nextInt(500);
            return create(moment, user, 1, buy ? "BUY" : "SELL", "LIMIT", "GTC", cents * CENT, qty);
        }

        private boolean polledOnce;

        /** True at most every 50 ms of story time: the signal files are looked at on that beat, not on every spin. */
        private boolean signalPoll(final long now) {
            if (polledOnce && now - lastSignalPollNs < SIGNAL_POLL_NS) {
                return false;
            }
            polledOnce = true;
            lastSignalPollNs = now;
            return true;
        }

        /** Phase transitions of a03-fill and the window of --ioc-burst-on; called on every pass of the run loop. */
        private void signals(final long now, final int nextIndex) {
            if (cfg.iocBurstOn == null && phase == PHASE_NONE) {
                return;
            }
            final boolean beat = signalPoll(now);
            if (cfg.iocBurstOn != null && !burstEnded) {
                if (burstStartNs < 0 && beat && clock.exists(cfg.iocBurstOn)) {
                    burstStartNs = now;
                    marker("ioc_burst_started", map("marker_file", cfg.iocBurstOn));
                } else if (burstStartNs >= 0 && now >= burstStartNs + IOC_BURST_NS) {
                    burstEnded = true;
                    marker("ioc_burst_ended", map("rows", iocBurstRows));
                }
            }
            if (phase == PHASE_NONE || phase == PHASE_DONE) {
                return;
            }
            if (!capacityClosed && beat && clock.exists(cfg.signalDir + "/capacity_closed")) {
                capacityClosed = true;
                marker("capacity_closed_seen", map());
            }
            if (phase == PHASE_FILL && nextIndex >= timeline.size()) {
                phase = PHASE_WAIT;
                waitStartNs = now;
                marker("fill_ended", map("rows", rows.size()));
            }
            if (phase == PHASE_WAIT) {
                final boolean opened = beat && clock.exists(cfg.signalDir + "/capacity_open");
                if (opened || now - waitStartNs >= cfg.markerTimeoutS * SECOND) {
                    capacityOpened = opened;
                    marker(opened ? "capacity_open_seen" : "capacity_open_timeout", map("waited_ns", now - waitStartNs));
                    for (final Timed r : reopenPlan) {
                        r.atNs = (now - t0) + r.atNs;
                        timeline.add(r);
                    }
                    phase = PHASE_REOPEN;
                    marker("reopen_started", map("rows", reopenPlan.size()));
                }
            } else if (phase == PHASE_REOPEN && nextIndex >= timeline.size()) {
                phase = PHASE_DONE;
            }
        }

        private boolean phasesPending() {
            return phase != PHASE_NONE && phase != PHASE_DONE;
        }

        Map<String, Object> a03() {
            int created = 0;
            int gate = 0;
            int reopenAcked = 0;
            for (final StoryRow r : rows) {
                if (r.resolves != null || !r.list.equals("creates")) {
                    continue;
                }
                created += r.moment.equals("fill") && "ACK".equals(r.outcome()) ? 1 : 0;
                gate += "REJECT".equals(r.outcome()) && "GATE_CLOSED".equals(r.reply.get("reason")) ? 1 : 0;
                reopenAcked += r.moment.equals("reopen") && "ACK".equals(r.outcome()) ? 1 : 0;
            }
            return map("created", created, "rejected_gate", gate, "cancelled", 0, "reopen_acked", reopenAcked,
                    "closed", capacityClosed, "opened", capacityOpened);
        }

        String a03Line() {
            final Map<String, Object> a = a03();
            return "A03 created=" + a.get("created") + " rejected_gate=" + a.get("rejected_gate") + " cancelled=" + a.get("cancelled")
                    + " reopen_acked=" + a.get("reopen_acked") + " closed=" + a.get("closed") + " opened=" + a.get("opened");
        }

        private Step step(final String op, final String moment) {
            final Step s = new Step();
            s.op = op;
            s.moment = moment;
            steps.add(s);
            return s;
        }

        private int handleCount;

        private int send(final StoryRow spec) {
            final Step s = step("create", spec.moment);
            s.spec = spec;
            s.handle = handleCount++;
            return s.handle;
        }

        private void amend(final String moment, final int target, final long price, final long qty, final Map<String, Object> marker) {
            final Step s = step("amend", moment);
            final StoryRow r = new StoryRow();
            r.list = "amends";
            r.moment = moment;
            r.newPrice = price;
            r.newQuantity = qty;
            r.markerOnSend = marker;
            s.spec = r;
            s.target = target;
        }

        private void cancel(final String moment, final int target) {
            final Step s = step("cancel", moment);
            final StoryRow r = new StoryRow();
            r.list = "cancels";
            r.moment = moment;
            s.spec = r;
            s.target = target;
        }

        private void await(final String moment, final int target, final String cond, final long arg) {
            final Step s = step("await", moment);
            s.target = target;
            s.cond = cond;
            s.arg = arg;
        }

        /** A hold names the order it holds (review F6): the drill reads the id from hold_ready, never guesses it. */
        private void hold(final String moment, final String name, final int target) {
            final Step s = step("hold", moment);
            s.name = name;
            s.target = target;
        }

        private void markerStep(final String moment, final String name) {
            step("marker", moment).name = name;
        }

        /**
         * a02-lifecycle (6, items 1-7). Moments run in order on market 1, each priced in its own band so a leftover of
         * one cannot trade with the next (all inside the ME band 0.01..100.00 and the 50 % collar, W0 answer 7);
         * every moment cancels what it left resting. The seed shifts every market-1 price by 0..9 cents and prices
         * the filler. Users: A = users[0] buys, B = users[1] sells.
         */
        private void planA02() {
            final SplittableRandom rng = new SplittableRandom(cfg.seed);
            final long o = rng.nextInt(10) * CENT;
            final long a = cfg.users[0];
            final long b = cfg.users[1];
            if (!cfg.without.contains("iceberg")) {
                final String m = "iceberg";
                final StoryRow parent = create(m, a, 1, "BUY", "ICEBERG", "GTC", 9000 * CENT + o, 30 * ONE);
                parent.displayQty = 10 * ONE;
                final int ice = send(parent);
                await(m, ice, "ack_new", 1);
                send(create(m, b, 1, "SELL", "LIMIT", "GTC", 8950 * CENT + o, 4 * ONE));   // partial fill below the limit
                await(m, ice, "filled", 4 * ONE);
                hold(m, "slice1_exhausting_fill", ice);
                final StoryRow exhausting = create(m, b, 1, "SELL", "LIMIT", "GTC", 9000 * CENT + o, 6 * ONE);
                exhausting.markerOnSend = map("marker", "slice1_exhausting_fill_sent");
                send(exhausting);
                await(m, ice, "ack_new", 2);                                                // slice 2 refilled
                send(create(m, b, 1, "SELL", "LIMIT", "GTC", 9000 * CENT + o, 10 * ONE));
                await(m, ice, "ack_new", 3);                                                // slice 3 refilled
                send(create(m, b, 1, "SELL", "LIMIT", "GTC", 9000 * CENT + o, 10 * ONE));
                await(m, ice, "terminal", 0);
            }
            if (!cfg.without.contains("replace")) {
                final String m = "replace";
                final int up = send(create(m, a, 1, "BUY", "LIMIT", "GTC", 8500 * CENT + o, 12 * ONE));
                await(m, up, "ack_new", 1);
                send(create(m, b, 1, "SELL", "LIMIT", "GTC", 8500 * CENT + o, 5 * ONE));
                await(m, up, "filled", 5 * ONE);
                hold(m, "replace_open:1", up);
                amend(m, up, 8600 * CENT + o, 12 * ONE, map("marker", "replace_open", "index", 1));   // amend up after a partial fill
                await(m, up, "replaced", 1);
                send(create(m, b, 1, "SELL", "LIMIT", "GTC", 8600 * CENT + o, 4 * ONE));             // fill the new leg
                await(m, up, "filled", 9 * ONE);
                cancel(m, up);                                                                        // cancel the rest
                await(m, up, "terminal", 0);
                final int down = send(create(m, a, 1, "BUY", "LIMIT", "GTC", 8400 * CENT + o, 10 * ONE));
                await(m, down, "ack_new", 1);
                hold(m, "replace_open:2", down);
                amend(m, down, 8300 * CENT + o, 8 * ONE, map("marker", "replace_open", "index", 2));  // amend down
                await(m, down, "replaced", 1);
                cancel(m, down);
                await(m, down, "terminal", 0);
            }
            if (!cfg.without.contains("maker_replace")) {
                final String m = "maker_replace";
                final int ask = send(create(m, b, 1, "SELL", "LIMIT", "GTC", 8800 * CENT + o, 2 * ONE));
                await(m, ask, "ack_new", 1);
                final int maker = send(create(m, a, 1, "BUY", "LIMIT_MAKER", "GTC", 8700 * CENT + o, 2 * ONE));
                await(m, maker, "ack_new", 1);
                hold(m, "replace_open:3", maker);
                // the new LIMIT_MAKER leg would cross the ask: REPLACED with ME_REJECTED, old leg kept (W0 answer 7, A8)
                amend(m, maker, 8800 * CENT + o, 2 * ONE, map("marker", "replace_open", "index", 3));
                await(m, maker, "replaced", 1);
                cancel(m, maker);
                cancel(m, ask);
                await(m, maker, "terminal", 0);
                await(m, ask, "terminal", 0);
            }
            if (!cfg.without.contains("stop")) {
                final String m = "stop";
                final int ask = send(create(m, b, 1, "SELL", "LIMIT", "GTC", 9500 * CENT + o, ONE));
                await(m, ask, "ack_new", 1);
                // a BUY stop is refused while bestAsk >= stop (OrderEngine.java:397-398): stop above the 95 ask
                final StoryRow stop = create(m, a, 1, "BUY", "STOP_LOSS", "GTC", 0, ONE);
                stop.stopPrice = 9600 * CENT + o;
                stop.budget = 100 * ONE;   // explicit budget (S14 DEFECT-3): the child fills at 98 under it
                final int s = send(stop);
                await(m, s, "acked", 0);
                final int high = send(create(m, b, 1, "SELL", "LIMIT", "GTC", 9800 * CENT + o, ONE));
                await(m, high, "ack_new", 1);
                // taking the 95 ask moves bestAsk to 98 >= stop: the forwarder's MarketTick fires the stop (S13)
                final StoryRow trigger = create(m, a, 1, "BUY", "LIMIT", "GTC", 9500 * CENT + o, ONE);
                trigger.markerOnSend = map("marker", "stop_trigger_sent");
                final int t = send(trigger);
                await(m, t, "terminal", 0);
                await(m, s, "terminal", 0);
                await(m, high, "terminal", 0);
            }
            if (!cfg.without.contains("ioc_fok")) {
                final String m = "ioc_fok";
                final int ask = send(create(m, b, 1, "SELL", "LIMIT", "GTC", 8000 * CENT + o, 2 * ONE));
                await(m, ask, "ack_new", 1);
                final int ioc = send(create(m, a, 1, "BUY", "LIMIT", "IOC", 8000 * CENT + o, 10 * ONE));   // partial + EXPIRED
                await(m, ioc, "terminal", 0);
                final int ask2 = send(create(m, b, 1, "SELL", "LIMIT", "GTC", 8100 * CENT + o, ONE));
                await(m, ask2, "ack_new", 1);
                final int kill = send(create(m, a, 1, "BUY", "LIMIT", "FOK", 8100 * CENT + o, 2 * ONE));  // infeasible
                await(m, kill, "terminal", 0);
                final int fill = send(create(m, a, 1, "BUY", "LIMIT", "FOK", 8100 * CENT + o, ONE));      // feasible
                await(m, fill, "terminal", 0);
                await(m, ask2, "terminal", 0);
            }
            if (!cfg.without.contains("gtd")) {
                final String m = "gtd";
                final StoryRow gtd = create(m, a, 1, "BUY", "LIMIT", "GTD", 7000 * CENT + o, ONE);
                gtd.expiresInMs = 5_000;   // expires 5 s after it is built, on the ME timer
                final int g = send(gtd);
                await(m, g, "terminal", 0);
            }
            markerStep("end", "moments_done");
            if (!cfg.without.contains("markets")) {
                // item 7 and the filler: crossing pairs on markets 2..5 at rate/2 commands/s for `seconds`
                final int commands = cfg.rate * cfg.seconds / 2;
                final int pairs = Math.max(4, commands / 2);
                final int n = cfg.users.length - cfg.users.length % 2;
                for (int k = 0; k < pairs; k++) {
                    final int market = 2 + k % 4;
                    final long cents = 4500 + rng.nextInt(1001);
                    final long buyer = cfg.users[(2 * k) % n];
                    final long seller = cfg.users[(2 * k + 1) % n];
                    final long qty = (1 + rng.nextInt(2)) * ONE;
                    for (int side = 0; side < 2; side++) {
                        final Timed t = new Timed();
                        t.atNs = (2L * k + side) * foregroundSpacingNs;
                        t.create = create("markets", side == 0 ? buyer : seller, market, side == 0 ? "BUY" : "SELL", "LIMIT",
                                "GTC", cents * CENT, qty);
                        timeline.add(t);
                    }
                }
            }
        }

        /** RequestTable.PER_USER_CAP (256 retained requests per user, TTL 15 min, W0 F-S15-28): refused before sending. */
        private void checkPerUserCap() {
            final Map<Long, Integer> perUser = new TreeMap<>();
            for (final Timed t : timeline) {
                final long user = t.create != null ? t.create.user : cfg.users[t.cancelIndex % cfg.users.length];
                perUser.merge(user, 1, Integer::sum);
            }
            for (final Timed t : reopenPlan) {
                perUser.merge(t.create.user, 1, Integer::sum);
            }
            for (final Step s : steps) {
                if (s.op.equals("create")) {
                    perUser.merge(s.spec.user, 1, Integer::sum);
                } else if (s.op.equals("amend") || s.op.equals("cancel")) {
                    perUser.merge(handleUser(s.target), 1, Integer::sum);
                }
            }
            for (final Map.Entry<Long, Integer> e : perUser.entrySet()) {
                if (e.getValue() > RequestTable.PER_USER_CAP) {
                    throw new IllegalArgumentException("story " + cfg.script + " plans " + e.getValue() + " requests for user "
                            + e.getKey() + "; the core retains at most " + RequestTable.PER_USER_CAP
                            + " per user (RequestTable.PER_USER_CAP): pass more users");
                }
            }
        }

        private long handleUser(final int handle) {
            for (final Step s : steps) {
                if (s.op.equals("create") && s.handle == handle) {
                    return s.spec.user;
                }
            }
            throw new IllegalStateException("story step names an unknown handle " + handle);
        }

        // ---------------------------------------------------------- run

        void marker(final String name, final Map<String, Object> attrs) {
            final Map<String, Object> m = map("marker", name);
            m.putAll(attrs);
            m.put("at_ns", clock.nowNs());
            markerOut.accept(m);
        }

        Summary run() {
            t0 = clock.nowNs();
            nextForegroundNs = t0;
            marker("load_started", map("script", cfg.script, "seed", cfg.seed, "rate", cfg.rate, "seconds", cfg.seconds));
            int ti = 0;
            while (true) {
                final long now = clock.nowNs();
                signals(now, ti);
                while (ti < timeline.size() && t0 + timeline.get(ti).atNs <= now) {
                    due(timeline.get(ti), t0 + timeline.get(ti).atNs);
                    ti++;
                }
                signals(now, ti);
                foreground(now);
                int work = flush(now);
                work += port.poll();
                expire(clock.nowNs());
                if (ti >= timeline.size() && pc >= steps.size() && !phasesPending()) {
                    break;   // what is still queued is offered (or found UNSENT) by drain()
                }
                clock.idle(work);
            }
            marker("load_ended", map("rows", rows.size()));
            drain();
            marker("drained", map("unknown", countOriginal("UNKNOWN")));
            resolve();
            return new Summary(this);
        }

        private void due(final Timed t, final long scheduledNs) {
            if (t.create != null) {
                final StoryRow c = t.create.copy();
                if (burstStartNs >= 0 && scheduledNs >= burstStartNs && scheduledNs < burstStartNs + IOC_BURST_NS) {
                    // --ioc-burst-on: the whole band is crossed with IOC, so the ids minted during the pause are ME-terminal
                    c.moment = "ioc_burst";
                    c.tif = "IOC";
                    c.price = (c.side.equals("BUY") ? 9999 : 8000) * CENT;
                    iocBurstRows++;
                }
                enqueue(c, scheduledNs);
                return;
            }
            final long user = cfg.users[t.cancelIndex % cfg.users.length];
            final TreeSet<Long> live = liveByUser.get(user);
            if (live == null || live.isEmpty()) {
                skippedCancels++;
                return;
            }
            final Long[] candidates = live.toArray(new Long[0]);
            final long order = candidates[cancelRng.nextInt(candidates.length)];
            live.remove(order);
            cancelSent.add(order);
            final StoryRow r = new StoryRow();
            r.list = "cancels";
            r.moment = "cancel";
            r.user = user;
            r.order = order;
            r.target = createByOrder.get(order);
            enqueue(r, scheduledNs);
        }

        private void enqueue(final StoryRow r, final long scheduledNs) {
            r.id = nextId++;
            if (r.resolves == null) {
                r.rh = requestHigh;
                r.rl = r.id;
            }
            if (r.expiresInMs > 0 && r.resolves == null) {
                r.expires = scheduledNs / 1_000_000L + r.expiresInMs;
            }
            r.scheduledNs = scheduledNs;
            rows.add(r);
            queue.add(r);
        }

        private int flush(final long now) {
            int work = 0;
            while (!queue.isEmpty()) {
                final StoryRow r = queue.peek();
                final long correlation = nextCorrelation++;
                if (!port.offer(r, correlation)) {
                    break;
                }
                queue.poll();
                r.sentNs = now;
                byCorrelation.put(correlation, r);
                outstanding.add(r);
                if (r.markerOnSend != null && r.resolves == null) {
                    final Map<String, Object> attrs = new LinkedHashMap<>(r.markerOnSend);
                    final String name = (String) attrs.remove("marker");
                    if (r.list.equals("amends")) {
                        attrs.put("order", r.order);
                    }
                    attrs.put("row", r.id);
                    once(name + attrs.getOrDefault("index", ""), name, attrs);
                }
                work++;
            }
            return work;
        }

        private void once(final String key, final String name, final Map<String, Object> attrs) {
            if (markersWritten.add(key)) {
                marker(name, attrs);
            }
        }

        private void expire(final long now) {
            while (!outstanding.isEmpty()) {
                final StoryRow r = outstanding.peek();
                if (r.reply != null) {
                    outstanding.poll();
                } else if (now - r.sentNs >= DEADLINE_NS) {
                    outstanding.poll();
                    r.reply = map("outcome", "UNKNOWN");
                } else {
                    break;
                }
            }
        }

        private void foreground(final long now) {
            while (pc < steps.size()) {
                final Step s = steps.get(pc);
                if (stepStartNs < 0) {
                    stepStartNs = now;
                }
                final boolean advanced = switch (s.op) {
                    case "create" -> {
                        if (now < nextForegroundNs) {
                            yield false;
                        }
                        final StoryRow r = s.spec.copy();
                        handles.put(s.handle, r);
                        enqueue(r, now);
                        nextForegroundNs = now + foregroundSpacingNs;
                        yield true;
                    }
                    case "amend", "cancel" -> {
                        final StoryRow target = handles.get(s.target);
                        if (target == null || target.reply == null) {
                            if (now - stepStartNs >= AWAIT_NS) {
                                skip(s, "target_unanswered");
                                yield true;
                            }
                            yield false;
                        }
                        if (!"ACK".equals(target.outcome())) {
                            skip(s, "target_not_acked");
                            yield true;
                        }
                        if (now < nextForegroundNs) {
                            yield false;
                        }
                        final StoryRow r = s.spec.copy();
                        r.user = target.user;
                        r.order = target.ackedOrder();
                        r.target = target;
                        if (r.list.equals("cancels")) {
                            cancelSent.add(r.order);
                        }
                        enqueue(r, now);
                        nextForegroundNs = now + foregroundSpacingNs;
                        yield true;
                    }
                    case "await" -> {
                        final StoryRow target = handles.get(s.target);
                        if (target != null && target.reply != null && !"ACK".equals(target.outcome())) {
                            skip(s, "await_unreachable");
                            yield true;
                        }
                        if (target != null && holds(s, target)) {
                            yield true;
                        }
                        if (now - stepStartNs >= AWAIT_NS) {
                            awaitExpired++;
                            marker("await_expired", map("moment", s.moment, "step", pc, "cond", s.cond, "arg", s.arg,
                                    "row", target == null ? null : target.id));
                            yield true;
                        }
                        yield false;
                    }
                    case "hold" -> {
                        if (!cfg.holds.contains(s.name)) {
                            yield true;
                        }
                        final StoryRow held = handles.get(s.target);
                        once("hold_ready:" + s.name, "hold_ready", map("hold", s.name, "go", gateFile(s.name),
                                "order", held == null || held.ackedOrder() == 0L ? null : held.ackedOrder(),
                                "row", held == null ? null : held.id));
                        if (clock.exists(gateFile(s.name))) {
                            once("hold_released:" + s.name, "hold_released", map("hold", s.name));
                            yield true;
                        }
                        if (now - stepStartNs >= cfg.holdMs * 1_000_000L) {
                            holdsExpired++;
                            once("hold_expired:" + s.name, "hold_expired", map("hold", s.name));
                            yield true;
                        }
                        yield false;
                    }
                    case "marker" -> {
                        once(s.name, s.name, map());
                        yield true;
                    }
                    default -> throw new IllegalStateException("story step " + s.op);
                };
                if (!advanced) {
                    return;
                }
                pc++;
                stepStartNs = -1;
            }
        }

        private String gateFile(final String hold) {
            return cfg.gateDir + "/" + hold.replace(':', '-') + ".go";
        }

        private void skip(final Step s, final String why) {
            skippedSteps++;
            marker("step_skipped", map("moment", s.moment, "step", pc, "op", s.op, "why", why));
        }

        private boolean holds(final Step s, final StoryRow target) {
            final long order = target.ackedOrder();
            if (order == 0) {
                return false;
            }
            final Track t = tracks.computeIfAbsent(order, k -> new Track());
            return switch (s.cond) {
                case "acked" -> true;
                case "ack_new" -> t.count("ACK_NEW") >= s.arg;
                case "filled" -> t.filled >= s.arg;
                case "replaced" -> t.count("REPLACED") >= s.arg;
                case "terminal" -> TERMINAL.contains(t.status);
                default -> throw new IllegalStateException("story await " + s.cond);
            };
        }

        /** Until every offered row has a reply or its deadline passed; rows still queued a deadline after the load are UNSENT. */
        private void drain() {
            final long start = clock.nowNs();
            while (true) {
                final long now = clock.nowNs();
                int work = flush(now);
                work += port.poll();
                expire(clock.nowNs());
                if (!queue.isEmpty() && now - start >= DEADLINE_NS) {
                    while (!queue.isEmpty()) {
                        final StoryRow r = queue.poll();
                        rows.remove(r);
                        r.reply = map("outcome", "UNSENT");
                        unsent.add(r);
                    }
                }
                if (queue.isEmpty() && outstanding.isEmpty()) {
                    return;
                }
                clock.idle(work);
            }
        }

        /** 6.1: every UNKNOWN row is re-sent once with the SAME requestId, at the story rate, bounded 30 s. */
        private void resolve() {
            final List<StoryRow> unknown = new ArrayList<>();
            for (final StoryRow r : rows) {
                if (r.resolves == null && "UNKNOWN".equals(r.outcome())) {
                    unknown.add(r);
                }
            }
            if (unknown.isEmpty()) {
                return;
            }
            if (cfg.resolveGate != null) {
                final long start = clock.nowNs();
                marker("resolve_gate_wait", map("gate", cfg.resolveGate));
                while (!clock.exists(cfg.resolveGate)) {
                    if (clock.nowNs() - start >= cfg.resolveGateMs * 1_000_000L) {
                        marker("resolve_gate_expired", map("gate", cfg.resolveGate));
                        break;
                    }
                    clock.idle(port.poll());
                }
            }
            marker("resolution_started", map("unknown", unknown.size()));
            final long start = clock.nowNs();
            final long interval = SECOND / cfg.rate;
            final List<StoryRow> resent = new ArrayList<>();
            int next = 0;
            while (next < unknown.size()) {
                final long now = clock.nowNs();
                if (now - start >= RESOLVE_BOUND_NS) {
                    marker("resolution_bound_hit", map("not_resent", unknown.size() - next));
                    break;
                }
                if (now >= start + next * interval) {
                    final StoryRow orig = unknown.get(next++);
                    final StoryRow r = orig.copy();
                    r.resolves = orig.id;
                    r.markerOnSend = null;
                    enqueue(r, now);
                    resent.add(r);
                }
                int work = flush(now);
                work += port.poll();
                expire(clock.nowNs());
                clock.idle(work);
            }
            drain();
            int resolved = 0;
            for (final StoryRow r : resent) {
                final String outcome = r.outcome();
                if ("ACK".equals(outcome) || "REJECT".equals(outcome)) {
                    for (final StoryRow orig : unknown) {
                        if (orig.id == r.resolves) {
                            orig.resolvedBy = r.id;
                        }
                    }
                    resolved++;
                }
            }
            marker("resolution_ended", map("resent", resent.size(), "resolved", resolved));
        }

        private int countOriginal(final String outcome) {
            int n = 0;
            for (final StoryRow r : rows) {
                if (r.resolves == null && outcome.equals(r.outcome())) {
                    n++;
                }
            }
            return n;
        }

        // ---------------------------------------------------------- egress (StorySink)

        private StoryRow replied(final long correlationId, final Map<String, Object> reply) {
            final StoryRow r = byCorrelation.get(correlationId);
            if (r == null) {
                return null;
            }
            if (r.reply == null) {
                r.reply = reply;
                r.replyNs = clock.nowNs();
                return r;
            }
            if ("UNKNOWN".equals(r.outcome()) && r.lateReply == null) {
                reply.put("at_ns", clock.nowNs());
                r.lateReply = reply;   // past the deadline: evidence, not the answer (6); the re-send resolves it
            }
            return null;
        }

        public void onAck(final long correlationId, final long orderId, final boolean duplicate, final int holdAsset,
                          final long holdAmount, final String status) {
            final StoryRow r = replied(correlationId, map("outcome", "ACK", "order", orderId, "duplicate", duplicate,
                    "hold_asset", holdAsset, "hold_amount", holdAmount, "status", status));
            if (r == null || !r.list.equals("creates")) {
                return;
            }
            createByOrder.putIfAbsent(orderId, r);
            final Track t = tracks.computeIfAbsent(orderId, k -> new Track());
            if (t.status.isEmpty()) {
                t.status = status;
            }
            if (!TERMINAL.contains(t.status) && !cancelSent.contains(orderId) && r.tif.equals("GTC")) {
                liveByUser.computeIfAbsent(r.user, k -> new TreeSet<>()).add(orderId);
            }
        }

        public void onReject(final long correlationId, final String reason, final int meReason, final long detail, final long orderId) {
            replied(correlationId, map("outcome", "REJECT", "reason", reason, "me_reason", meReason, "detail", detail));
        }

        public void onEvent(final long orderId, final String kind, final String status, final long filled) {
            final Track t = tracks.computeIfAbsent(orderId, k -> new Track());
            t.kinds.merge(kind, 1, Integer::sum);
            t.status = status;
            t.filled = Math.max(t.filled, filled);
            if (TERMINAL.contains(status)) {
                final StoryRow c = createByOrder.get(orderId);
                if (c != null) {
                    final TreeSet<Long> live = liveByUser.get(c.user);
                    if (live != null) {
                        live.remove(orderId);
                    }
                }
            }
        }

        // ---------------------------------------------------------- output

        /** JSON lines {"story": creates|amends|cancels|unsent, "row": {...}} in row id order. */
        String requestLog() {
            final StringBuilder sb = new StringBuilder();
            for (final StoryRow r : rows) {
                sb.append(json(map("story", r.list, "row", r.toJson()))).append('\n');
            }
            for (final StoryRow r : unsent) {
                sb.append(json(map("story", "unsent", "row", r.toJson()))).append('\n');
            }
            return sb.toString();
        }

        record Summary(String script, int sent, int acked, int unknown, int rejected, int resolved, int unsent, int resent,
                       int skippedCancels, int awaitExpired, int holdsExpired, int skippedSteps, int iocBurstRows,
                       Map<String, Object> a03) {
            Summary(final Story s) {
                this(s.cfg.script, count(s, r -> r.sentNs >= 0), count(s, r -> "ACK".equals(r.outcome())),
                        count(s, r -> "UNKNOWN".equals(r.outcome())), count(s, r -> "REJECT".equals(r.outcome())),
                        count(s, r -> r.resolvedBy != null), s.unsent.size(), countResent(s), s.skippedCancels, s.awaitExpired,
                        s.holdsExpired, s.skippedSteps, s.iocBurstRows, s.cfg.script.equals("a03-fill") ? s.a03() : null);
            }

            private static int count(final Story s, final Predicate<StoryRow> p) {
                int n = 0;
                for (final StoryRow r : s.rows) {
                    if (r.resolves == null && p.test(r)) {
                        n++;
                    }
                }
                return n;
            }

            private static int countResent(final Story s) {
                int n = 0;
                for (final StoryRow r : s.rows) {
                    if (r.resolves != null) {
                        n++;
                    }
                }
                return n;
            }

            /** A story with nothing sent, or every request UNKNOWN, is a setup failure (INCONCLUSIVE), never a PASS. */
            boolean setupFailure() {
                return sent == 0 || unknown == sent;
            }

            String storyLine() {
                return "STORY sent=" + sent + " acked=" + acked + " unknown=" + unknown + " rejected=" + rejected
                        + " resolved=" + resolved;
            }

            Map<String, Object> json() {
                final Map<String, Object> m = map("verb", "story", "script", script, "sent", sent, "acked", acked, "unknown", unknown,
                        "rejected", rejected, "resolved", resolved, "unresolved", unknown - resolved, "unsent", unsent,
                        "resent", resent, "skipped_cancels", skippedCancels, "await_expired", awaitExpired,
                        "holds_expired", holdsExpired, "skipped_steps", skippedSteps, "ioc_burst_rows", iocBurstRows,
                        "setup_failure", setupFailure());
                if (a03 != null) {
                    m.put("a03", a03);
                }
                return m;
            }
        }
    }

    // ------------------------------------------------------------------ continuity (S15 5.7)

    /** dispatchSeq (or eventSeq) values seen by a tap; density over [first, last], duplicates counted, kept once. */
    static final class SeqDensity {
        final TreeSet<Long> seen = new TreeSet<>();
        long duplicates;

        void add(final long seq) {
            if (!seen.add(seq)) {
                duplicates++;
            }
        }

        long first() {
            return seen.isEmpty() ? 0 : seen.first();
        }

        long last() {
            return seen.isEmpty() ? 0 : seen.last();
        }

        List<long[]> gaps() {
            final List<long[]> gaps = new ArrayList<>();
            long previous = Long.MIN_VALUE;
            for (final long s : seen) {
                if (previous != Long.MIN_VALUE && s > previous + 1) {
                    gaps.add(new long[] {previous + 1, s - 1});
                }
                previous = s;
            }
            return gaps;
        }

        String tapLine() {
            final StringBuilder g = new StringBuilder("[");
            boolean firstGap = true;
            for (final long[] gap : gaps()) {
                g.append(firstGap ? "" : ",").append('[').append(gap[0]).append(',').append(gap[1]).append(']');
                firstGap = false;
            }
            return "TAP first=" + first() + " last=" + last() + " rows=" + seen.size() + " gaps=" + g.append(']');
        }

        Map<String, Object> json() {
            return map("first", first(), "last", last(), "rows", seen.size(), "duplicates", duplicates, "gaps", gaps());
        }
    }

    /** Session transitions of a long-lived session, each with its wall time and the last seqs seen before it. */
    static final class Continuity {
        final SeqDensity dispatch = new SeqDensity();
        final SeqDensity events = new SeqDensity();
        final Consumer<Map<String, Object>> sink;
        final Map<String, Integer> counts = new TreeMap<>();

        Continuity(final Consumer<Map<String, Object>> sink) {
            this.sink = sink;
        }

        void note(final String event, final Map<String, Object> attrs) {
            counts.merge(event, 1, Integer::sum);
            final Map<String, Object> m = map("event", event, "at_ms", System.currentTimeMillis(),
                    "last_dispatch_seq", dispatch.last(), "last_event_seq", events.last());
            m.putAll(attrs);
            sink.accept(m);
        }

        Map<String, Object> summary() {
            return map("dispatch", dispatch.json(), "events", events.json(), "transitions", new TreeMap<>(counts));
        }
    }

    // ------------------------------------------------------------------ egress

    final class Listener implements EgressListener {
        long expectCorrelation;
        boolean finished;
        boolean refused;
        String lastAdminResult = "";
        long nextOrderId;
        long balanceCorr, holdCorr;
        boolean balancesEnd, holdsEnd, positionSeen, journalEnabled;
        long consumePosition, lastAppliedTradeId;
        /** v7 FeedPositionReport (S16 W2): the bound ME epoch, the feed cursor and the halt latch. */
        long meEpoch, lastAppliedJournalSeq;
        boolean feedHalted;
        String haltReason = "NONE";
        int pendingCount;
        long pendingHead;
        PrintWriter tap;
        long tapped;
        StorySink story;
        boolean reregister;
        final Map<String, String> balances = new java.util.LinkedHashMap<>();
        final Map<Long, String> holds = new java.util.LinkedHashMap<>();

        void reset() {
            nextPage();
            rows.clear();
        }

        /** The reply state of one request; the rows collected so far are kept (order-dump pages). */
        void nextPage() {
            finished = false;
            refused = false;
            lastAdminResult = "";
        }

        private void finish(final int template) {
            if (done.test(template)) {
                finished = true;
            }
        }

        public void onNewLeader(final long clusterSessionId, final long leadershipTermId, final int leaderMemberId,
                                final String ingressEndpoints) {
            reregister = true;   // 5.7 rule 1: the egress mask is registered again on the new leader
            continuity.note("new_leader", map("session", clusterSessionId, "term", leadershipTermId, "leader", leaderMemberId));
        }

        public void onSessionEvent(final long correlationId, final long clusterSessionId, final long leadershipTermId,
                                   final int leaderMemberId, final EventCode code, final String detail) {
            if (code != EventCode.OK) {
                continuity.note("session_event", map("session", clusterSessionId, "term", leadershipTermId, "leader", leaderMemberId,
                        "code", String.valueOf(code), "detail", String.valueOf(detail)));
            }
        }

        public void onMessage(final long session, final long timestamp, final DirectBuffer b, final int offset,
                              final int length, final Header ignored) {
            if (length < HEADER) {
                return;
            }
            header.wrap(b, offset);
            final int t = header.templateId();
            if (tap != null) {
                tapRow(t, timestamp, b, offset);
            }
            if (story != null && storyRow(t, b, offset)) {
                return;
            }
            switch (t) {
                case AdminAckDecoder.TEMPLATE_ID -> {
                    final AdminAckDecoder d = new AdminAckDecoder().wrapAndApplyHeader(b, offset, header);
                    if (d.correlationId() != expectCorrelation) return;
                    lastAdminResult = d.result().name();
                    rows.add("{\"t\":\"AdminAck\",\"ref\":" + d.refTemplateId() + ",\"result\":" + q(lastAdminResult)
                            + ",\"reason\":" + d.reason() + ",\"configVersion\":" + d.configVersion() + "}");
                    finish(t);
                }
                case OrderAckDecoder.TEMPLATE_ID -> {
                    final OrderAckDecoder d = new OrderAckDecoder().wrapAndApplyHeader(b, offset, header);
                    if (d.correlationId() != expectCorrelation) return;
                    rows.add("{\"t\":\"OrderAck\",\"order\":" + d.orderId() + ",\"user\":" + d.userId() + ",\"market\":" + d.marketId()
                            + ",\"status\":" + q(d.status().name()) + ",\"duplicate\":" + (d.duplicate() == BoolFlag.TRUE)
                            + ",\"hold_asset\":" + d.holdAssetId() + ",\"hold_amount\":" + d.holdAmount()
                            + ",\"event_seq\":" + d.eventSeq() + ",\"request\":[" + d.requestIdHigh() + "," + d.requestIdLow() + "]}");
                    finish(t);
                }
                case OrderRejectDecoder.TEMPLATE_ID -> {
                    final OrderRejectDecoder d = new OrderRejectDecoder().wrapAndApplyHeader(b, offset, header);
                    if (d.correlationId() != expectCorrelation) return;
                    refused = true;
                    rows.add("{\"t\":\"OrderReject\",\"ref\":" + d.refTemplateId() + ",\"reason\":" + q(d.reason().name())
                            + ",\"me_reason\":" + d.meReason() + ",\"detail\":" + d.detail() + ",\"order\":" + d.orderId() + "}");
                    finish(t);
                }
                case DepositAckDecoder.TEMPLATE_ID -> {
                    final DepositAckDecoder d = new DepositAckDecoder().wrapAndApplyHeader(b, offset, header);
                    if (d.correlationId() != expectCorrelation) return;
                    rows.add("{\"t\":\"DepositAck\",\"user\":" + d.userId() + ",\"asset\":" + d.assetId() + ",\"amount\":" + d.amount()
                            + ",\"duplicate\":" + (d.duplicate() == BoolFlag.TRUE) + "}");
                    finish(t);
                }
                case DepositRejectDecoder.TEMPLATE_ID -> {
                    final DepositRejectDecoder d = new DepositRejectDecoder().wrapAndApplyHeader(b, offset, header);
                    if (d.correlationId() != expectCorrelation) return;
                    refused = true;
                    rows.add("{\"t\":\"DepositReject\",\"reason\":" + q(d.reason().name()) + "}");
                    finish(t);
                }
                case WithdrawAckDecoder.TEMPLATE_ID -> {
                    final WithdrawAckDecoder d = new WithdrawAckDecoder().wrapAndApplyHeader(b, offset, header);
                    if (d.correlationId() != expectCorrelation) return;
                    rows.add("{\"t\":\"WithdrawAck\",\"user\":" + d.userId() + ",\"asset\":" + d.assetId() + ",\"amount\":" + d.amount()
                            + ",\"duplicate\":" + (d.duplicate() == BoolFlag.TRUE) + "}");
                    finish(t);
                }
                case WithdrawRejectDecoder.TEMPLATE_ID -> {
                    final WithdrawRejectDecoder d = new WithdrawRejectDecoder().wrapAndApplyHeader(b, offset, header);
                    if (d.correlationId() != expectCorrelation) return;
                    refused = true;
                    rows.add("{\"t\":\"WithdrawReject\",\"reason\":" + q(d.reason().name()) + "}");
                    finish(t);
                }
                case FeedPositionReportDecoder.TEMPLATE_ID -> {
                    final FeedPositionReportDecoder d = new FeedPositionReportDecoder().wrapAndApplyHeader(b, offset, header);
                    if (d.correlationId() != expectCorrelation) return;
                    consumePosition = d.consumePosition();
                    lastAppliedTradeId = d.lastAppliedTradeId();
                    journalEnabled = d.journalEnabled() == BoolFlag.TRUE;
                    meEpoch = d.meEpoch();
                    lastAppliedJournalSeq = d.lastAppliedJournalSeq();
                    feedHalted = d.feedHalted() == BoolFlag.TRUE;
                    haltReason = d.haltReason().name();
                    positionSeen = true;
                    rows.add("{\"t\":\"FeedPositionReport\",\"consumePosition\":" + consumePosition + ",\"lastAppliedTradeId\":"
                            + lastAppliedTradeId + ",\"journalEnabled\":" + journalEnabled + ",\"meEpoch\":" + meEpoch
                            + ",\"lastAppliedJournalSeq\":" + lastAppliedJournalSeq + ",\"feedHalted\":" + feedHalted
                            + ",\"haltReason\":" + q(haltReason) + "}");
                    finish(t);
                }
                case OrderSnapshotBatchDecoder.TEMPLATE_ID -> {
                    final OrderSnapshotBatchDecoder d = new OrderSnapshotBatchDecoder().wrapAndApplyHeader(b, offset, header);
                    for (final OrderSnapshotBatchDecoder.OrdersDecoder o : d.orders()) {
                        rows.add("{\"order\":" + o.orderId() + ",\"user\":" + o.userId() + ",\"market\":" + o.marketId()
                                + ",\"status\":" + q(o.status().name()) + ",\"side\":" + q(o.side().name())
                                + ",\"type\":" + q(o.orderType().name()) + ",\"tif\":" + q(o.timeInForce().name())
                                + ",\"price\":" + o.price() + ",\"quantity\":" + o.quantity() + ",\"filled\":" + o.filledQty()
                                + ",\"remaining\":" + o.remainingQty() + ",\"stop_price\":" + o.stopPrice()
                                + ",\"display_qty\":" + o.displayQty() + ",\"expires_at_ms\":" + o.expiresAtMs()
                                + ",\"hold_asset\":" + o.holdAssetId() + ",\"hold_amount\":" + o.holdAmount()
                                + ",\"me_order_id\":" + o.meOrderId() + ",\"hidden_qty\":" + o.hiddenQty()
                                + ",\"slice_seq\":" + o.sliceSeq() + ",\"budget\":" + o.budget() + "}");
                    }
                }
                case OrderSnapshotEndDecoder.TEMPLATE_ID -> {
                    final OrderSnapshotEndDecoder d = new OrderSnapshotEndDecoder().wrapAndApplyHeader(b, offset, header);
                    if (d.correlationId() != expectCorrelation) return;
                    nextOrderId = d.nextOrderId();
                    finish(t);
                }
                case BalanceUpdateDecoder.TEMPLATE_ID -> {
                    if (balancesEnd) return;
                    final BalanceUpdateDecoder d = new BalanceUpdateDecoder().wrapAndApplyHeader(b, offset, header);
                    balance(d.userId(), d.assetId(), d.available(), d.locked());
                }
                case BalanceUpdateBatchDecoder.TEMPLATE_ID -> {
                    if (balancesEnd) return;
                    final BalanceUpdateBatchDecoder d = new BalanceUpdateBatchDecoder().wrapAndApplyHeader(b, offset, header);
                    for (final BalanceUpdateBatchDecoder.UpdatesDecoder u : d.updates()) {
                        balance(u.userId(), u.assetId(), u.available(), u.locked());
                    }
                }
                case BalanceSnapshotEndDecoder.TEMPLATE_ID -> {
                    if (new BalanceSnapshotEndDecoder().wrapAndApplyHeader(b, offset, header).correlationId() == balanceCorr) {
                        balancesEnd = true;
                        finish(t);
                    }
                }
                case HoldSnapshotEntryDecoder.TEMPLATE_ID -> {
                    if (holdsEnd) return;
                    final HoldSnapshotEntryDecoder d = new HoldSnapshotEntryDecoder().wrapAndApplyHeader(b, offset, header);
                    hold(d.orderId(), d.userId(), d.assetId(), d.remaining());
                }
                case HoldSnapshotBatchDecoder.TEMPLATE_ID -> {
                    if (holdsEnd) return;
                    final HoldSnapshotBatchDecoder d = new HoldSnapshotBatchDecoder().wrapAndApplyHeader(b, offset, header);
                    for (final HoldSnapshotBatchDecoder.HoldsDecoder h : d.holds()) {
                        hold(h.orderId(), h.userId(), h.assetId(), h.remaining());
                    }
                }
                case HoldSnapshotEndDecoder.TEMPLATE_ID -> {
                    if (new HoldSnapshotEndDecoder().wrapAndApplyHeader(b, offset, header).correlationId() == holdCorr) {
                        holdsEnd = true;
                        finish(t);
                    }
                }
                case MeDispatchDecoder.TEMPLATE_ID -> {
                    if (tap == null) {
                        final MeDispatchDecoder d = new MeDispatchDecoder().wrapAndApplyHeader(b, offset, header);
                        rows.add(dispatch(d.dispatchSeq(), d.commandIdHigh(), d.commandIdLow(), d.kind().name(), d.userId(),
                                d.omsOrderId(), d.oldOrderId(), d.marketId(), d.price(), d.quantity(), d.budget(), timestamp));
                    }
                }
                case MeDispatchBatchDecoder.TEMPLATE_ID -> {
                    if (tap == null) {
                        final MeDispatchBatchDecoder d = new MeDispatchBatchDecoder().wrapAndApplyHeader(b, offset, header);
                        for (final MeDispatchBatchDecoder.DispatchesDecoder e : d.dispatches()) {
                            rows.add(dispatch(e.dispatchSeq(), e.commandIdHigh(), e.commandIdLow(), e.kind().name(), e.userId(),
                                    e.omsOrderId(), e.oldOrderId(), e.marketId(), e.price(), e.quantity(), e.budget(), timestamp));
                        }
                    }
                }
                case PendingDispatchEndDecoder.TEMPLATE_ID -> {
                    final PendingDispatchEndDecoder d = new PendingDispatchEndDecoder().wrapAndApplyHeader(b, offset, header);
                    if (d.correlationId() != expectCorrelation) return;
                    pendingCount = d.count();
                    pendingHead = d.headDispatchSeq();
                    finish(t);
                }
                default -> {
                    if (done.test(t)) {
                        finished = true;
                    }
                }
            }
        }

        /** Story mode: replies by correlation id and every order event go to the story; true when consumed. */
        private boolean storyRow(final int t, final DirectBuffer b, final int offset) {
            switch (t) {
                case OrderAckDecoder.TEMPLATE_ID -> {
                    final OrderAckDecoder d = new OrderAckDecoder().wrapAndApplyHeader(b, offset, header);
                    story.onAck(d.correlationId(), d.orderId(), d.duplicate() == BoolFlag.TRUE, d.holdAssetId(), d.holdAmount(),
                            d.status().name());
                    return true;
                }
                case OrderRejectDecoder.TEMPLATE_ID -> {
                    final OrderRejectDecoder d = new OrderRejectDecoder().wrapAndApplyHeader(b, offset, header);
                    story.onReject(d.correlationId(), d.reason().name(), d.meReason(), d.detail(), d.orderId());
                    return true;
                }
                case OrderEventDecoder.TEMPLATE_ID -> {
                    final OrderEventDecoder d = new OrderEventDecoder().wrapAndApplyHeader(b, offset, header);
                    story.onEvent(d.orderId(), d.eventKind().name(), d.status().name(), d.filledQty());
                    return true;
                }
                case OrderEventBatchDecoder.TEMPLATE_ID -> {
                    final OrderEventBatchDecoder d = new OrderEventBatchDecoder().wrapAndApplyHeader(b, offset, header);
                    for (final OrderEventBatchDecoder.EventsDecoder e : d.events()) {
                        story.onEvent(e.orderId(), e.eventKind().name(), e.status().name(), e.filledQty());
                    }
                    return true;
                }
                default -> {
                    return false;
                }
            }
        }

        private void balance(final long user, final int asset, final long available, final long locked) {
            balances.put(user + ":" + asset, "{\"user\":" + user + ",\"asset\":" + asset + ",\"available\":" + available
                    + ",\"locked\":" + locked + "}");
        }

        private void hold(final long order, final long user, final int asset, final long remaining) {
            holds.put(order, "{\"order\":" + order + ",\"user\":" + user + ",\"asset\":" + asset + ",\"remaining\":" + remaining + "}");
        }

        private String dispatch(final long seq, final long high, final long low, final String kind, final long user,
                                final long order, final long oldLeg, final int market, final long price, final long qty,
                                final long budget, final long at) {
            return "{\"seq\":" + seq + ",\"id_high\":" + high + ",\"id_low\":" + low + ",\"kind\":" + q(kind) + ",\"order\":"
                    + order + ",\"user\":" + user + ",\"old_leg\":" + oldLeg + ",\"market\":" + market + ",\"price\":" + price
                    + ",\"quantity\":" + qty + ",\"budget\":" + budget + ",\"at_ms\":" + at + "}";
        }

        void tapRow(final int t, final long timestamp, final DirectBuffer b, final int offset) {
            String row = null;
            if (t == MeDispatchDecoder.TEMPLATE_ID) {
                final MeDispatchDecoder d = new MeDispatchDecoder().wrapAndApplyHeader(b, offset, header);
                continuity.dispatch.add(d.dispatchSeq());
                row = "{\"tap\":\"dispatch\",\"row\":" + dispatch(d.dispatchSeq(), d.commandIdHigh(), d.commandIdLow(), d.kind().name(),
                        d.userId(), d.omsOrderId(), d.oldOrderId(), d.marketId(), d.price(), d.quantity(), d.budget(), timestamp) + "}";
            } else if (t == MeDispatchBatchDecoder.TEMPLATE_ID) {
                final MeDispatchBatchDecoder d = new MeDispatchBatchDecoder().wrapAndApplyHeader(b, offset, header);
                final StringBuilder sb = new StringBuilder();
                for (final MeDispatchBatchDecoder.DispatchesDecoder e : d.dispatches()) {
                    continuity.dispatch.add(e.dispatchSeq());
                    sb.append(sb.length() == 0 ? "" : "\n").append("{\"tap\":\"dispatch\",\"row\":").append(dispatch(e.dispatchSeq(),
                            e.commandIdHigh(), e.commandIdLow(), e.kind().name(), e.userId(), e.omsOrderId(), e.oldOrderId(),
                            e.marketId(), e.price(), e.quantity(), e.budget(), timestamp)).append('}');
                }
                row = sb.length() == 0 ? null : sb.toString();
            } else if (t == OrderEventDecoder.TEMPLATE_ID) {
                final OrderEventDecoder d = new OrderEventDecoder().wrapAndApplyHeader(b, offset, header);
                continuity.events.add(d.eventSeq());
                row = event(d.eventSeq(), d.orderId(), d.eventKind().name(), d.status().name(), d.reason().name(), d.filledQty(),
                        d.quantity(), d.remainingQty(), d.tradeId(), d.meOrderId(), d.holdAmount(), d.holdRemaining(), d.logPosition());
            } else if (t == OrderEventBatchDecoder.TEMPLATE_ID) {
                final OrderEventBatchDecoder d = new OrderEventBatchDecoder().wrapAndApplyHeader(b, offset, header);
                final StringBuilder sb = new StringBuilder();
                for (final OrderEventBatchDecoder.EventsDecoder e : d.events()) {
                    continuity.events.add(e.eventSeq());
                    sb.append(sb.length() == 0 ? "" : "\n").append(event(e.eventSeq(), e.orderId(), e.eventKind().name(),
                            e.status().name(), e.reason().name(), e.filledQty(), e.quantity(), e.remainingQty(), e.tradeId(),
                            e.meOrderId(), e.holdAmount(), e.holdRemaining(), e.logPosition()));
                }
                row = sb.length() == 0 ? null : sb.toString();
            } else if (t == AdmissionStateDecoder.TEMPLATE_ID) {
                final AdmissionStateDecoder d = new AdmissionStateDecoder().wrapAndApplyHeader(b, offset, header);
                row = "{\"tap\":\"admission\",\"row\":{\"market\":" + d.marketId() + ",\"state\":" + q(d.gateState().name())
                        + ",\"reason\":" + q(d.gateReason().name()) + ",\"breaker\":" + (d.circuitBreaker() == BoolFlag.TRUE)
                        + ",\"log_position\":" + d.logPosition() + ",\"at_ms\":" + d.atMs() + "}}";
            } else if (t == OrderFaultDecoder.TEMPLATE_ID) {
                final OrderFaultDecoder d = new OrderFaultDecoder().wrapAndApplyHeader(b, offset, header);
                row = "{\"tap\":\"order_fault\",\"row\":{\"kind\":" + q(d.kind().name()) + ",\"order\":" + d.orderId()
                        + ",\"trade\":" + d.tradeId() + ",\"amount\":" + d.amount() + "}}";
            }
            if (row != null) {
                tap.println(row);
                tapped++;
            }
        }

        private String event(final long seq, final long order, final String kind, final String status, final String reason,
                             final long filled, final long qty, final long remaining, final long trade, final long leg,
                             final long holdAmount, final long holdRemaining, final long logPosition) {
            return "{\"tap\":\"order_event\",\"row\":{\"seq\":" + seq + ",\"order\":" + order + ",\"kind\":" + q(kind)
                    + ",\"status\":" + q(status) + ",\"reason\":" + q(reason) + ",\"filled\":" + filled + ",\"quantity\":" + qty
                    + ",\"remaining\":" + remaining + ",\"trade\":" + trade + ",\"leg\":" + leg + ",\"hold_amount\":" + holdAmount
                    + ",\"hold_remaining\":" + holdRemaining + ",\"log_position\":" + logPosition + "}}";
        }
    }
}
