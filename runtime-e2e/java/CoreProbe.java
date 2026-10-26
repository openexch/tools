// SPDX-License-Identifier: Apache-2.0
import com.openexchange.assets.auth.CoreCredentials;
import com.openexchange.assets.domain.Asset;
import com.openexchange.assets.domain.Market;
import com.openexchange.assets.infrastructure.generated.*;
import io.aeron.cluster.client.AeronCluster;
import io.aeron.cluster.client.EgressListener;
import io.aeron.driver.MediaDriver;
import io.aeron.driver.ThreadingMode;
import io.aeron.logbuffer.Header;
import org.agrona.CloseHelper;
import org.agrona.DirectBuffer;
import org.agrona.concurrent.BackoffIdleStrategy;
import org.agrona.concurrent.UnsafeBuffer;

import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ThreadLocalRandom;
import java.util.function.Predicate;

/**
 * RC2 S14 core probe: the fixture's only client of the OMS + ledger core (money-schema v6, RC1 a9a865d).
 * Compiled separately against the frozen AE jar and run with it on the class path; never linked into a
 * product artifact. One verb per process, one authenticated session, one JSON line on stdout.
 *
 * <p>Environment (all required, no defaults): CORE_AE_ADDRESSES (comma list, member order),
 * CORE_AE_PORT_BASE, CLUSTER_PORT_STRIDE, CORE_LOCAL_HOST, AE_AUTH_CREDENTIAL (keyId:CLASS:secretHex).
 * The credential's class must be one the verb allows; the core checks it again.</p>
 *
 * <p>Exit codes: 0 answered; 3 no answer before the deadline (outcome UNKNOWN); 4 the core refused
 * (the JSON says why); 5 a negative control was NOT refused; 64 usage.</p>
 */
public final class CoreProbe {
    private static final long DEADLINE_MS = 30_000;
    private static final int HEADER = MessageHeaderEncoder.ENCODED_LENGTH;

    private final Map<String, String> args = new HashMap<>();
    private final UnsafeBuffer buffer = new UnsafeBuffer(new byte[16 * 1024]);
    private final MessageHeaderEncoder headerEncoder = new MessageHeaderEncoder();
    private final MessageHeaderDecoder header = new MessageHeaderDecoder();
    private final List<String> rows = new ArrayList<>();
    private Predicate<Integer> done = t -> false;
    private Listener listener;
    private AeronCluster cluster;
    private MediaDriver driver;
    private long keepAliveAt;

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

    private static String q(final String s) {
        return "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
    }

    private int run(final String[] argv) {
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
            args.put(argv[i].substring(0, eq), argv[i].substring(eq + 1));
        }
        final String verb = argv[0];
        try {
            if (verb.equals("unauth")) {
                return unauthenticated();
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
            case "create", "cancel", "amend" -> c == SessionClass.GATEWAY;
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

    private void connect(final io.aeron.security.CredentialsSupplier supplier) {
        driver = MediaDriver.launch(new MediaDriver.Context()
                .aeronDirectoryName("/dev/shm/core-probe-" + ProcessHandle.current().pid())
                .threadingMode(ThreadingMode.SHARED).dirDeleteOnStart(true).dirDeleteOnShutdown(true)
                .errorHandler(t -> t.printStackTrace(System.err)));
        listener = new Listener();
        cluster = AeronCluster.connect(new AeronCluster.Context()
                .credentialsSupplier(supplier)
                .messageTimeoutNs(java.util.concurrent.TimeUnit.SECONDS.toNanos(8))
                .aeronDirectoryName(driver.aeronDirectoryName())
                .ingressChannel("aeron:udp?term-length=4m|mtu=8192")
                .ingressEndpoints(endpoints())
                .egressChannel("aeron:udp?endpoint=" + env("CORE_LOCAL_HOST") + ":0|term-length=4m")
                .egressListener(listener)
                .errorHandler(t -> t.printStackTrace(System.err)));
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
        do {
            listener.reset();
            offer(HEADER + new RequestOrderSnapshotEncoder().wrapAndApplyHeader(buffer, 0, headerEncoder)
                    .correlationId(listener.expectCorrelation = corr()).userId(0).fromOrderId(from).encodedLength());
            await(t -> t == OrderSnapshotEndDecoder.TEMPLATE_ID || t == OrderRejectDecoder.TEMPLATE_ID);
            if (listener.refused) {
                return print("order-dump");
            }
            from = listener.nextOrderId;
            pages++;
        } while (from != 0);
        System.out.println("{\"verb\":\"order-dump\",\"pages\":" + pages + ",\"orders\":[" + String.join(",", rows) + "]}");
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
        final StringBuilder sb = new StringBuilder("{\"verb\":\"money-dump\",\"balances\":[");
        sb.append(String.join(",", listener.balances.values())).append("],\"holds\":[");
        sb.append(String.join(",", listener.holds.values())).append("],\"consumePosition\":").append(listener.consumePosition)
                .append(",\"lastAppliedTradeId\":").append(listener.lastAppliedTradeId)
                .append(",\"journalEnabled\":").append(listener.journalEnabled).append('}');
        System.out.println(sb);
        return 0;
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

    private int tap() throws RuntimeException {
        final long until = System.currentTimeMillis() + num("duration_ms");
        try (PrintWriter out = new PrintWriter(new FileWriter(arg("out"), true))) {
            listener.tap = out;
            register(corr(), SessionClass.TOOL, true, true);
            final BackoffIdleStrategy idle = new BackoffIdleStrategy();
            while (System.currentTimeMillis() < until && !Thread.currentThread().isInterrupted()) {
                idle.idle(service());
                out.flush();
            }
        } catch (final java.io.IOException e) {
            throw new IllegalStateException("tap output: " + e.getMessage());
        }
        System.out.println("{\"verb\":\"tap\",\"rows\":" + listener.tapped + "}");
        return 0;
    }

    // ------------------------------------------------------------------ egress

    private final class Listener implements EgressListener {
        long expectCorrelation;
        boolean finished;
        boolean refused;
        String lastAdminResult = "";
        long nextOrderId;
        long balanceCorr, holdCorr;
        boolean balancesEnd, holdsEnd, positionSeen, journalEnabled;
        long consumePosition, lastAppliedTradeId;
        int pendingCount;
        long pendingHead;
        PrintWriter tap;
        long tapped;
        final Map<String, String> balances = new java.util.LinkedHashMap<>();
        final Map<Long, String> holds = new java.util.LinkedHashMap<>();

        void reset() {
            finished = false;
            refused = false;
            lastAdminResult = "";
            rows.clear();
        }

        private void finish(final int template) {
            if (done.test(template)) {
                finished = true;
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
                    positionSeen = true;
                    rows.add("{\"t\":\"FeedPositionReport\",\"consumePosition\":" + consumePosition + ",\"lastAppliedTradeId\":"
                            + lastAppliedTradeId + ",\"journalEnabled\":" + journalEnabled + "}");
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

        private void tapRow(final int t, final long timestamp, final DirectBuffer b, final int offset) {
            String row = null;
            if (t == MeDispatchDecoder.TEMPLATE_ID) {
                final MeDispatchDecoder d = new MeDispatchDecoder().wrapAndApplyHeader(b, offset, header);
                row = "{\"tap\":\"dispatch\",\"row\":" + dispatch(d.dispatchSeq(), d.commandIdHigh(), d.commandIdLow(), d.kind().name(),
                        d.userId(), d.omsOrderId(), d.oldOrderId(), d.marketId(), d.price(), d.quantity(), d.budget(), timestamp) + "}";
            } else if (t == MeDispatchBatchDecoder.TEMPLATE_ID) {
                final MeDispatchBatchDecoder d = new MeDispatchBatchDecoder().wrapAndApplyHeader(b, offset, header);
                final StringBuilder sb = new StringBuilder();
                for (final MeDispatchBatchDecoder.DispatchesDecoder e : d.dispatches()) {
                    sb.append(sb.length() == 0 ? "" : "\n").append("{\"tap\":\"dispatch\",\"row\":").append(dispatch(e.dispatchSeq(),
                            e.commandIdHigh(), e.commandIdLow(), e.kind().name(), e.userId(), e.omsOrderId(), e.oldOrderId(),
                            e.marketId(), e.price(), e.quantity(), e.budget(), timestamp)).append('}');
                }
                row = sb.length() == 0 ? null : sb.toString();
            } else if (t == OrderEventDecoder.TEMPLATE_ID) {
                final OrderEventDecoder d = new OrderEventDecoder().wrapAndApplyHeader(b, offset, header);
                row = event(d.eventSeq(), d.orderId(), d.eventKind().name(), d.status().name(), d.reason().name(), d.filledQty(),
                        d.quantity(), d.remainingQty(), d.tradeId(), d.meOrderId(), d.holdAmount(), d.holdRemaining(), d.logPosition());
            } else if (t == OrderEventBatchDecoder.TEMPLATE_ID) {
                final OrderEventBatchDecoder d = new OrderEventBatchDecoder().wrapAndApplyHeader(b, offset, header);
                final StringBuilder sb = new StringBuilder();
                for (final OrderEventBatchDecoder.EventsDecoder e : d.events()) {
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
