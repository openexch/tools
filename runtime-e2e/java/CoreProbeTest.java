// SPDX-License-Identifier: Apache-2.0
import com.openexchange.assets.infrastructure.generated.*;
import org.agrona.concurrent.UnsafeBuffer;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.PriorityQueue;
import java.util.Set;
import java.util.function.Function;

/**
 * Unit tests of {@code CoreProbe story} and {@code CoreProbe tap}: no cluster, a
 * reply stub and a fake clock. Compiled with CoreProbe.java against the AE jar (the same class path the probe
 * runs with) and driven by {@code test_story.py}. Prints {@code PASS <name>} or {@code FAIL <name>: why} per case,
 * exit 0 only when every case passed. Argument: a directory the sample logs are written to (the Python side
 * checks their key sets against the oracle model).
 */
public final class CoreProbeTest {
    private static final List<String> failures = new ArrayList<>();
    private static Path outDir;

    public static void main(final String[] argv) throws Exception {
        outDir = Path.of(argv[0]);
        Files.createDirectories(outDir);
        run("a01_request_log_is_a_function_of_the_seed", CoreProbeTest::a01Deterministic);
        run("a02_request_log_is_a_function_of_the_seed", CoreProbeTest::a02Deterministic);
        run("a01_open_loop_never_waits_for_a_reply", CoreProbeTest::openLoop);
        run("a01_cancels_target_live_own_orders", CoreProbeTest::cancelsTargetOwnLive);
        run("markers_are_written_once_per_moment", CoreProbeTest::markersOnce);
        run("without_iceberg_removes_the_moment", CoreProbeTest::withoutIceberg);
        run("unknown_replies_are_resolved_by_resend_with_the_same_request_id", CoreProbeTest::resolution);
        run("unanswered_resend_leaves_the_row_unresolved", CoreProbeTest::unresolved);
        run("unoffered_rows_are_unsent_not_unknown", CoreProbeTest::unsent);
        run("hold_waits_for_the_gate_file", CoreProbeTest::holdReleased);
        run("hold_without_gate_file_expires_loudly", CoreProbeTest::holdExpired);
        run("story_refuses_ambiguous_arguments", CoreProbeTest::refusals);
        run("funding_plan_covers_every_user_and_asset", CoreProbeTest::fundingPlan);
        run("a03_fill_runs_the_three_phases_with_markers", CoreProbeTest::a03Phases);
        run("a03_open_timeout_starts_phase_three_with_opened_false", CoreProbeTest::a03Timeout);
        run("a03_summary_counts_gate_rejects_and_reopen_acks", CoreProbeTest::a03Summary);
        run("a03_request_log_is_a_function_of_the_seed", CoreProbeTest::a03Deterministic);
        run("a03_refuses_ambiguous_arguments", CoreProbeTest::a03Refusals);
        run("a01_ioc_burst_follows_the_marker_for_two_seconds", CoreProbeTest::iocBurst);
        run("a01_ioc_burst_rearms_when_the_marker_is_deleted", CoreProbeTest::iocBurstRearm);
        run("a01_takes_120_users_and_funding_covers_them", CoreProbeTest::users120);
        run("money_dump_exports_the_v7_halt_fields", CoreProbeTest::moneyDumpV7);
        run("listener_routes_story_replies_by_correlation", CoreProbeTest::listenerRoutes);
        run("tap_reports_dispatch_gaps_and_new_leader", CoreProbeTest::tapGaps);
        run("tap_dense_run_reports_no_gap", CoreProbeTest::tapDense);
        run("order_dump_keeps_every_page", CoreProbeTest::orderDumpPages);
        System.out.println(failures.isEmpty() ? "ALL PASS" : "FAILED " + failures);
        System.exit(failures.isEmpty() ? 0 : 1);
    }

    interface Case {
        void run() throws Exception;
    }

    private static void run(final String name, final Case c) {
        try {
            c.run();
            System.out.println("PASS " + name);
        } catch (final Throwable t) {
            failures.add(name);
            System.out.println("FAIL " + name + ": " + t);
        }
    }

    private static void check(final boolean ok, final String what) {
        if (!ok) {
            throw new AssertionError(what);
        }
    }

    // ------------------------------------------------------------------ fakes

    /** Epoch-ns clock that advances 1 ms per idle; gate files appear at a given time. */
    static final class FakeClock implements CoreProbe.StoryClock {
        long now = 1_793_000_000_000_000_000L;
        final Map<String, Long> filesAt = new HashMap<>();

        public long nowNs() {
            return now;
        }

        public void idle(final int work) {
            now += 1_000_000L;
        }

        /** A file present in [from, to) spans (a deleted and re-created marker). */
        final Map<String, long[]> fileSpans = new HashMap<>();

        public boolean exists(final String path) {
            final long[] spans = fileSpans.get(path);
            if (spans != null) {
                for (int i = 0; i + 1 < spans.length; i += 2) {
                    if (now >= spans[i] && now < spans[i + 1]) {
                        return true;
                    }
                }
                return false;
            }
            final Long at = filesAt.get(path);
            return at != null && now >= at;
        }
    }

    /** The reply stub: a policy per offered row; replies and events arrive 5 ms later on poll. */
    static final class StubPort implements CoreProbe.StoryPort {
        enum Mode { ACK_ALL, SILENT, DROP_FIRST, REFUSE_OFFER }

        final FakeClock clock;
        final Mode mode;
        CoreProbe.StorySink sink;
        final Set<Integer> dropCreateIndex = new HashSet<>();   // n-th create (1-based) whose FIRST reply is lost
        final Set<Integer> commitOnDrop = new HashSet<>();      // ... and the core committed it anyway
        final Set<Integer> silentOnResend = new HashSet<>();
        final Map<String, Long> committed = new HashMap<>();
        final Map<String, Integer> sends = new HashMap<>();
        final Map<String, Integer> createIndex = new HashMap<>();
        final List<CoreProbe.StoryRow> offered = new ArrayList<>();
        final PriorityQueue<long[]> due = new PriorityQueue<>((a, b) -> Long.compare(a[0], b[0]));
        final List<Runnable> actions = new ArrayList<>();
        long nextOrder = 1000;
        int creates;
        /** creates offered inside [gateFrom, gateTo) (epoch ns) are rejected GATE_CLOSED, as the core does while the gate is shut. */
        long gateFrom = Long.MAX_VALUE;
        long gateTo = Long.MAX_VALUE;

        StubPort(final FakeClock clock, final Mode mode) {
            this.clock = clock;
            this.mode = mode;
        }

        private void later(final Runnable r) {
            actions.add(r);
            due.add(new long[] {clock.now + 5_000_000L, actions.size() - 1});
        }

        public boolean offer(final CoreProbe.StoryRow row, final long correlationId) {
            if (mode == Mode.REFUSE_OFFER) {
                return false;
            }
            offered.add(row);
            final String key = row.rh + ":" + row.rl;
            final int n = sends.merge(key, 1, Integer::sum);
            if (row.list.equals("creates") && n == 1) {
                createIndex.put(key, ++creates);
            }
            if (mode == Mode.SILENT) {
                return true;
            }
            final int index = createIndex.getOrDefault(key, 0);
            if (mode == Mode.DROP_FIRST && row.list.equals("creates")) {
                if (n == 1 && dropCreateIndex.contains(index)) {
                    if (commitOnDrop.contains(index)) {
                        committed.put(key, nextOrder++);
                    }
                    return true;
                }
                if (n > 1 && silentOnResend.contains(index)) {
                    return true;
                }
            }
            later(() -> reply(row, correlationId, key));
            return true;
        }

        private void reply(final CoreProbe.StoryRow row, final long correlationId, final String key) {
            switch (row.list) {
                case "creates" -> {
                    if (row.sentNs >= gateFrom && row.sentNs < gateTo) {
                        sink.onReject(correlationId, "GATE_CLOSED", 0, 0, 0);
                        return;
                    }
                    final boolean duplicate = committed.containsKey(key);
                    final long order = committed.computeIfAbsent(key, k -> nextOrder++);
                    final String status = row.tif.equals("GTC") || row.tif.equals("GTD") ? "NEW" : "EXPIRED";
                    sink.onAck(correlationId, order, duplicate, row.side.equals("BUY") ? 0 : 1, row.quantity, status);
                    sink.onEvent(order, "ACK_NEW", status, 0);
                }
                case "amends" -> {
                    sink.onAck(correlationId, row.order, false, 0, 0, "PENDING_REPLACE");
                    sink.onEvent(row.order, "REPLACED", "NEW", 0);
                }
                default -> {
                    sink.onAck(correlationId, row.order, false, 0, 0, "PENDING_CANCEL");
                    sink.onEvent(row.order, "CANCELLED", "CANCELLED", 0);
                }
            }
        }

        public int poll() {
            int work = 0;
            while (!due.isEmpty() && due.peek()[0] <= clock.now) {
                actions.get((int) due.poll()[1]).run();
                work++;
            }
            return work;
        }
    }

    static final class Result {
        CoreProbe.Story story;
        CoreProbe.Story.Summary summary;
        String log;
        final List<Map<String, Object>> markers = new ArrayList<>();
        StubPort port;
        FakeClock clock;
    }

    private static CoreProbe.StoryConfig cfg(final String... kv) {
        final Map<String, String> a = new HashMap<>();
        a.put("out", "/unused/out.jsonl");
        a.put("markers", "/unused/markers.jsonl");
        for (final String s : kv) {
            final int eq = s.indexOf('=');
            a.put(s.substring(0, eq), s.substring(eq + 1));
        }
        return CoreProbe.StoryConfig.parse(a);
    }

    private static Result story(final CoreProbe.StoryConfig c, final StubPort.Mode mode, final Function<StubPort, StubPort> setup,
                                final FakeClock clock) {
        final Result r = new Result();
        r.clock = clock == null ? new FakeClock() : clock;
        r.port = setup.apply(new StubPort(r.clock, mode));
        r.story = new CoreProbe.Story(c, r.clock, r.port, r.markers::add);
        r.port.sink = r.story;
        r.summary = r.story.run();
        r.log = r.story.requestLog();
        return r;
    }

    private static Result story(final CoreProbe.StoryConfig c, final StubPort.Mode mode) {
        return story(c, mode, p -> p, null);
    }

    private static List<CoreProbe.StoryRow> list(final Result r, final String list) {
        final List<CoreProbe.StoryRow> out = new ArrayList<>();
        for (final CoreProbe.StoryRow row : r.story.rows) {
            if (row.list.equals(list)) {
                out.add(row);
            }
        }
        return out;
    }

    private static int markerCount(final Result r, final String name, final Object index) {
        int n = 0;
        for (final Map<String, Object> m : r.markers) {
            if (name.equals(m.get("marker")) && (index == null || index.equals(m.get("index")))) {
                n++;
            }
        }
        return n;
    }

    // ------------------------------------------------------------------ story cases

    private static void a01Deterministic() throws Exception {
        final CoreProbe.StoryConfig c = cfg("script=a01-mix", "seed=7", "seconds=3", "rate=20", "users=1,2,3,4");
        final Result one = story(c, StubPort.Mode.ACK_ALL);
        final Result two = story(c, StubPort.Mode.ACK_ALL);
        check(one.log.equals(two.log), "two runs with seed 7 wrote different request logs");
        check(list(one, "creates").size() == 60, "a01 3 s at 20/s planned " + list(one, "creates").size() + " creates, not 60");
        check(!list(one, "cancels").isEmpty(), "a01 sent no cancel");
        final Result other = story(cfg("script=a01-mix", "seed=8", "seconds=3", "rate=20", "users=1,2,3,4"), StubPort.Mode.ACK_ALL);
        check(!one.log.equals(other.log), "seed 8 wrote the same request log as seed 7");
        int ioc = 0;
        for (final CoreProbe.StoryRow row : list(one, "creates")) {
            check(row.market == 1 && row.type.equals("LIMIT"), "a01 create is not a LIMIT on market 1: " + row.toJson());
            check(row.side.equals(row.user % 2 == 1 ? "BUY" : "SELL"), "a01 side does not follow the user position: " + row.toJson());
            ioc += row.tif.equals("IOC") ? 1 : 0;
        }
        check(ioc > 0, "a01 carried no IOC create");
        Files.writeString(outDir.resolve("a01-mix.jsonl"), one.log, StandardCharsets.UTF_8);
    }

    private static void a02Deterministic() throws Exception {
        final CoreProbe.StoryConfig c = cfg("script=a02-lifecycle", "seed=7", "seconds=2", "rate=20", "users=1,2");
        final Result one = story(c, StubPort.Mode.ACK_ALL);
        final Result two = story(c, StubPort.Mode.ACK_ALL);
        check(one.log.equals(two.log), "two a02 runs with seed 7 wrote different request logs");
        final Result other = story(cfg("script=a02-lifecycle", "seed=9", "seconds=2", "rate=20", "users=1,2"), StubPort.Mode.ACK_ALL);
        check(!one.log.equals(other.log), "seed 9 wrote the same a02 request log as seed 7");
        final Set<String> kinds = new HashSet<>();
        final Set<Integer> markets = new HashSet<>();
        for (final CoreProbe.StoryRow row : list(one, "creates")) {
            kinds.add(row.type + "/" + row.tif);
            markets.add(row.market);
            if (row.type.equals("STOP_LOSS")) {
                check(row.budget > 0 && row.stopPrice > 0 && row.price == 0, "stop-buy without an explicit budget: " + row.toJson());
            }
            if (row.type.equals("ICEBERG")) {
                check(row.displayQty > 0 && row.displayQty < row.quantity, "iceberg without a display slice: " + row.toJson());
            }
            if (row.tif.equals("GTD")) {
                check(row.expires == row.scheduledNs / 1_000_000L + 5_000, "GTD expires is not 5 s after the send: " + row.toJson());
            }
            check(row.price == 0 || (row.price >= 1_000_000L && row.price <= 10_000_000_000L && row.price % 1_000_000L == 0),
                    "price outside the ME band or off tick: " + row.toJson());
        }
        for (final String k : List.of("ICEBERG/GTC", "LIMIT/GTC", "LIMIT_MAKER/GTC", "STOP_LOSS/GTC", "LIMIT/IOC", "LIMIT/FOK", "LIMIT/GTD")) {
            check(kinds.contains(k), "a02 lacks a " + k + " create (has " + kinds + ")");
        }
        check(markets.containsAll(Set.of(1, 2, 3, 4, 5)), "a02 does not trade markets 1..5: " + markets);
        check(list(one, "amends").size() == 3, "a02 sent " + list(one, "amends").size() + " amends, not 3 replace windows");
        Files.writeString(outDir.resolve("a02-lifecycle.jsonl"), one.log, StandardCharsets.UTF_8);
    }

    private static void openLoop() {
        final Result r = story(cfg("script=a01-mix", "seed=3", "seconds=3", "rate=20", "users=1,2,3,4"), StubPort.Mode.SILENT);
        final List<CoreProbe.StoryRow> creates = new ArrayList<>();
        for (final CoreProbe.StoryRow row : list(r, "creates")) {
            if (row.resolves == null) {
                creates.add(row);   // the resolution pass re-sends every UNKNOWN once: those rows are not the load
            }
        }
        check(creates.size() == 60, "a silent core stopped the story at " + creates.size() + " of 60 creates");
        check(r.summary.resent() == 60, "the resolution pass re-sent " + r.summary.resent() + " of 60 UNKNOWN creates");
        for (int i = 0; i < creates.size(); i++) {
            final CoreProbe.StoryRow row = creates.get(i);
            check(row.sentNs >= 0 && row.sentNs - row.scheduledNs < 2_000_000L, "create " + i + " was sent "
                    + (row.sentNs - row.scheduledNs) + " ns after its slot: the loop waited");
            check(row.scheduledNs - r.story.t0 == i * 50_000_000L, "create " + i + " slot is not i x 1/rate");
            check("UNKNOWN".equals(row.outcome()), "a silent core produced outcome " + row.outcome());
        }
        check(r.summary.unknown() == r.summary.sent() && r.summary.setupFailure(), "every reply lost is not a setup failure");
        check(r.summary.storyLine().equals("STORY sent=60 acked=0 unknown=60 rejected=0 resolved=0"), r.summary.storyLine());
        check(r.story.skippedCancels == 12, "cancels with no live order were not skipped: " + r.story.skippedCancels);
    }

    private static void cancelsTargetOwnLive() {
        final Result r = story(cfg("script=a01-mix", "seed=5", "seconds=4", "rate=20", "users=1,2,3,4"), StubPort.Mode.ACK_ALL);
        final Set<Long> cancelled = new HashSet<>();
        for (final CoreProbe.StoryRow row : list(r, "cancels")) {
            check(row.target != null && row.target.user == row.user, "cancel names an order the user does not own: " + row.toJson());
            check(row.target.tif.equals("GTC"), "cancel targets a non-resting create: " + row.toJson());
            check(cancelled.add(row.order), "order " + row.order + " cancelled twice");
        }
        check(!cancelled.isEmpty(), "no cancel was sent");
    }

    private static void markersOnce() {
        final Result r = story(cfg("script=a02-lifecycle", "seed=7", "seconds=2", "rate=20", "users=1,2"), StubPort.Mode.ACK_ALL);
        for (final String m : List.of("load_started", "load_ended", "drained", "moments_done", "slice1_exhausting_fill_sent",
                "stop_trigger_sent")) {
            check(markerCount(r, m, null) == 1, "marker " + m + " written " + markerCount(r, m, null) + " times");
        }
        for (int i = 1; i <= 3; i++) {
            check(markerCount(r, "replace_open", i) == 1, "replace_open " + i + " written " + markerCount(r, "replace_open", i) + " times");
        }
        for (final Map<String, Object> m : r.markers) {
            if ("replace_open".equals(m.get("marker"))) {
                check(((Long) m.get("order")) > 0, "replace_open without the order it opens: " + m);
            }
        }
    }

    private static void withoutIceberg() {
        final Result r = story(cfg("script=a02-lifecycle", "seed=7", "seconds=2", "rate=20", "users=1,2", "without=iceberg"),
                StubPort.Mode.ACK_ALL);
        for (final CoreProbe.StoryRow row : list(r, "creates")) {
            check(!row.type.equals("ICEBERG") && !"iceberg".equals(row.moment), "without=iceberg still sent " + row.toJson());
        }
        check(markerCount(r, "slice1_exhausting_fill_sent", null) == 0, "without=iceberg still wrote the slice marker");
        check(markerCount(r, "stop_trigger_sent", null) == 1, "without=iceberg dropped another moment");
    }

    private static void resolution() throws Exception {
        final Result r = story(cfg("script=a01-mix", "seed=11", "seconds=1", "rate=10", "users=1,2,3,4"), StubPort.Mode.DROP_FIRST, p -> {
            p.dropCreateIndex.addAll(Set.of(3, 4, 5));
            p.commitOnDrop.addAll(Set.of(3, 5));
            return p;
        }, null);
        final List<CoreProbe.StoryRow> creates = list(r, "creates");
        final Map<Integer, CoreProbe.StoryRow> byId = new HashMap<>();
        for (final CoreProbe.StoryRow row : creates) {
            byId.put(row.id, row);
        }
        int originals = 0;
        for (final CoreProbe.StoryRow row : creates) {
            if (row.resolves != null) {
                continue;
            }
            originals++;
            if ("UNKNOWN".equals(row.outcome())) {
                check(row.resolvedBy != null, "UNKNOWN create " + row.id + " not resolved");
                final CoreProbe.StoryRow res = byId.get(row.resolvedBy);
                check(res.rh == row.rh && res.rl == row.rl, "the re-send changed the requestId");
                check(res.resolves == row.id, "resolving row does not name the original");
                final boolean committed = r.port.commitOnDrop.contains(r.port.createIndex.get(row.rh + ":" + row.rl));
                check(Boolean.valueOf(committed).equals(res.reply.get("duplicate")), "row " + row.id + ": committed=" + committed
                        + " but the resolving ACK says duplicate=" + res.reply.get("duplicate"));
            }
        }
        check(originals == 10, "a01 1 s at 10/s planned " + originals + " creates");
        check(r.summary.unknown() == 3 && r.summary.resolved() == 3 && r.summary.resent() == 3, r.summary.json().toString());
        check(r.summary.storyLine().equals("STORY sent=" + r.summary.sent() + " acked=" + r.summary.acked()
                + " unknown=3 rejected=0 resolved=3"), r.summary.storyLine());
        check(markerCount(r, "resolution_started", null) == 1 && markerCount(r, "resolution_ended", null) == 1, "resolution markers");
        Files.writeString(outDir.resolve("a01-resolved.jsonl"), r.log, StandardCharsets.UTF_8);
    }

    private static void unresolved() {
        final Result r = story(cfg("script=a01-mix", "seed=11", "seconds=1", "rate=10", "users=1,2,3,4"), StubPort.Mode.DROP_FIRST, p -> {
            p.dropCreateIndex.add(2);
            p.silentOnResend.add(2);
            return p;
        }, null);
        check(r.summary.unknown() == 1 && r.summary.resolved() == 0, r.summary.json().toString());
        check(((Integer) r.summary.json().get("unresolved")) == 1, "unresolved count not reported");
        for (final CoreProbe.StoryRow row : list(r, "creates")) {
            if (row.resolves == null && "UNKNOWN".equals(row.outcome())) {
                check(row.resolvedBy == null, "an UNKNOWN re-send was recorded as a resolution");
            }
        }
    }

    private static void unsent() {
        final Result r = story(cfg("script=a01-mix", "seed=1", "seconds=1", "rate=10", "users=1,2"), StubPort.Mode.REFUSE_OFFER);
        check(r.summary.sent() == 0 && r.summary.unsent() == 10 && r.summary.setupFailure(), r.summary.json().toString());
        check(r.log.contains("\"story\":\"unsent\"") && !r.log.contains("\"story\":\"creates\""), "unsent rows were logged as creates");
        check(r.log.contains("\"outcome\":\"UNSENT\""), "unsent rows do not say UNSENT");
    }

    private static void holdReleased() {
        final FakeClock clock = new FakeClock();
        clock.filesAt.put("/g/replace_open-1.go", clock.now + 1_000_000_000_000L);   // 1,000 s: after the iceberg moment's awaits
        final Result r = story(cfg("script=a02-lifecycle", "seed=7", "seconds=0", "rate=20", "users=1,2", "hold=replace_open:1",
                "gate_dir=/g", "hold_ms=2000000"), StubPort.Mode.ACK_ALL, p -> p, clock);
        check(markerCount(r, "hold_ready", null) == 1 && markerCount(r, "hold_released", null) == 1, "hold markers " + r.markers);
        final CoreProbe.StoryRow amend = list(r, "amends").get(0);
        check(amend.sentNs >= clock.filesAt.get("/g/replace_open-1.go"), "the held amend was sent before the gate file existed");
        check(r.story.holdsExpired == 0, "a released hold counted as expired");
        long readyAt = -1;
        for (final Map<String, Object> m : r.markers) {
            if ("hold_ready".equals(m.get("marker"))) {
                readyAt = (Long) m.get("at_ns");
                check("/g/replace_open-1.go".equals(m.get("go")), "hold_ready does not name its gate file: " + m);
                // review F6: the marker names the held order (the amend's target), so the drill never guesses it
                check(m.get("order") != null && m.get("order").equals(amend.order), "hold_ready does not name the held order: " + m
                        + " amend order " + amend.order);
            }
        }
        check(readyAt > 0 && readyAt < amend.sentNs, "hold_ready was not written before the held send");
    }

    private static void holdExpired() {
        final Result r = story(cfg("script=a02-lifecycle", "seed=7", "seconds=0", "rate=20", "users=1,2", "hold=slice1_exhausting_fill",
                "gate_dir=/g", "hold_ms=1000"), StubPort.Mode.ACK_ALL);
        check(r.story.holdsExpired == 1 && markerCount(r, "hold_expired", null) == 1, "an unreleased hold did not expire loudly");
        check(((Integer) r.summary.json().get("holds_expired")) == 1, "holds_expired not in the summary");
        final CoreProbe.StoryRow parent = list(r, "creates").stream().filter(c -> "ICEBERG".equals(c.type)).findFirst().orElseThrow();
        check(list(r, "creates").stream().filter(c -> "ICEBERG".equals(c.type)).count() == 1, "a02 has one iceberg");
        for (final Map<String, Object> m : r.markers) {
            if ("hold_ready".equals(m.get("marker"))) {
                check(Long.valueOf(parent.ackedOrder()).equals(m.get("order")) && Integer.valueOf(parent.id).equals(m.get("row")),
                        "slice1 hold_ready does not name the iceberg parent: " + m + " parent " + parent.ackedOrder());
            }
        }
    }

    private static void refusal(final String expect, final Runnable r) {
        try {
            r.run();
        } catch (final IllegalArgumentException e) {
            check(e.getMessage().contains(expect), "refused with '" + e.getMessage() + "', expected '" + expect + "'");
            return;
        }
        throw new AssertionError("not refused (expected '" + expect + "')");
    }

    private static void refusals() {
        refusal("unknown story script", () -> cfg("script=a03-mix", "seed=1", "seconds=1", "rate=1", "users=1,2"));
        refusal("seed must be an integer", () -> cfg("script=a01-mix", "seed=x", "seconds=1", "rate=1", "users=1,2"));
        refusal("seed must be an integer", () -> cfg("script=a01-mix", "seed=-1", "seconds=1", "rate=1", "users=1,2"));
        refusal("seed must be an integer", () -> cfg("script=a01-mix", "seed=1.5", "seconds=1", "rate=1", "users=1,2"));
        refusal("does not take foo=", () -> cfg("script=a01-mix", "seed=1", "seconds=1", "rate=1", "users=1,2", "foo=1"));
        refusal("functional bound", () -> cfg("script=a01-mix", "seed=1", "seconds=1", "rate=170", "users=1,2"));
        refusal("above 50", () -> cfg("script=a02-lifecycle", "seed=1", "seconds=1", "rate=51", "users=1,2"));
        refusal("even number of users", () -> cfg("script=a01-mix", "seed=1", "seconds=1", "rate=1", "users=1,2,3"));
        refusal("distinct positive", () -> cfg("script=a01-mix", "seed=1", "seconds=1", "rate=1", "users=1,1"));
        refusal("unknown moment", () -> cfg("script=a02-lifecycle", "seed=1", "seconds=1", "rate=1", "users=1,2", "without=icebreg"));
        refusal("unknown hold", () -> cfg("script=a02-lifecycle", "seed=1", "seconds=1", "rate=1", "users=1,2", "hold=replace_open"));
        refusal("story needs gate_dir=", () -> cfg("script=a02-lifecycle", "seed=1", "seconds=1", "rate=1", "users=1,2",
                "hold=replace_open:2"));
        refusal("a02-lifecycle switches", () -> cfg("script=a01-mix", "seed=1", "seconds=1", "rate=1", "users=1,2", "without=gtd"));
        refusal("needs seconds > 0", () -> cfg("script=a01-mix", "seed=1", "seconds=0", "rate=1", "users=1,2"));
        refusal("rate must be > 0", () -> cfg("script=a01-mix", "seed=1", "seconds=1", "rate=0", "users=1,2"));
        refusal("PER_USER_CAP", () -> new CoreProbe.Story(cfg("script=a01-mix", "seed=1", "seconds=60", "rate=100",
                "users=1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20"), new FakeClock(), null, m -> { }));
        // 7,200 requests over 40 users is 180 each: the planned size is accepted
        final StringBuilder forty = new StringBuilder();
        for (int u = 1; u <= 40; u++) {
            forty.append(u == 1 ? "" : ",").append(u);
        }
        new CoreProbe.Story(cfg("script=a01-mix", "seed=1", "seconds=60", "rate=100", "users=" + forty), new FakeClock(), null, m -> { });
        final int code = new CoreProbe().run(new String[] {"story", "script=a01-mix", "seed=nope", "seconds=1", "rate=1",
                "users=1,2", "out=/x", "markers=/y"});
        check(code == 64, "the verb answered a bad seed with exit " + code + ", not 64 (usage)");
    }

    private static void fundingPlan() throws Exception {
        final CoreProbe.StoryConfig a01 = CoreProbe.StoryConfig.parse(Map.of("script", "funding", "seed", "3", "users", "5,6",
                "out", "/x", "for", "a01-mix"));
        final List<Map<String, Object>> a01Plan = CoreProbe.Story.fundingPlan(a01);
        check(a01Plan.size() == 4, "a01 funding plan has " + a01Plan.size() + " rows, not 2 users x (USD, BTC)");
        final Map<String, String> a = new HashMap<>(Map.of("script", "funding", "seed", "3", "users", "5,6",
                "out", outDir.resolve("funding.jsonl").toString(), "for", "a02-lifecycle"));
        final CoreProbe.StoryConfig c = CoreProbe.StoryConfig.parse(a);
        final List<Map<String, Object>> plan = CoreProbe.Story.fundingPlan(c);
        check(plan.size() == 12, "funding plan has " + plan.size() + " rows, not 2 users x 6 assets");
        final Set<String> seen = new HashSet<>();
        for (final Map<String, Object> row : plan) {
            final long[] req = (long[]) row.get("request");
            check(seen.add(req[0] + ":" + req[1]), "funding request id repeated");
            check(row.get("kind").equals("deposit") && ((Long) row.get("amount")) > 0, "funding row " + row);
        }
        final int code = new CoreProbe().run(new String[] {"story", "script=funding", "seed=3", "users=5,6",
                "out=" + outDir.resolve("funding.jsonl"), "for=a02-lifecycle"});
        check(code == 0, "story script=funding exited " + code);
        refusal("does not take rate=", () -> CoreProbe.StoryConfig.parse(Map.of("script", "funding", "seed", "3", "users", "5",
                "out", "/x", "rate", "1", "for", "a01-mix")));
        refusal("story needs for=", () -> CoreProbe.StoryConfig.parse(Map.of("script", "funding", "seed", "3", "users", "5",
                "out", "/x")));
        refusal("for= must be", () -> CoreProbe.StoryConfig.parse(Map.of("script", "funding", "seed", "3", "users", "5",
                "out", "/x", "for", "funding")));
    }

    // ------------------------------------------------------------------ listener / tap cases

    private static final UnsafeBuffer BUF = new UnsafeBuffer(new byte[8192]);
    private static final MessageHeaderEncoder HDR = new MessageHeaderEncoder();

    private static int dispatchFrame(final long seq) {
        return MessageHeaderEncoder.ENCODED_LENGTH + new MeDispatchEncoder().wrapAndApplyHeader(BUF, 0, HDR).dispatchSeq(seq)
                .commandIdHigh(1).commandIdLow(seq).kind(DispatchKind.CREATE).userId(1).omsOrderId(seq).oldOrderId(0).marketId(1)
                .orderType((short) 0).side((short) 0).price(1).quantity(1).budget(0).timeInForce((short) 0)
                .releaseScope(ReleaseScope.UP_TO).expectedOldRemaining(0).encodedLength();
    }

    private static int dispatchBatch(final long... seqs) {
        final MeDispatchBatchEncoder e = new MeDispatchBatchEncoder().wrapAndApplyHeader(BUF, 0, HDR);
        final MeDispatchBatchEncoder.DispatchesEncoder d = e.dispatchesCount(seqs.length);
        for (final long s : seqs) {
            d.next().dispatchSeq(s).commandIdHigh(1).commandIdLow(s).kind(DispatchKind.RELEASE_ID).userId(0).omsOrderId(0)
                    .oldOrderId(0).marketId(0).orderType((short) 0).side((short) 0).price(0).quantity(0).budget(0)
                    .timeInForce((short) 0).releaseScope(ReleaseScope.ORDER).expectedOldRemaining(0);
        }
        return MessageHeaderEncoder.ENCODED_LENGTH + e.encodedLength();
    }

    private static int eventFrame(final long seq, final long order, final EventKind kind, final OrderStatus status, final long filled) {
        return MessageHeaderEncoder.ENCODED_LENGTH + new OrderEventEncoder().wrapAndApplyHeader(BUF, 0, HDR).eventSeq(seq)
                .logPosition(0).orderId(order).userId(1).marketId(1).eventKind(kind).status(status).reason(CoreRejectReason.NONE)
                .side(Side.BUY).orderType(OrderType.LIMIT).timeInForce(TimeInForce.GTC).price(1).stopPrice(0).quantity(1)
                .filledQty(filled).remainingQty(0).lastPrice(0).lastQty(0).tradeId(0).meOrderId(0).holdAssetId(0).holdAmount(0)
                .holdRemaining(0).clientOrderIdHigh(0).clientOrderIdLow(0).createdAtMs(0).updatedAtMs(0).meReason((short) 255)
                .encodedLength();
    }

    private static CoreProbe tapProbe(final StringWriter rows, final List<Map<String, Object>> transitions) {
        final CoreProbe p = new CoreProbe();
        p.listener = p.new Listener();
        p.listener.tap = new PrintWriter(rows, true);
        p.continuity = new CoreProbe.Continuity(transitions::add);
        return p;
    }

    private static void tapGaps() {
        final StringWriter rows = new StringWriter();
        final List<Map<String, Object>> transitions = new ArrayList<>();
        final CoreProbe p = tapProbe(rows, transitions);
        for (final long s : new long[] {1, 2, 3}) {
            p.listener.onMessage(1, 10, BUF, 0, dispatchFrame(s), null);
        }
        p.listener.onMessage(1, 11, BUF, 0, dispatchBatch(6, 7), null);
        p.listener.onNewLeader(1, 4, 2, "0=a:1");
        p.listener.onMessage(1, 12, BUF, 0, dispatchFrame(8), null);
        p.listener.onMessage(1, 12, BUF, 0, dispatchFrame(2), null);      // a repeat is counted, kept once
        p.listener.onMessage(1, 13, BUF, 0, eventFrame(10, 5, EventKind.ACK_NEW, OrderStatus.NEW, 0), null);
        p.listener.onMessage(1, 13, BUF, 0, eventFrame(12, 5, EventKind.FILL, OrderStatus.FILLED, 1), null);
        final String line = p.continuity.dispatch.tapLine();
        check(line.equals("TAP first=1 last=8 rows=6 gaps=[[4,5]]"), "tap line " + line);
        check(p.continuity.dispatch.duplicates == 1, "duplicate dispatch not counted");
        check(p.listener.reregister, "a NewLeaderEvent did not ask for re-registration");
        check(transitions.size() == 1 && "new_leader".equals(transitions.get(0).get("event"))
                && Long.valueOf(7).equals(transitions.get(0).get("last_dispatch_seq"))
                && Integer.valueOf(2).equals(transitions.get(0).get("leader")), "new_leader transition " + transitions);
        check(p.continuity.events.gaps().size() == 1 && p.continuity.events.gaps().get(0)[0] == 11, "event seq gap not reported");
        check(rows.toString().lines().count() == 9 && p.listener.tapped == 8, "tap rows written: "
                + rows.toString().lines().count() + " lines, tapped " + p.listener.tapped);
        final Map<String, Object> summary = p.continuity.summary();
        check(CoreProbe.json(summary).contains("\"gaps\":[[4,5]]"), "summary JSON " + CoreProbe.json(summary));
        p.listener.onSessionEvent(0, 1, 4, 2, io.aeron.cluster.codecs.EventCode.CLOSED, "timeout");
        check(transitions.size() == 2 && "CLOSED".equals(transitions.get(1).get("code")), "session close not recorded");
    }

    private static void tapDense() {
        final CoreProbe p = tapProbe(new StringWriter(), new ArrayList<>());
        p.listener.onMessage(1, 10, BUF, 0, dispatchBatch(3, 4, 5), null);
        p.listener.onMessage(1, 10, BUF, 0, dispatchFrame(6), null);
        check(p.continuity.dispatch.tapLine().equals("TAP first=3 last=6 rows=4 gaps=[]"), p.continuity.dispatch.tapLine());
        check(new CoreProbe.SeqDensity().tapLine().equals("TAP first=0 last=0 rows=0 gaps=[]"), "empty tap line");
    }

    private static int snapshotBatch(final long... orders) {
        final OrderSnapshotBatchEncoder e = new OrderSnapshotBatchEncoder().wrapAndApplyHeader(BUF, 0, HDR);
        final OrderSnapshotBatchEncoder.OrdersEncoder o = e.ordersCount(orders.length);
        for (final long id : orders) {
            o.next().orderId(id).userId(1).marketId(1).status(OrderStatus.NEW).side(Side.BUY).orderType(OrderType.LIMIT)
                    .timeInForce(TimeInForce.GTC);
        }
        return MessageHeaderEncoder.ENCODED_LENGTH + e.encodedLength();
    }

    private static void orderDumpPages() {
        final CoreProbe p = new CoreProbe();
        p.listener = p.new Listener();
        p.listener.reset();
        p.listener.nextPage();
        p.listener.onMessage(1, 1, BUF, 0, snapshotBatch(1, 2), null);
        p.listener.nextPage();
        p.listener.onMessage(1, 1, BUF, 0, snapshotBatch(3), null);
        check(p.rows.size() == 3, "order-dump kept " + p.rows.size() + " of 3 orders over two pages");
        p.listener.reset();
        check(p.rows.isEmpty(), "reset() must still clear the rows of a new verb");
    }

    // ------------------------------------------------------------------ marker and funding cases

    private static final String SIG = "/sig";

    private static List<Map<String, Object>> markersNamed(final Result r, final String name) {
        final List<Map<String, Object>> out = new ArrayList<>();
        for (final Map<String, Object> m : r.markers) {
            if (name.equals(m.get("marker"))) {
                out.add(m);
            }
        }
        return out;
    }

    private static long markerAt(final Result r, final String name) {
        final List<Map<String, Object>> m = markersNamed(r, name);
        check(m.size() == 1, "marker " + name + " written " + m.size() + " times, expected once: " + r.markers);
        return (Long) m.get(0).get("at_ns");
    }

    private static void a03Phases() {
        final FakeClock clock = new FakeClock();
        final long t0 = clock.now;
        clock.filesAt.put(SIG + "/capacity_closed", t0 + 1_000_000_000L);
        clock.filesAt.put(SIG + "/capacity_open", t0 + 4_000_000_000L);
        final Result r = story(cfg("script=a03-fill", "seed=3", "rate=20", "fill_s=2", "reopen_s=1", "marker_timeout_s=10",
                "users=1,2,3,4", "signal_dir=" + SIG), StubPort.Mode.ACK_ALL, p -> p, clock);
        check(list(r, "cancels").isEmpty() && list(r, "amends").isEmpty(), "a03-fill sent a cancel or an amend (the A03 drain has no cancel wave)");
        int fill = 0;
        int reopen = 0;
        for (final CoreProbe.StoryRow c : list(r, "creates")) {
            check(c.market == 1 && c.type.equals("LIMIT") && c.tif.equals("GTC"), "a03 create is not a LIMIT GTC on market 1: " + c.toJson());
            check(c.side.equals(c.user % 2 == 1 ? "BUY" : "SELL"), "a03 side does not follow the user position: " + c.toJson());
            check(c.side.equals("BUY") ? c.price < 8500 * CoreProbe.Story.CENT : c.price >= 9500 * CoreProbe.Story.CENT,
                    "a03 create crosses the other side's band: " + c.toJson());
            if (c.moment.equals("fill")) {
                fill++;
                check(c.sentNs < t0 + 2_100_000_000L, "a fill create was sent after the fill window: " + c.toJson());
            } else if (c.moment.equals("reopen")) {
                reopen++;
                check(c.sentNs >= t0 + 4_000_000_000L, "a reopen create was sent before capacity_open: " + c.toJson());
            } else {
                throw new AssertionError("unknown a03 moment " + c.moment);
            }
        }
        check(fill == 40 && reopen == 20, "a03 planned fill " + fill + " reopen " + reopen + ", expected 40 and 20");
        check(markerAt(r, "capacity_closed_seen") >= t0 + 1_000_000_000L, "capacity_closed_seen before the file existed");
        final long ended = markerAt(r, "fill_ended");
        final long open = markerAt(r, "capacity_open_seen");
        final long started = markerAt(r, "reopen_started");
        check(ended <= open && open <= started, "marker order fill_ended " + ended + " capacity_open_seen " + open + " reopen_started " + started);
        check(markersNamed(r, "capacity_open_timeout").isEmpty(), "a seen capacity_open also wrote a timeout marker");
        check(Boolean.TRUE.equals(r.story.a03().get("closed")) && Boolean.TRUE.equals(r.story.a03().get("opened")),
                "a03 closed/opened " + r.story.a03());
    }

    private static void a03Timeout() {
        final FakeClock clock = new FakeClock();
        final Result r = story(cfg("script=a03-fill", "seed=3", "rate=20", "fill_s=2", "reopen_s=1", "marker_timeout_s=3",
                "users=1,2,3,4", "signal_dir=" + SIG), StubPort.Mode.ACK_ALL, p -> p, clock);
        final long ended = markerAt(r, "fill_ended");
        final long timeout = markerAt(r, "capacity_open_timeout");
        check(timeout - ended >= 3_000_000_000L && timeout - ended < 3_100_000_000L, "timeout after " + (timeout - ended) + " ns, expected 3 s");
        check(markersNamed(r, "capacity_open_seen").isEmpty(), "a timeout also wrote capacity_open_seen");
        check(markersNamed(r, "capacity_closed_seen").isEmpty(), "capacity_closed_seen without the file");
        check(list(r, "creates").stream().filter(c -> c.moment.equals("reopen")).count() == 20, "phase 3 did not run after the timeout");
        check(Boolean.FALSE.equals(r.story.a03().get("closed")) && Boolean.FALSE.equals(r.story.a03().get("opened")),
                "a03 closed/opened " + r.story.a03());
    }

    private static void a03Summary() {
        final FakeClock clock = new FakeClock();
        final long t0 = clock.now;
        clock.filesAt.put(SIG + "/capacity_open", t0 + 4_000_000_000L);
        final Result r = story(cfg("script=a03-fill", "seed=3", "rate=20", "fill_s=2", "reopen_s=1", "marker_timeout_s=10",
                "users=1,2,3,4", "signal_dir=" + SIG), StubPort.Mode.ACK_ALL, p -> {
            p.gateFrom = t0 + 1_000_000_000L;   // the gate shuts 1 s into the fill and stays shut until phase 3
            p.gateTo = t0 + 3_900_000_000L;
            return p;
        }, clock);
        final Map<String, Object> a = r.story.a03();
        final int gate = (Integer) a.get("rejected_gate");
        check(gate > 0 && gate < 40, "rejected_gate " + gate + " (expected the fill rows sent after the gate shut)");
        check((Integer) a.get("created") == 40 - gate, "created " + a.get("created") + " with " + gate + " gate rejects of 40");
        check((Integer) a.get("cancelled") == 0, "a03 reports cancelled " + a.get("cancelled"));
        check((Integer) a.get("reopen_acked") == 20, "reopen_acked " + a.get("reopen_acked") + ", expected 20");
        final String line = r.story.a03Line();
        check(line.equals("A03 created=" + (40 - gate) + " rejected_gate=" + gate + " cancelled=0 reopen_acked=20 closed=false opened=true"),
                "A03 line " + line);
        check(r.summary.json().get("a03") != null, "the JSON summary has no a03 block");
    }

    private static void a03Deterministic() throws Exception {
        final String[] kv = {"script=a03-fill", "seed=11", "rate=10", "fill_s=3", "reopen_s=2", "marker_timeout_s=1", "users=1,2,3,4,5,6",
                "signal_dir=" + SIG};
        final Result one = story(cfg(kv), StubPort.Mode.ACK_ALL);
        final Result two = story(cfg(kv), StubPort.Mode.ACK_ALL);
        check(one.log.equals(two.log), "two a03 runs with seed 11 wrote different request logs");
        final String[] other = kv.clone();
        other[1] = "seed=12";
        check(!one.log.equals(story(cfg(other), StubPort.Mode.ACK_ALL).log), "seed 12 wrote the same a03 log as seed 11");
        final Result a01 = story(cfg("script=a01-mix", "seed=11", "seconds=3", "rate=10", "users=1,2,3,4,5,6"), StubPort.Mode.ACK_ALL);
        check(one.story.requestHigh != a01.story.requestHigh, "a03 and a01 share a request id space");
        Files.writeString(outDir.resolve("a03-fill.jsonl"), one.log, StandardCharsets.UTF_8);
    }

    private static void a03Refusals() {
        final String[] base = {"script=a03-fill", "seed=1", "users=1,2", "signal_dir=" + SIG};
        refusal("signal_dir", () -> cfg("script=a03-fill", "seed=1", "users=1,2"));
        refusal("does not take seconds=", () -> cfg(concat(base, "seconds=5")));
        refusal("does not take without=", () -> cfg(concat(base, "without=gtd")));
        refusal("above the functional bound", () -> cfg(concat(base, "rate=201")));
        refusal("marker_timeout_s", () -> cfg(concat(base, "marker_timeout_s=0")));
        refusal("fill_s", () -> cfg(concat(base, "fill_s=0")));
        refusal("fill_s", () -> cfg(concat(base, "fill_s=x")));
        refusal("at least two users", () -> cfg("script=a03-fill", "seed=1", "users=1", "signal_dir=" + SIG));
        refusal("pass more users", () -> {   // 4000 creates / 2 users
            final CoreProbe.StoryConfig big = cfg(concat(base, "rate=100", "fill_s=30", "reopen_s=10"));
            new CoreProbe.Story(big, new FakeClock(), null, m -> { });
        });
        refusal("does not take fill_s=", () -> cfg("script=a01-mix", "seed=1", "seconds=1", "rate=1", "users=1,2", "fill_s=3"));
        refusal("does not take signal_dir=", () -> cfg("script=a01-mix", "seed=1", "seconds=1", "rate=1", "users=1,2", "signal_dir=/x"));
        refusal("does not take ioc_burst_on=", () -> cfg(concat(base, "ioc_burst_on=/m")));
        refusal("does not take ioc_burst_on=", () -> cfg("script=a02-lifecycle", "seed=1", "seconds=0", "rate=1", "users=1,2", "ioc_burst_on=/m"));
        // defaults: 100/s, fill_s 30, reopen_s 10, marker_timeout_s 60
        final CoreProbe.StoryConfig d = cfg("script=a03-fill", "seed=1", "users=" + users(40), "signal_dir=" + SIG);
        check(d.rate == 100 && d.fillS == 30 && d.reopenS == 10 && d.markerTimeoutS == 60,
                "a03 defaults " + d.rate + "/" + d.fillS + "/" + d.reopenS + "/" + d.markerTimeoutS);
    }

    private static String[] concat(final String[] a, final String... b) {
        final String[] out = java.util.Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    private static String users(final int n) {
        final StringBuilder sb = new StringBuilder();
        for (int i = 1; i <= n; i++) {
            sb.append(i == 1 ? "" : ",").append(i);
        }
        return sb.toString();
    }

    private static void iocBurst() {
        final String[] kv = {"script=a01-mix", "seed=5", "seconds=6", "rate=20", "users=1,2,3,4"};
        final Result plain = story(cfg(kv), StubPort.Mode.ACK_ALL);
        final FakeClock clock = new FakeClock();
        final long t0 = clock.now;
        clock.filesAt.put("/m/burst", t0 + 2_000_000_000L);
        final Result r = story(cfg(concat(kv, "ioc_burst_on=/m/burst")), StubPort.Mode.ACK_ALL, p -> p, clock);
        final long start = markerAt(r, "ioc_burst_started");
        final long end = markerAt(r, "ioc_burst_ended");
        check(start >= t0 + 2_000_000_000L && start < t0 + 2_100_000_000L, "burst started at +" + (start - t0));
        check(end - start >= 2_000_000_000L && end - start < 2_100_000_000L, "burst lasted " + (end - start) + " ns, expected 2 s");
        int burst = 0;
        for (final CoreProbe.StoryRow c : list(r, "creates")) {
            final boolean inside = c.scheduledNs >= start && c.scheduledNs < start + 2_000_000_000L;
            if (inside) {
                burst++;
                check(c.moment.equals("ioc_burst") && c.tif.equals("IOC") && c.type.equals("LIMIT"), "create inside the burst is not IOC: " + c.toJson());
                check(c.side.equals("BUY") ? c.price == 9999 * CoreProbe.Story.CENT : c.price == 8000 * CoreProbe.Story.CENT,
                        "burst create does not cross the whole band: " + c.toJson());
            } else {
                check(!c.moment.equals("ioc_burst"), "create outside the burst is marked ioc_burst: " + c.toJson());
            }
        }
        check(burst >= 38 && burst <= 42, "burst carried " + burst + " creates for 2 s at 20/s");
        check(((Integer) r.summary.json().get("ioc_burst_rows")) == burst, "ioc_burst_rows " + r.summary.json().get("ioc_burst_rows"));
        // rows before the marker are the plain story's rows: the burst changes nothing it was not asked to
        final List<CoreProbe.StoryRow> a = list(plain, "creates");
        final List<CoreProbe.StoryRow> b = list(r, "creates");
        check(a.size() == b.size(), "burst changed the number of creates");
        for (int i = 0; i < a.size(); i++) {
            if (b.get(i).scheduledNs - t0 < 2_000_000_000L) {
                check(a.get(i).toJson().get("price").equals(b.get(i).toJson().get("price")) && a.get(i).tif.equals(b.get(i).tif),
                        "a pre-burst row differs from the plain story at " + i);
            }
        }
        final Result never = story(cfg(concat(kv, "ioc_burst_on=/m/never")), StubPort.Mode.ACK_ALL);
        check(never.log.equals(plain.log) && markersNamed(never, "ioc_burst_started").isEmpty(), "a burst marker that never appears changed the story");
    }

    /** Fwdring pauses twice; the drill deletes the marker after the first burst and writes it again. A marker
     *  that stays only ever gives one burst (iocBurst above); a deleted and re-created one gives a second, numbered n=2. */
    private static void iocBurstRearm() {
        final String[] kv = {"script=a01-mix", "seed=5", "seconds=10", "rate=20", "users=1,2,3,4"};
        final FakeClock clock = new FakeClock();
        final long t0 = clock.now;
        clock.fileSpans.put("/m/burst", new long[] {t0 + 2_000_000_000L, t0 + 5_000_000_000L, t0 + 6_000_000_000L, Long.MAX_VALUE});
        final Result r = story(cfg(concat(kv, "ioc_burst_on=/m/burst")), StubPort.Mode.ACK_ALL, p -> p, clock);
        final List<Map<String, Object>> started = markersNamed(r, "ioc_burst_started");
        check(started.size() == 2, "expected two bursts, got " + started.size());
        check(Integer.valueOf(1).equals(started.get(0).get("n")) && Integer.valueOf(2).equals(started.get(1).get("n")),
                "bursts not numbered 1, 2: " + started);
        final long second = ((Number) started.get(1).get("at_ns")).longValue();
        check(second >= t0 + 6_000_000_000L && second < t0 + 6_100_000_000L, "second burst started at +" + (second - t0));
        int burst = 0;
        for (final CoreProbe.StoryRow c : list(r, "creates")) {
            burst += c.moment.equals("ioc_burst") ? 1 : 0;
        }
        check(burst >= 76 && burst <= 84, "two bursts carried " + burst + " creates for 2 x 2 s at 20/s");
        final FakeClock stays = new FakeClock();
        stays.filesAt.put("/m/burst", stays.now + 2_000_000_000L);
        final Result once = story(cfg(concat(kv, "ioc_burst_on=/m/burst")), StubPort.Mode.ACK_ALL, p -> p, stays);
        check(markersNamed(once, "ioc_burst_started").size() == 1, "a marker that stays re-armed the burst");
    }

    private static void users120() {
        final String u = users(120);
        final CoreProbe.StoryConfig c = cfg("script=a01-mix", "seed=2", "seconds=20", "rate=160", "users=" + u);
        final Result r = story(c, StubPort.Mode.ACK_ALL);
        check(list(r, "creates").size() == 3200, "a01 160/s 20 s with 120 users planned " + list(r, "creates").size() + " creates");
        check(c.users.length == 120, "users parsed " + c.users.length);
        final Set<Long> seen = new HashSet<>();
        for (final CoreProbe.StoryRow row : list(r, "creates")) {
            seen.add(row.user);
        }
        check(seen.size() == 120, "the story used " + seen.size() + " of 120 users");
        final CoreProbe.StoryConfig f = CoreProbe.StoryConfig.parse(Map.of("script", "funding", "seed", "2", "users", u,
                "out", "/x", "for", "a01-mix"));
        check(CoreProbe.Story.fundingPlan(f).size() == 240, "funding 120 users planned " + CoreProbe.Story.fundingPlan(f).size() + " rows, expected 240");
        // A05: 80 users, 90 s at 100/s
        final CoreProbe.StoryConfig a05 = cfg("script=a01-mix", "seed=2", "seconds=90", "rate=100", "users=" + users(80));
        check(a05.users.length == 80, "80 users");
        new CoreProbe.Story(a05, new FakeClock(), new StubPort(new FakeClock(), StubPort.Mode.ACK_ALL), m -> { });
    }

    private static void moneyDumpV7() {
        final CoreProbe p = new CoreProbe();
        p.listener = p.new Listener();
        p.listener.expectCorrelation = 5;
        p.listener.balancesEnd = true;
        p.listener.holdsEnd = true;
        int n = MessageHeaderEncoder.ENCODED_LENGTH + new FeedPositionReportEncoder().wrapAndApplyHeader(BUF, 0, HDR).correlationId(5)
                .consumePosition(4096).lastAppliedTradeId(77).journalEnabled(BoolFlag.TRUE).meEpoch(7506L).lastAppliedJournalSeq(321)
                .feedHalted(BoolFlag.TRUE).haltReason(FeedHaltReason.SOURCE_SCHEMA).encodedLength();
        p.listener.onMessage(1, 1, BUF, 0, n, null);
        String line = p.moneyDumpLine();
        check(line.contains("\"meEpoch\":7506") && line.contains("\"lastAppliedJournalSeq\":321") && line.contains("\"feedHalted\":true")
                && line.contains("\"haltReason\":\"SOURCE_SCHEMA\""), "money-dump halt fields missing: " + line);
        check(line.contains("\"consumePosition\":4096") && line.contains("\"lastAppliedTradeId\":77") && line.contains("\"journalEnabled\":true"),
                "money-dump lost a v6 field: " + line);
        n = MessageHeaderEncoder.ENCODED_LENGTH + new FeedPositionReportEncoder().wrapAndApplyHeader(BUF, 0, HDR).correlationId(5)
                .consumePosition(9).lastAppliedTradeId(3).journalEnabled(BoolFlag.FALSE).meEpoch(8L).lastAppliedJournalSeq(2)
                .feedHalted(BoolFlag.FALSE).haltReason(FeedHaltReason.NONE).encodedLength();
        p.listener.onMessage(1, 1, BUF, 0, n, null);
        line = p.moneyDumpLine();
        check(line.contains("\"meEpoch\":8") && line.contains("\"feedHalted\":false") && line.contains("\"haltReason\":\"NONE\""),
                "a running feed does not export feedHalted false / NONE: " + line);
        check(!line.contains("SOURCE_SCHEMA"), "the later report did not replace the earlier one");
    }

    private static void listenerRoutes() {
        final CoreProbe p = new CoreProbe();
        p.listener = p.new Listener();
        final List<String> calls = new ArrayList<>();
        p.listener.story = new CoreProbe.StorySink() {
            public void onAck(final long c, final long o, final boolean d, final int a, final long h, final String s) {
                calls.add("ack " + c + " " + o + " " + d + " " + s);
            }

            public void onReject(final long c, final String r, final int m, final long d, final long o) {
                calls.add("reject " + c + " " + r + " " + d);
            }

            public void onEvent(final long o, final String k, final String s, final long f) {
                calls.add("event " + o + " " + k + " " + s + " " + f);
            }
        };
        int n = MessageHeaderEncoder.ENCODED_LENGTH + new OrderAckEncoder().wrapAndApplyHeader(BUF, 0, HDR).correlationId(77)
                .requestIdHigh(1).requestIdLow(2).orderId(9).userId(1).marketId(1).status(OrderStatus.PENDING_NEW)
                .duplicate(BoolFlag.TRUE).holdAssetId(0).holdAmount(5).acceptedAtMs(0).eventSeq(1).encodedLength();
        p.listener.onMessage(1, 1, BUF, 0, n, null);
        n = MessageHeaderEncoder.ENCODED_LENGTH + new OrderRejectEncoder().wrapAndApplyHeader(BUF, 0, HDR).correlationId(78)
                .requestIdHigh(1).requestIdLow(3).userId(1).orderId(0).marketId(1).refTemplateId(50)
                .reason(CoreRejectReason.TOO_MANY_PENDING_REQUESTS).meReason((short) 255).detail(256).rejectedAtMs(0).encodedLength();
        p.listener.onMessage(1, 1, BUF, 0, n, null);
        p.listener.onMessage(1, 1, BUF, 0, eventFrame(4, 9, EventKind.FILL, OrderStatus.PARTIALLY_FILLED, 3), null);
        check(calls.equals(List.of("ack 77 9 true PENDING_NEW", "reject 78 TOO_MANY_PENDING_REQUESTS 256",
                "event 9 FILL PARTIALLY_FILLED 3")), "story routing " + calls);
        check(p.rows.isEmpty(), "story replies leaked into the one-verb reply rows");
    }
}
