// SPDX-License-Identifier: Apache-2.0
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.BufferedWriter;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.LockSupport;

/** Open-loop fixture workload, with durable PostgreSQL observation on the same monotonic clock.
 * HTTP acceptance is recorded separately and never counted as durable completion.
 */
public final class BenchmarkProbe {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static BufferedWriter events;
    private static synchronized void event(Object value) {
        try { events.write(JSON.writeValueAsString(value)); events.newLine(); }
        catch (Exception e) { throw new IllegalStateException("raw evidence write failed", e); }
    }
    private record Pending(long index, long intendedNs, long startedNs) {}

    public static void main(String[] args) throws Exception {
        JsonNode config = JSON.readTree(System.in);
        int rate = config.required("rate").asInt();
        int warmup = config.required("warmup_seconds").asInt();
        int seconds = config.required("measurement_seconds").asInt();
        int users = config.required("user_count").asInt();
        int maxInflight = config.required("max_inflight").asInt();
        if (rate < 1 || rate > 2000 || warmup < 0 || warmup > 60 || seconds < 1 || seconds > 120
                || users < 2 || users > 1000 || users % 2 != 0 || maxInflight < 1 || maxInflight > 8192)
            throw new IllegalArgumentException("unbounded workload");
        String run = config.required("run_id").asText();
        String baseUrl = config.required("oms_url").asText();
        Path output = Path.of("/data/benchmark"); Files.createDirectory(output);
        Files.writeString(output.resolve("config.json"), JSON.writeValueAsString(config));
        events = Files.newBufferedWriter(output.resolve("events.jsonl"));
        int total = Math.multiplyExact(rate, warmup + seconds);
        var pending = new ConcurrentHashMap<String, Pending>();
        var accepted = new AtomicInteger(); var durable = new AtomicInteger();
        var settlements = new AtomicInteger(); var httpErrors = new AtomicInteger();
        var loadMisses = new AtomicInteger(); var observerStop = new AtomicBoolean();
        var observerError = new AtomicReference<Throwable>();
        var done = new CountDownLatch(total); var slots = new Semaphore(maxInflight);
        long start = System.nanoTime() + TimeUnit.SECONDS.toNanos(1);
        event(Map.of("event", "window", "start_ns", start, "warmup_seconds", warmup,
                     "measurement_seconds", seconds, "rate", rate, "total_scheduled", total));
        Thread observer = new Thread(() -> {
            try (Connection orders = DriverManager.getConnection(config.required("oms_jdbc").asText(),
                     "runtime_fixture", "synthetic-fixture-only");
                 Connection money = DriverManager.getConnection(config.required("money_jdbc").asText(),
                     "runtime_fixture", "synthetic-fixture-only")) {
                long journalSeq = 0;
                while (!observerStop.get()) {
                    List<String> ids = new ArrayList<>(pending.keySet());
                    if (!ids.isEmpty()) {
                        try (var statement = orders.prepareStatement("SELECT oms_order_id,status,client_order_id FROM orders WHERE client_order_id=ANY(?) AND status NOT IN ('PENDING_NEW','PENDING_TRIGGER')")) {
                            var array = orders.createArrayOf("varchar", ids.toArray(String[]::new));
                            try {
                                statement.setArray(1, array); statement.setQueryTimeout(5);
                                try (var rows = statement.executeQuery()) {
                                    // The observed time is after executeQuery returns committed rows; a conservative
                                    // upper bound. Polling delay is retained, never subtracted from latency.
                                    long observed = System.nanoTime();
                                    while (rows.next()) {
                                        long id = rows.getLong(1); String clientId = rows.getString(3);
                                        Pending p = pending.remove(clientId);
                                        if (p != null) {
                                            durable.incrementAndGet();
                                            event(Map.of("event", "durable", "order_id", id, "status", rows.getString(2),
                                                "index", p.index(), "intended_ns", p.intendedNs(),
                                                "started_ns", p.startedNs(), "observed_ns", observed, "client_id", clientId));
                                        }
                                    }
                                }
                            } finally { array.free(); }
                        }
                    }
                    try (var statement = money.prepareStatement("SELECT journal_seq,movement_type,trade_id FROM money_journal WHERE journal_seq>? ORDER BY journal_seq")) {
                        statement.setLong(1, journalSeq); statement.setQueryTimeout(5);
                        try (var rows = statement.executeQuery()) {
                            long observed = System.nanoTime();
                            while (rows.next()) {
                                journalSeq = rows.getLong(1);
                                if (rows.getInt(2) == 4) {
                                    settlements.incrementAndGet();
                                    event(Map.of("event", "settled", "journal_seq", journalSeq,
                                                 "trade_id", rows.getLong(3), "observed_ns", observed));
                                }
                            }
                        }
                    }
                    LockSupport.parkNanos(2_000_000);
                }
            } catch (Throwable error) { observerError.set(error); }
        }, "fixture-durable-observer");
        observer.start();
        try (var executor = Executors.newVirtualThreadPerTaskExecutor();
             var client = HttpClient.newBuilder().executor(executor).connectTimeout(Duration.ofSeconds(5)).build()) {
            for (int i = 0; i < total; i++) {
                if (observerError.get() != null) throw new IllegalStateException("durable observer failed", observerError.get());
                long intended = start + (long)i * 1_000_000_000L / rate;
                long wait;
                while ((wait = intended - System.nanoTime()) > 0) LockSupport.parkNanos(wait);
                final int index = i;
                final long user = 72000L + (i % users);
                final long sentAt = System.nanoTime();
                var body = Map.<String,Object>of("marketId", 1, "side", i % 2 == 0 ? "SELL" : "BUY",
                    "orderType", "LIMIT", "price", "100000.00000000", "quantity", "0.01000000",
                    "clientOrderId", run + "-b-" + i);
                event(Map.of("event", "intent", "index", i, "user", user, "intended_ns", intended,
                             "started_ns", sentAt, "request", body));
                if (!slots.tryAcquire()) {
                    loadMisses.incrementAndGet(); done.countDown();
                    event(Map.of("event", "generator_overload", "index", i, "intended_ns", intended));
                    continue;
                }
                var request = HttpRequest.newBuilder(URI.create(baseUrl + "/api/v1/orders"))
                    .header("Authorization", "Bearer dev:" + user).header("Content-Type", "application/json")
                    .timeout(Duration.ofSeconds(10)).POST(HttpRequest.BodyPublishers.ofString(JSON.writeValueAsString(body))).build();
                String clientId = (String)body.get("clientOrderId");
                if (pending.putIfAbsent(clientId, new Pending(index, intended, sentAt)) != null)
                    throw new IllegalStateException("duplicate submitted client identity");
                client.sendAsync(request, HttpResponse.BodyHandlers.ofString()).whenComplete((response, error) -> {
                    try {
                        long observed = System.nanoTime();
                        int status = response == null ? 0 : response.statusCode();
                        String responseBody = response == null ? JSON.createObjectNode().put("error", String.valueOf(error)).toString() : response.body();
                        event(Map.of("event", "http", "index", index, "method", "POST", "path", "/api/v1/orders",
                            "request", body, "user", user, "intended_ns", intended, "observed_ns", observed,
                            "response", Map.of("status", status, "body", responseBody)));
                        JsonNode parsed = JSON.readTree(responseBody);
                        if ((status == 200 || status == 201) && parsed.path("accepted").asBoolean(false)) {
                            Long.parseLong(parsed.required("omsOrderId").asText());
                            accepted.incrementAndGet();
                        } else httpErrors.incrementAndGet();
                    } catch (Throwable failure) { observerError.compareAndSet(null, failure); }
                    finally { slots.release(); done.countDown(); }
                });
            }
            if (!done.await(30, TimeUnit.SECONDS)) throw new IllegalStateException("HTTP completion drain timeout");
            long drain = System.nanoTime() + TimeUnit.SECONDS.toNanos(30);
            while (!pending.isEmpty() && System.nanoTime() < drain && observerError.get() == null) Thread.sleep(5);
            // Keep the observer alive for delayed journal flushes; the exact oracle subsequently
            // requires every accepted effect, so an idle or incomplete projector cannot pass.
            Thread.sleep(2000);
        } finally {
            observerStop.set(true); observer.join(10_000);
            if (observer.isAlive()) throw new IllegalStateException("durable observer did not stop");
            events.close();
        }
        var summary = Map.of("status", "MEASURED_NOT_ACCEPTED", "scheduled", total,
            "accepted", accepted.get(), "durable_observed", durable.get(), "settled_observed", settlements.get(),
            "http_errors", httpErrors.get(), "generator_misses", loadMisses.get(), "pending", pending.size(),
            "elapsed_ns", System.nanoTime() - start);
        Files.writeString(output.resolve("summary.json"), JSON.writeValueAsString(summary));
        System.out.println(JSON.writeValueAsString(summary));
        if (observerError.get() != null) throw new IllegalStateException("measurement error", observerError.get());
    }
}
