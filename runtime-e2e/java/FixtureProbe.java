// SPDX-License-Identifier: Apache-2.0
import io.aeron.samples.CncFileReader;
import io.aeron.cluster.ClusterTool;
import java.io.File;

/** Test-side probe compiled separately. Never linked into or substituted for an engine artifact. */
public final class FixtureProbe {
    private static String quote(String s) {
        return "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"")
            .replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t") + "\"";
    }

    public static void main(String[] args) {
        if (args.length == 4 && args[0].equals("fill-log")) {
            fillLog(args[1], args[2], Integer.parseInt(args[3])); return;
        }
        if (args.length != 1) throw new IllegalArgumentException("counters or snapshot required");
        if (args[0].equals("counters")) {
            try (CncFileReader cnc = CncFileReader.map()) {
                var counters = cnc.countersReader();
                var rows = new java.util.ArrayList<String>();
                counters.forEach((int id, String label) -> rows.add("{\"id\":" + id
                    + ",\"type\":" + counters.getCounterTypeId(id)
                    + ",\"value\":" + counters.getCounterValue(id) + ",\"label\":" + quote(label) + "}"));
                System.out.println("{\"driverPid\":" + cnc.driverPid() + ",\"heartbeatAgeMs\":"
                    + cnc.driverHeartbeatAgeMs() + ",\"counters\":[" + String.join(",", rows) + "]}");
            }
        } else if (args[0].equals("snapshot")) {
            if (!ClusterTool.snapshot(new File("/data/state/cluster"), System.err)) {
                throw new IllegalStateException("snapshot request was not accepted");
            }
            System.out.println("{\"snapshotRequested\":true}");
        } else throw new IllegalArgumentException("unsupported probe command");
    }

    private static void fillLog(String endpoints, String localHost, int count) {
        if (count <= 0 || count > 1_000_000) throw new IllegalArgumentException("bounded request count required");
        final long base = 7_000_000_000_000_000_000L;
        var seen = new java.util.BitSet(count);
        int[] received = {0};
        var decoder = new com.match.infrastructure.generated.OpenOrdersSnapshotDecoder();
        var header = new com.match.infrastructure.generated.MessageHeaderDecoder();
        var listener = new io.aeron.cluster.client.EgressListener() {
            public void onMessage(long session, long timestamp, org.agrona.DirectBuffer buffer,
                                  int offset, int length, io.aeron.logbuffer.Header ignored) {
                header.wrap(buffer, offset);
                if (header.templateId() != decoder.sbeTemplateId()) return;
                decoder.wrapAndApplyHeader(buffer, offset, header);
                long index = decoder.requestId() - base;
                if (index < 0 || index >= count || decoder.isLast() != 1) return;
                if (seen.get((int)index)) throw new IllegalStateException("duplicate diagnostic response");
                seen.set((int)index); received[0]++;
            }
        };
        long started = System.nanoTime();
        try (var driver = io.aeron.driver.MediaDriver.launch(new io.aeron.driver.MediaDriver.Context()
                .aeronDirectoryName("/dev/shm/fixture-log-fill-" + ProcessHandle.current().pid())
                .threadingMode(io.aeron.driver.ThreadingMode.SHARED)
                .publicationTermBufferLength(1024 * 1024).ipcTermBufferLength(1024 * 1024)
                .dirDeleteOnStart(true).dirDeleteOnShutdown(true));
             var cluster = io.aeron.cluster.client.AeronCluster.connect(new io.aeron.cluster.client.AeronCluster.Context()
                .aeronDirectoryName(driver.aeronDirectoryName()).clientName("fixture-diagnostic-log-fill")
                .ingressEndpoints(endpoints).ingressChannel("aeron:udp?term-length=1m")
                .egressChannel("aeron:udp?endpoint=" + localHost + ":0").egressListener(listener))) {
            var buffer = new org.agrona.concurrent.UnsafeBuffer(new byte[64]);
            var request = new com.match.infrastructure.generated.RequestOpenOrdersSnapshotEncoder();
            var messageHeader = new com.match.infrastructure.generated.MessageHeaderEncoder();
            var idle = new org.agrona.concurrent.BackoffIdleStrategy();
            long deadline = started + java.util.concurrent.TimeUnit.MINUTES.toNanos(6);
            long keepalive = 0;
            int sent = 0, nextReport = 100_000;
            while (received[0] < count) {
                long now = System.nanoTime();
                if (now > deadline) throw new IllegalStateException("bounded log-fill timeout: sent=" + sent + " received=" + received[0]);
                int work = cluster.pollEgress();
                for (int burst = 0; burst < 32 && sent < count && sent - received[0] < 256; burst++) {
                    request.wrapAndApplyHeader(buffer, 0, messageHeader).requestId(base + sent);
                    if (cluster.offer(buffer, 0, 8 + request.encodedLength()) <= 0) break;
                    sent++; work++;
                }
                if (now >= keepalive) { cluster.sendKeepAlive(); keepalive = now + 200_000_000; }
                if (received[0] >= nextReport) { System.err.println("diagnostic responses=" + received[0]); nextReport += 100_000; }
                idle.idle(work);
            }
            System.out.println("{\"sent\":" + sent + ",\"processed\":" + received[0]
                + ",\"uniqueResponses\":" + seen.cardinality() + ",\"elapsedNs\":" + (System.nanoTime() - started)
                + ",\"scope\":\"logged read-only diagnostic requests; not financial throughput\"}");
        }
    }
}
