// SPDX-License-Identifier: Apache-2.0
import io.aeron.Subscription;
import io.aeron.archive.client.AeronArchive;
import io.aeron.cluster.client.AeronCluster;
import io.aeron.cluster.client.EgressListener;
import io.aeron.driver.MediaDriver;
import io.aeron.driver.ThreadingMode;
import io.aeron.logbuffer.FrameDescriptor;
import io.aeron.logbuffer.Header;
import org.agrona.CloseHelper;
import org.agrona.DirectBuffer;
import org.agrona.concurrent.BackoffIdleStrategy;
import org.agrona.concurrent.UnsafeBuffer;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;

/**
 * RC2 S14 ME-side probe, compiled separately against the frozen ME jar. It never decodes journal
 * records itself: {@code dump} copies every frame of every journal recording verbatim (hex) with its
 * recording and position, and the Python profile decoder (journal_decode.py, pinned schema XML) judges
 * them. That keeps this probe valid across the RC2 S1 journal schema change.
 *
 * <pre>
 * dump      archive=host:port local=ip control_stream=4010 stream=4001 replay_port=19820 source=me0
 * open-legs ingress=0=h:p,1=h:p,2=h:p local=ip     (OpenOrdersSnapshot 27 via the ME cluster)
 * </pre>
 * Optional ME_AUTH_CREDENTIAL (keyId:CLASS:secretHex) is presented on the ME session once the ME
 * authenticator exists (RC2 S6); without it the session presents nothing, as today's ME expects.
 * Exit codes: 0 complete; 3 deadline; 64 usage. Output: JSON lines on stdout.
 */
public final class JournalProbe {
    private static final long DEADLINE_MS = 60_000;

    public static void main(final String[] argv) {
        final java.util.Map<String, String> args = new java.util.HashMap<>();
        for (int i = 1; i < argv.length; i++) {
            final int eq = argv[i].indexOf('=');
            if (eq <= 0) {
                System.err.println("argument must be key=value: " + argv[i]);
                System.exit(64);
            }
            args.put(argv[i].substring(0, eq), argv[i].substring(eq + 1));
        }
        if (argv.length == 0) {
            System.err.println("usage: JournalProbe dump|open-legs key=value...");
            System.exit(64);
        }
        final MediaDriver driver = MediaDriver.launch(new MediaDriver.Context()
                .aeronDirectoryName("/dev/shm/journal-probe-" + ProcessHandle.current().pid())
                .threadingMode(ThreadingMode.SHARED).dirDeleteOnStart(true).dirDeleteOnShutdown(true)
                .errorHandler(t -> t.printStackTrace(System.err)));
        int code;
        try {
            code = switch (argv[0]) {
                case "dump" -> dump(driver, args);
                case "open-legs" -> openLegs(driver, args);
                default -> 64;
            };
        } catch (final IllegalStateException | io.aeron.exceptions.TimeoutException e) {
            System.err.println("JournalProbe: " + e.getMessage());
            code = 3;
        } finally {
            CloseHelper.quietClose(driver);
        }
        System.exit(code);
    }

    private static String need(final java.util.Map<String, String> args, final String key) {
        final String value = args.get(key);
        if (value == null) {
            throw new IllegalArgumentException("required argument " + key + "= is missing");
        }
        return value;
    }

    private static int dump(final MediaDriver driver, final java.util.Map<String, String> args) {
        final String local = need(args, "local");
        final int stream = Integer.parseInt(need(args, "stream"));
        final String source = need(args, "source");
        final HexFormat hex = HexFormat.of();
        try (AeronArchive archive = AeronArchive.connect(new AeronArchive.Context()
                .aeronDirectoryName(driver.aeronDirectoryName())
                .controlRequestChannel("aeron:udp?endpoint=" + need(args, "archive"))
                .controlRequestStreamId(Integer.parseInt(need(args, "control_stream")))
                .controlResponseChannel("aeron:udp?endpoint=" + local + ":0")
                .recordingSignalConsumer((controlSessionId, correlationId, recordingId, subscriptionId, position, signal) -> { }))) {
            final List<long[]> recordings = new ArrayList<>();
            final int listed = archive.listRecordings(0, 1000, (controlSessionId, correlationId, recordingId, startTimestamp, stopTimestamp,
                    startPosition, stopPosition, initialTermId, segmentFileLength, termBufferLength, mtuLength, sessionId,
                    streamId, strippedChannel, originalChannel, sourceIdentity) -> {
                if (streamId == stream) {
                    recordings.add(new long[] {recordingId, startPosition, stopPosition});
                }
            });
            if (listed >= 1000) {
                throw new IllegalStateException("1000 or more recordings listed; the dump would be truncated");
            }
            long frames = 0;
            final String replayChannel = "aeron:udp?endpoint=" + local + ":" + need(args, "replay_port");
            for (final long[] r : recordings) {
                final long stop = r[2] != AeronArchive.NULL_POSITION ? r[2] : archive.getRecordingPosition(r[0]);
                final long length = stop - r[1];
                System.out.println("{\"kind\":\"recording\",\"source\":\"" + source + "\",\"recording\":" + r[0]
                        + ",\"start\":" + r[1] + ",\"stop\":" + stop + ",\"active\":" + (r[2] == AeronArchive.NULL_POSITION) + "}");
                if (length <= 0) {
                    continue;
                }
                final long[] seen = {0, r[1]};
                try (Subscription replay = archive.replay(r[0], r[1], length, replayChannel, 4013)) {
                    final long deadline = System.currentTimeMillis() + DEADLINE_MS;
                    final BackoffIdleStrategy idle = new BackoffIdleStrategy();
                    while (seen[1] < stop) {
                        if (System.currentTimeMillis() > deadline) {
                            throw new IllegalStateException("replay of recording " + r[0] + " stalled at " + seen[1] + " < " + stop);
                        }
                        idle.idle(replay.poll((DirectBuffer buffer, int offset, int len, Header header) -> {
                            final boolean whole = (header.flags() & FrameDescriptor.UNFRAGMENTED) == FrameDescriptor.UNFRAGMENTED;
                            final byte[] bytes = new byte[len];
                            buffer.getBytes(offset, bytes);
                            System.out.println("{\"kind\":\"frame\",\"source\":\"" + source + "\",\"recording\":" + r[0]
                                    + ",\"position\":" + header.position() + ",\"fragmented\":" + !whole
                                    + ",\"hex\":\"" + hex.formatHex(bytes) + "\"}");
                            seen[0]++;
                            seen[1] = header.position();
                        }, 64));
                    }
                }
                frames += seen[0];
            }
            System.out.println("{\"kind\":\"end\",\"source\":\"" + source + "\",\"recordings\":" + recordings.size()
                    + ",\"frames\":" + frames + "}");
        }
        return 0;
    }

    private static byte[] meCredentials() {
        final String spec = System.getenv("ME_AUTH_CREDENTIAL");
        if (spec == null || spec.isBlank()) {
            return null;
        }
        final String[] p = spec.trim().split(":");
        final int cls = switch (p[1].toUpperCase()) {
            case "FORWARDER" -> 2;
            case "ADMIN" -> 4;
            default -> throw new IllegalArgumentException("ME credential class must be FORWARDER or ADMIN");
        };
        final byte[] secret = HexFormat.of().parseHex(p[2]);
        return ByteBuffer.allocate(6 + secret.length).order(ByteOrder.LITTLE_ENDIAN)
                .put((byte) 1).put((byte) cls).putInt(Integer.parseInt(p[0])).put(secret).array();
    }

    private static int openLegs(final MediaDriver driver, final java.util.Map<String, String> args) {
        final long requestId = 7_100_000_000_000_000_000L + (System.nanoTime() & 0xFFFFFFL);
        final List<String> rows = new ArrayList<>();
        final boolean[] last = {false};
        final long[] maxOrderId = {0};
        final var decoder = new com.match.infrastructure.generated.OpenOrdersSnapshotDecoder();
        final var header = new com.match.infrastructure.generated.MessageHeaderDecoder();
        final EgressListener listener = (session, timestamp, buffer, offset, length, ignored) -> {
            header.wrap(buffer, offset);
            if (header.templateId() != decoder.sbeTemplateId()) return;
            decoder.wrapAndApplyHeader(buffer, offset, header);
            if (decoder.requestId() != requestId) return;
            maxOrderId[0] = decoder.snapshotMaxOrderId();
            for (final var o : decoder.orders()) {
                rows.add("{\"leg\":" + o.orderId() + ",\"order\":" + o.omsOrderId() + "}");
            }
            if (decoder.isLast() == 1) last[0] = true;
        };
        final byte[] credentials = meCredentials();
        final AeronCluster.Context context = new AeronCluster.Context()
                .aeronDirectoryName(driver.aeronDirectoryName()).ingressEndpoints(need(args, "ingress"))
                .ingressChannel("aeron:udp?term-length=1m").egressChannel("aeron:udp?endpoint=" + need(args, "local") + ":0")
                .egressListener(listener);
        if (credentials != null) {
            context.credentialsSupplier(new io.aeron.security.CredentialsSupplier() {
                public byte[] encodedCredentials() { return credentials.clone(); }
                public byte[] onChallenge(final byte[] challenge) { return new byte[0]; }
            });
        }
        try (AeronCluster cluster = AeronCluster.connect(context)) {
            final UnsafeBuffer buffer = new UnsafeBuffer(new byte[64]);
            final var encoder = new com.match.infrastructure.generated.RequestOpenOrdersSnapshotEncoder();
            final var headerEncoder = new com.match.infrastructure.generated.MessageHeaderEncoder();
            encoder.wrapAndApplyHeader(buffer, 0, headerEncoder).requestId(requestId);
            final long deadline = System.currentTimeMillis() + DEADLINE_MS;
            final BackoffIdleStrategy idle = new BackoffIdleStrategy();
            while (cluster.offer(buffer, 0, 8 + encoder.encodedLength()) < 0) {
                if (System.currentTimeMillis() > deadline) throw new IllegalStateException("offer to the ME timed out");
                cluster.pollEgress();
                idle.idle();
            }
            long keepalive = 0;
            while (!last[0]) {
                final long now = System.currentTimeMillis();
                if (now > deadline) throw new IllegalStateException("no complete OpenOrdersSnapshot before the deadline");
                if (now >= keepalive) { cluster.sendKeepAlive(); keepalive = now + 250; }
                idle.idle(cluster.pollEgress());
            }
        }
        System.out.println("{\"verb\":\"open-legs\",\"snapshot_max_order_id\":" + maxOrderId[0] + ",\"legs\":["
                + String.join(",", rows) + "]}");
        return 0;
    }
}
