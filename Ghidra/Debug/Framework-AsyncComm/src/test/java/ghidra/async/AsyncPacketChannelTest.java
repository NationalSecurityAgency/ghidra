/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.async;

import static ghidra.async.AsyncUtils.*;
import static ghidra.comm.tests.packet.BinaryPacketDecodingTest.consPacket;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.io.EOFException;
import java.io.IOException;
import java.net.*;
import java.nio.*;
import java.nio.channels.*;
import java.util.Random;
import java.util.concurrent.*;

import org.junit.*;

import ghidra.comm.packet.*;
import ghidra.comm.packet.binary.ByteBufferPacketCodec;
import ghidra.comm.packet.err.PacketDecodeException;
import ghidra.comm.packet.err.PacketEncodeException;
import ghidra.comm.tests.packet.PacketTestClasses.TestMessageEnum;
import ghidra.comm.tests.packet.PacketTestClasses.TestMessageTypedByMap;
import ghidra.comm.tests.packet.PacketTestClasses.TestMessageTypedByMap.TestASubByMap;
import ghidra.util.NumericUtilities;

// Also checks that the resulting syntax/patterns are agreeable
public class AsyncPacketChannelTest {
	final static PacketCodec<ByteBuffer> BB_CODEC = ByteBufferPacketCodec.getInstance();

	protected int testPort;

	private static class FragmentControlledAsyncByteChannel implements AsynchronousByteChannel {
		final byte[][] fragments;
		int fragno = 0;

		public FragmentControlledAsyncByteChannel(byte[]... fragments) {
			this.fragments = fragments;
		}

		@Override
		public boolean isOpen() {
			return true;
		}

		@Override
		public void close() throws IOException {
			// Nothing
		}

		@Override
		public <A> void write(ByteBuffer src, A attachment,
				CompletionHandler<Integer, ? super A> handler) {
			// Nothing, doesn't need testing here
		}

		@Override
		public Future<Integer> write(ByteBuffer src) {
			// Nothing
			return null;
		}

		@Override
		public <A> void read(ByteBuffer dst, A attachment,
				CompletionHandler<Integer, ? super A> handler) {
			int pos = dst.position();
			try {
				dst.put(fragments[fragno]);
				int len = fragments[fragno].length;
				fragno++;
				ForkJoinPool.commonPool().submit(() -> {
					handler.completed(len, attachment);
				});
			}
			catch (BufferOverflowException e) {
				dst.position(pos);
				ForkJoinPool.commonPool().submit(() -> {
					handler.completed(0, attachment);
				});
			}
		}

		@Override
		public Future<Integer> read(ByteBuffer dst) {
			// Nothing. Implementing strictly via completion handler
			return null;
		}
	}

	static class MyMarshaller
			extends AbstractPacketMarshaller<TestMessageTypedByMap, TestMessageEnum, ByteBuffer> {
		public MyMarshaller() {
			super(BB_CODEC, TestMessageEnum.class);
		}

		@Override
		public void marshall(ByteBuffer outbuf, TestMessageTypedByMap pkt)
				throws PacketEncodeException {
			int pos = outbuf.position();
			try {
				outbuf.putLong(0); // Placeholder
				BB_CODEC.encodePacket(outbuf, pkt);

				// Backfill the length
				int end = outbuf.position();
				int len = end - pos - Long.BYTES;
				ByteOrder orig = outbuf.order();
				outbuf.order(ByteOrder.LITTLE_ENDIAN);
				outbuf.putLong(pos, len);
				outbuf.order(orig);
			}
			catch (Exception e) {
				outbuf.position(pos);
				throw e;
			}
		}

		@Override
		public <R extends TestMessageEnum> R unmarshall(Class<R> pktType, ByteBuffer inbuf)
				throws PacketDecodeException {
			int origPos = inbuf.position();
			int origLimit = inbuf.limit();
			ByteOrder origOrder = inbuf.order();
			try {
				inbuf.order(ByteOrder.LITTLE_ENDIAN);
				int len = (int) inbuf.getLong() + Long.BYTES;
				inbuf.order(origOrder);
				if (inbuf.limit() < len) {
					throw new BufferUnderflowException();
				}
				inbuf.limit(len);
				R rcvd = BB_CODEC.decodePacket(pktType, inbuf, factory);
				return rcvd;
			}
			catch (Exception e) {
				inbuf.position(origPos);
				throw e;
			}
			finally {
				inbuf.limit(origLimit);
				inbuf.order(origOrder);
			}
		}
	}

	static class SocketClient
			extends AsynchronousPacketChannel<TestMessageTypedByMap, TestMessageEnum> {
		SocketClient(AsynchronousByteChannel channel) {
			//super(channel, new MyMarshaller(), 8);
			super(new DebugByteChannel(channel), new MyMarshaller(), 8);
		}
	}

	void runServer() {
		try (ServerSocket srv = new ServerSocket(testPort)) {
			try (Socket cli = srv.accept()) {
				byte[] buf = new byte[13];
				int len = cli.getInputStream().read(buf);
				System.out.println("Server got " + len + " bytes: " +
					NumericUtilities.convertBytesToString(buf, 0, len, ":"));
				cli.getOutputStream()
						.write(consPacket( //
							"05:00:00:00:00:00:00:00", "02", "00:00:00:33", //
							"05:00:00:00:00:00:00:00", "03", "00:00:00:10"));
			}
		}
		catch (Exception e) {
			e.printStackTrace();
			fail();
		}
	}

	@Before
	public void setUp() {
		testPort = 12345 + new Random().nextInt(1024);
		new Thread(this::runServer).start();
	}

	@Test
	public void testUnmarshallIncomplete() throws Throwable {
		BB_CODEC.registerPacketType(TestMessageEnum.class);

		TestMessageEnum exp1 = new TestMessageEnum(TestMessageEnum.TestEnum.ONE, 51);
		TestMessageEnum exp2 = new TestMessageEnum(TestMessageEnum.TestEnum.TWO, 16);
		// Initialize any meta fields
		BB_CODEC.encodePacket(exp1);
		BB_CODEC.encodePacket(exp2);

		// Structure fragments to ensure incomplete packets reset the buffer state
		// Also, a complete packet should advance, not restore, the buffer state
		AsynchronousByteChannel channel = new FragmentControlledAsyncByteChannel( //
			consPacket("05:00"), //
			consPacket("00:00:00:00:00"), //
			consPacket("00", "02", "00"), //
			consPacket("00:00:33"), //
			//
			consPacket("05:00"), //
			consPacket("00:00:00:00:00"), //
			consPacket("00", "03", "00"), //
			consPacket("00:00:10") //
		);
		AsynchronousPacketChannel<TestMessageTypedByMap, TestMessageEnum> client =
			new SocketClient(channel);
		sequence(TypeSpec.VOID).then((seq) -> {
			client.read(TestMessageEnum.class).handle(seq::next);
		}, TypeSpec.cls(TestMessageEnum.class)).then((pkt, seq) -> {
			System.out.println("Read: " + pkt);
			assertEquals(exp1, pkt);

			client.read(TestMessageEnum.class).handle(seq::next);
		}, TypeSpec.cls(TestMessageEnum.class)).then((pkt, seq) -> {
			System.out.println("Read: " + pkt);
			assertEquals(exp2, pkt);

			seq.exit(null, null);
		}).finish().get(1000, TimeUnit.MILLISECONDS);
	}

	@Test
	@Ignore("TODO") // Not sure why this fails under Gradle but not my IDE
	public void testClient() throws Throwable {
		BB_CODEC.registerPacketType(TestMessageTypedByMap.class);
		BB_CODEC.registerPacketType(TestMessageEnum.class);

		AsynchronousSocketChannel channel = AsynchronousSocketChannel.open();
		AsynchronousPacketChannel<TestMessageTypedByMap, TestMessageEnum> client =
			new SocketClient(channel);
		sequence(TypeSpec.VOID).then((seq) -> {
			completable(TypeSpec.VOID, channel::connect,
				new InetSocketAddress("localhost", testPort)).handle(seq::next);
		}).then((seq) -> {
			System.out.println("Connected");
			client.write(new TestMessageTypedByMap(new TestASubByMap(5))).handle(seq::next);
		}, TypeSpec.cls(Integer.class)).then((len, seq) -> {
			System.out.println("Sent " + len + " bytes");
			client.read(TestMessageEnum.class).handle(seq::next);
		}, TypeSpec.cls(TestMessageEnum.class)).then((pkt, seq) -> {
			System.out.println("Received: " + pkt);
			client.read(TestMessageEnum.class).handle(seq::next);
		}, TypeSpec.cls(TestMessageEnum.class)).then((pkt, seq) -> {
			System.out.println("Received: " + pkt);
			seq.exit(null, null);
		}).finish().get(1000, TimeUnit.MILLISECONDS);
	}

	@Test(expected = EOFException.class)
	@Ignore("TODO") // Not sure why this fails under Gradle but not my IDE
	public void testClientDisconnect() throws Throwable {
		BB_CODEC.registerPacketType(TestMessageTypedByMap.class);
		BB_CODEC.registerPacketType(TestMessageEnum.class);

		AsynchronousSocketChannel channel = AsynchronousSocketChannel.open();
		AsynchronousPacketChannel<TestMessageTypedByMap, TestMessageEnum> client =
			new SocketClient(channel);
		try {
			sequence(TypeSpec.VOID).then((seq) -> {
				completable(TypeSpec.VOID, channel::connect,
					new InetSocketAddress("localhost", testPort)).handle(seq::next);
			}).then((seq) -> {
				System.out.println("Connected");
				client.write(new TestMessageTypedByMap(new TestASubByMap(5))).handle(seq::next);
			}, TypeSpec.INT).then((len, seq) -> {
				System.out.println("Sent " + len + " bytes");
				loop(TypeSpec.VOID, (loop) -> {
					client.read(TestMessageEnum.class).handle(loop::consume);
				}, TypeSpec.cls(TestMessageEnum.class), (pkt, loop) -> {
					System.out.println("Received: " + pkt);
					loop.repeat();
				}).handle(seq::exit);
			}).finish().get(1000, TimeUnit.MILLISECONDS);
		}
		catch (ExecutionException e) {
			throw e.getCause();
		}
	}
}
