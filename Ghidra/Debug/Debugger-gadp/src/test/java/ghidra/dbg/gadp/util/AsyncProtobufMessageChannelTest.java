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
package ghidra.dbg.gadp.util;

import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.AsynchronousByteChannel;
import java.nio.channels.CompletionHandler;
import java.util.Arrays;
import java.util.concurrent.*;

import org.junit.Test;

import ghidra.async.*;
import ghidra.dbg.gadp.protocol.Gadp;
import ghidra.dbg.gadp.protocol.Gadp.RootMessage;
import ghidra.util.NumericUtilities;
import ghidra.util.SystemUtilities;

public class AsyncProtobufMessageChannelTest {
	public final static long TIMEOUT_MILLIS =
		SystemUtilities.isInTestingBatchMode() ? 1000 : Long.MAX_VALUE;

	public static <T> T get(CompletableFuture<T> future) throws Exception {
		return future.get(TIMEOUT_MILLIS, TimeUnit.MILLISECONDS);
	}

	public static class AsyncFakeByteChannel implements AsynchronousByteChannel {
		AsyncPairingQueue<ReadReq<?>> readReqs = new AsyncPairingQueue<>();
		AsyncPairingQueue<WriteReq<?>> writeReqs = new AsyncPairingQueue<>();

		@Override
		public void close() throws IOException {
		}

		@Override
		public boolean isOpen() {
			return true;
		}

		@Override
		public <A> void read(ByteBuffer dst, A attachment,
				CompletionHandler<Integer, ? super A> handler) {
			readReqs.give(
				CompletableFuture.completedFuture(new ReadReq<>(dst, attachment, handler)));
		}

		@Override
		public Future<Integer> read(ByteBuffer dst) {
			return AsyncUtils.completable(TypeSpec.INT, this::read, dst);
		}

		@Override
		public <A> void write(ByteBuffer src, A attachment,
				CompletionHandler<Integer, ? super A> handler) {
			writeReqs.give(
				CompletableFuture.completedFuture(new WriteReq<>(src, attachment, handler)));
		}

		@Override
		public Future<Integer> write(ByteBuffer src) {
			return AsyncUtils.completable(TypeSpec.INT, this::write, src);
		}
	}

	public static class ReadReq<A> {
		private final ByteBuffer dst;
		private final A attachment;
		private final CompletionHandler<Integer, ? super A> handler;

		ReadReq(ByteBuffer dst, A attachment, CompletionHandler<Integer, ? super A> handler) {
			this.dst = dst;
			this.attachment = attachment;
			this.handler = handler;
		}

		void complete(byte[] src) {
			dst.put(src);
			handler.completed(src.length, attachment);
		}

		void error(Throwable exc) {
			handler.failed(exc, attachment);
		}
	}

	public static class WriteReq<A> {
		private final ByteBuffer src;
		private final A attachment;
		private final CompletionHandler<Integer, ? super A> handler;

		WriteReq(ByteBuffer src, A attachment, CompletionHandler<Integer, ? super A> handler) {
			this.src = src;
			this.attachment = attachment;
			this.handler = handler;
		}

		void complete(byte[] dst) {
			src.get(dst);
			handler.completed(dst.length, attachment);
		}

		void error(Throwable exc) {
			handler.failed(exc, attachment);
		}
	}

	AsyncFakeByteChannel byteChannel = new AsyncFakeByteChannel();

	AsyncProtobufMessageChannel<Gadp.RootMessage, Gadp.RootMessage> channel =
		new AsyncProtobufMessageChannel<>(byteChannel, 1);

	@Test
	public void testSendBufferGrows() throws Exception {
		channel.write(Gadp.RootMessage.newBuilder().setSequence(0x12345678).build());

		WriteReq<?> wr = get(byteChannel.writeReqs.take());
		byte[] data = new byte[wr.src.remaining()];
		wr.complete(data);
		assertEquals("0000000608f8acd19101", NumericUtilities.convertBytesToString(data));
	}

	@Test
	public void testRecvBufferGrows() throws Exception {
		byte[] data =
			NumericUtilities.convertStringToBytes("0000000608f8acd191010000000608f8acd19101");
		CompletableFuture<RootMessage> msg = channel.read(Gadp.RootMessage::parseFrom);

		ReadReq<?> rd = get(byteChannel.readReqs.take());
		assertEquals(1, rd.dst.remaining());
		rd.complete(Arrays.copyOfRange(data, 0, 1));

		rd = get(byteChannel.readReqs.take());
		assertEquals(0, rd.dst.remaining());
		rd.complete(Arrays.copyOfRange(data, 1, 1));

		rd = get(byteChannel.readReqs.take());
		assertEquals(1, rd.dst.remaining());
		rd.complete(Arrays.copyOfRange(data, 1, 2));

		rd = get(byteChannel.readReqs.take());
		assertEquals(0, rd.dst.remaining());
		rd.complete(Arrays.copyOfRange(data, 2, 2));

		rd = get(byteChannel.readReqs.take());
		assertEquals(2, rd.dst.remaining());
		rd.complete(Arrays.copyOfRange(data, 2, 4));

		rd = get(byteChannel.readReqs.take());
		assertEquals(0, rd.dst.remaining());
		rd.complete(Arrays.copyOfRange(data, 4, 4));

		rd = get(byteChannel.readReqs.take());
		assertEquals(4, rd.dst.remaining());
		rd.complete(Arrays.copyOfRange(data, 4, 8));

		rd = get(byteChannel.readReqs.take());
		assertEquals(0, rd.dst.remaining());
		rd.complete(Arrays.copyOfRange(data, 8, 8));

		rd = get(byteChannel.readReqs.take());
		assertEquals(8, rd.dst.remaining());
		rd.complete(Arrays.copyOfRange(data, 8, 16));

		assertEquals(Gadp.RootMessage.newBuilder().setSequence(0x12345678).build(), get(msg));

		msg = channel.read(Gadp.RootMessage::parseFrom);
		rd = get(byteChannel.readReqs.take());
		assertEquals(10, rd.dst.remaining());
		rd.complete(Arrays.copyOfRange(data, 6, 10));
		assertEquals(Gadp.RootMessage.newBuilder().setSequence(0x12345678).build(), get(msg));
	}
}
