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

import java.io.EOFException;
import java.io.IOException;
import java.nio.*;
import java.nio.channels.AsynchronousByteChannel;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicInteger;

import com.google.protobuf.*;
import com.google.protobuf.CodedOutputStream.OutOfSpaceException;

import ghidra.async.*;
import ghidra.util.ByteBufferUtils;
import ghidra.util.Msg;

public class AsyncProtobufMessageChannel<S extends GeneratedMessageV3, R extends GeneratedMessageV3> {
	public static final boolean LOG_READ = false;
	public static final boolean LOG_WRITE = false;

	public interface IOFunction<R extends Message> {
		R read(CodedInputStream stream) throws IOException;
	}

	public static final int DEFAULT_BUFFER_SIZE = 4096;

	public static void marshall(Message msg, ByteBuffer wBuf) throws IOException {
		int savedPosition = wBuf.position();
		try {
			wBuf.putInt(0); // Placeholder for len
			CodedOutputStream out = CodedOutputStream.newInstance(wBuf);
			msg.writeTo(out);
			out.flush();
			wBuf.putInt(savedPosition, out.getTotalBytesWritten());
			savedPosition = wBuf.position();
		}
		finally {
			wBuf.position(savedPosition);
		}
	}

	public static <R extends Message> R unmarshall(IOFunction<R> receiver, ByteBuffer rBuf)
			throws IOException {
		rBuf.flip();
		int savedPosition = rBuf.position();
		int savedLimit = rBuf.limit();
		try {
			int len = rBuf.getInt();
			if (rBuf.remaining() < len) {
				throw new BufferUnderflowException();
			}
			rBuf.limit(rBuf.position() + len);
			CodedInputStream in = CodedInputStream.newInstance(rBuf);
			R res = receiver.read(in);
			savedPosition = rBuf.position() + in.getTotalBytesRead();
			return res;
		}
		finally {
			rBuf.position(savedPosition);
			rBuf.limit(savedLimit);
			rBuf.compact();
		}
	}

	private final AsynchronousByteChannel channel;

	/** A lock for sharing the underlying channel's read operation */
	protected final AsyncLock rLock = new AsyncLock();
	/** A lock for sharing the underlying channel's write operation */
	protected final AsyncLock wLock = new AsyncLock();
	/** A buffer of received data */
	protected ByteBuffer rBuf;
	/** A buffer of data to send */
	protected ByteBuffer wBuf;

	public AsyncProtobufMessageChannel(AsynchronousByteChannel channel) {
		this(channel, DEFAULT_BUFFER_SIZE);
	}

	public AsyncProtobufMessageChannel(AsynchronousByteChannel channel, int initialBufferSize) {
		this.rBuf = ByteBuffer.allocate(initialBufferSize);
		this.wBuf = ByteBuffer.allocate(initialBufferSize);
		this.channel = channel;
	}

	/**
	 * Write a message to the channel
	 * 
	 * @param msg the message to write
	 * @return the length of the encoded message as a future
	 */
	public CompletableFuture<Integer> write(S msg) {
		if (LOG_WRITE) {
			Msg.debug(this, "Writing: " + msg);
		}
		AtomicInteger len = new AtomicInteger();
		return wLock.with(TypeSpec.INT, null).then((own, seq) -> {
			while (true) {
				try {
					wBuf.clear();
					marshall(msg, wBuf);
					break;
				}
				catch (BufferOverflowException | OutOfSpaceException e) {
					wBuf.clear();
					wBuf = ByteBufferUtils.upsize(wBuf);
				}
				catch (IOException e) {
					seq.exit(e);
					return;
				}
			}
			wBuf.flip();
			len.set(wBuf.remaining());
			AsyncUtils.loop(TypeSpec.VOID, loop -> {
				AsyncUtils.completable(TypeSpec.INT, channel::write, wBuf).handle(loop::consume);
			}, TypeSpec.INT, (l, loop) -> {
				loop.repeatWhile(wBuf.hasRemaining());
			}).handle(seq::next);
		}).then(seq -> {
			seq.exit(len.get());
		}).finish();
	}

	/**
	 * Read and decode a packet from the channel
	 * 
	 * @param pktType the type of packet expected
	 * @return the read packet as a future
	 */
	public <R2 extends R> CompletableFuture<R2> read(IOFunction<R2> receiver) {
		return rLock.with(TypeSpec.obj((R2) null), null).then((own, seq) -> {
			AsyncUtils.loop(TypeSpec.obj((R2) null), (loop) -> {
				try {
					R2 msg = unmarshall(receiver, rBuf);
					if (LOG_READ) {
						Msg.debug(this, "Read: " + msg);
					}
					loop.exit(msg);
				}
				catch (BufferUnderflowException | ArrayIndexOutOfBoundsException e) {
					AsyncUtils.completable(TypeSpec.INT, channel::read, rBuf).handle(loop::consume);
				}
				catch (Exception e) {
					loop.exit(e);
				}
			}, TypeSpec.INT, (lenread, loop) -> {
				if (lenread == -1) {
					loop.exit(new EOFException("Channel is closed"));
					return;
				}
				else if (lenread == 0) {
					rBuf = ByteBufferUtils.upsize(rBuf);
				}
				loop.repeat();
			}).handle(seq::exit);
		}).finish();
	}

	public void close() throws IOException {
		channel.close();
	}
}
