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
package ghidra.comm.packet;

import static ghidra.async.AsyncUtils.completable;
import static ghidra.async.AsyncUtils.loop;

import java.io.EOFException;
import java.nio.*;
import java.nio.channels.AsynchronousByteChannel;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicInteger;

import ghidra.async.AsyncLock;
import ghidra.async.TypeSpec;
import ghidra.comm.util.ByteBufferUtils;

/**
 * An asynchronous channel for exchanging packets, usually over a network
 * 
 * The underlying implementation uses {@link ByteBuffer}s, and the only provided codec that encodes
 * and decodes to a {@link ByteBuffer} is {@link ByteBufferCodec}. This does not preclude other
 * codecs. A {@link AbstractPacketMarshaller} must be provided during construction. The marshaller
 * provides the glue between the underlying channel, which is invariably {@link ByteBuffer} based,
 * and the decoded packet type. The marshaller chooses the codec.
 *
 * @param <S> the type of packet sent, possibly an abstract type
 * @param <R> the type of packet received, possibly an abstract type
 */
public class AsynchronousPacketChannel<S extends Packet, R extends Packet> {
	/** The byte channel for sending and receiving encoded data */
	protected final AsynchronousByteChannel channel;
	/** The marshaller for encoding and decoding packet data */
	protected final AbstractPacketMarshaller<S, R, ByteBuffer> marshaller;

	/** A lock for sharing the underlying channel's read operation */
	protected final AsyncLock rLock = new AsyncLock();
	/** A lock for sharing the underlying channel's write operation */
	protected final AsyncLock wLock = new AsyncLock();
	/** A buffer of received data */
	protected ByteBuffer rBuf;
	/** A buffer of data to send */
	protected ByteBuffer wBuf;

	/**
	 * Construct a new packet channel
	 * 
	 * @param channel the underlying byte channel for communication
	 * @param marshaller the marshaller for encoding and decoding packets
	 * @param initbuflen the initial size for the send and receive buffers. They will each grow as
	 *            needed.
	 */
	protected AsynchronousPacketChannel(AsynchronousByteChannel channel,
			AbstractPacketMarshaller<S, R, ByteBuffer> marshaller, int initbuflen) {
		this.channel = channel;
		this.marshaller = marshaller;
		this.rBuf = ByteBuffer.allocate(initbuflen);
		this.wBuf = ByteBuffer.allocate(initbuflen);
	}

	/**
	 * Construct a new packet channel
	 * 
	 * @param channel the underlying byte channel for communication
	 * @param marshaller the marshaller for encoding and decoding packets
	 */
	public AsynchronousPacketChannel(AsynchronousByteChannel channel,
			AbstractPacketMarshaller<S, R, ByteBuffer> marshaller) {
		this(channel, marshaller, 1024);
	}

	/**
	 * Read and decode a packet from the channel
	 * 
	 * @param pktType the type of packet expected
	 * @return the read packet as a future
	 */
	public <R2 extends R> CompletableFuture<R2> read(Class<R2> pktType) {
		return rLock.with(TypeSpec.cls(pktType), null).then((own, seq) -> {
			loop(TypeSpec.cls(pktType), (loop) -> {
				try {
					rBuf.flip();
					R2 res = marshaller.unmarshall(pktType, rBuf);
					rBuf.compact();
					loop.exit(res);
				}
				catch (BufferUnderflowException e) {
					rBuf.compact();
					completable(TypeSpec.INT, channel::read, rBuf).handle(loop::consume);
				}
				catch (Exception e) {
					rBuf.compact();
					loop.exit(e);
				}
			}, TypeSpec.INT, (lenread, loop) -> {
				if (lenread == -1) {
					loop.exit(new EOFException("Remote closed connection"));
					return;
				}
				else if (lenread == 0) {
					rBuf = ByteBufferUtils.upsize(rBuf);
				}
				loop.repeat();
			}).handle(seq::exit);
		}).finish();
	}

	/**
	 * Encode and write a packet to the channel
	 * 
	 * @param pkt the packet to write
	 * @return the length of the written encoded packet as a future
	 */
	public CompletableFuture<Integer> write(S pkt) {
		AtomicInteger len = new AtomicInteger();
		return wLock.with(TypeSpec.INT, null).then((own, seq) -> {
			while (true) {
				try {
					marshaller.marshall(wBuf, pkt);
					break;
				}
				catch (BufferOverflowException e) {
					wBuf.clear();
					wBuf = ByteBufferUtils.upsize(wBuf);
				}
				catch (Exception e) {
					seq.exit(e);
					return;
				}
			}
			wBuf.flip();
			len.set(wBuf.remaining());
			loop(TypeSpec.VOID, (loop) -> {
				completable(TypeSpec.INT, channel::write, wBuf).handle(loop::consume);
			}, TypeSpec.INT, (l, loop) -> {
				if (wBuf.hasRemaining()) {
					loop.repeat();
				}
				else {
					loop.exit();
				}
			}).handle(seq::next);
		}).then((seq) -> {
			wBuf.clear();
			seq.exit(len.get());
		}).finish();
	}
}
