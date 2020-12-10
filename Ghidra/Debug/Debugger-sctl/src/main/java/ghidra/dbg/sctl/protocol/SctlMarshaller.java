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
package ghidra.dbg.sctl.protocol;

import java.nio.*;

import ghidra.comm.packet.AbstractPacketMarshaller;
import ghidra.comm.packet.PacketCodec;
import ghidra.comm.packet.binary.ByteBufferPacketCodec;
import ghidra.comm.packet.err.PacketDecodeException;
import ghidra.comm.packet.err.PacketEncodeException;
import ghidra.util.Msg;
import ghidra.util.NumericUtilities;

/**
 * The marshaller for SCTL messages
 * 
 * This implements the {@code size[8]} portion of the messages, because that is used to delineate
 * each message from the following message. The remaining packet fields are implemented in
 * {@link SelSctlPacket} and its constituents.
 * 
 * This only marshalls and unmarshalls {@link SelSctlPacket}s to and from {@link ByteBuffer}s. It is
 * powered by the {@link ByteBufferPacketCodec}.
 */
public class SctlMarshaller
		extends AbstractPacketMarshaller<AbstractSelSctlPacket, AbstractSelSctlPacket, ByteBuffer> {
	final static boolean DEBUG = false;
	final static PacketCodec<ByteBuffer> BB_CODEC = ByteBufferPacketCodec.getInstance();

	/**
	 * Construct a SCTL packet marshaller
	 */
	public SctlMarshaller() {
		super(BB_CODEC, AbstractSelSctlPacket.class);
	}

	protected void printBuf(ByteBuffer buf) {
		if (DEBUG) {
			byte[] b = new byte[buf.remaining()];
			int p = buf.position();
			buf.get(b);
			buf.position(p);
			Msg.debug(this, NumericUtilities.convertBytesToString(b, ":"));
		}
	}

	@Override
	public void marshall(ByteBuffer outbuf, AbstractSelSctlPacket pkt)
			throws PacketEncodeException {
		int pos = outbuf.position();
		try {
			outbuf.order(ByteOrder.LITTLE_ENDIAN);
			outbuf.putLong(0); // Placeholder
			BB_CODEC.encodePacket(outbuf, pkt);

			// Backfill the length
			int end = outbuf.position();
			int len = end - pos - Long.BYTES;
			outbuf.putLong(pos, len);
		}
		catch (Exception e) {
			outbuf.position(pos);
			throw e;
		}
	}

	@Override
	public <R extends AbstractSelSctlPacket> R unmarshall(Class<R> pktType, ByteBuffer inbuf)
			throws PacketDecodeException {
		int origPos = inbuf.position();
		int origLimit = inbuf.limit();
		try {
			inbuf.order(ByteOrder.LITTLE_ENDIAN);
			int len = (int) inbuf.getLong() + Long.BYTES;
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
		}
	}
}
