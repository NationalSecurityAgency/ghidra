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
package ghidra.comm.packet.binary;

import java.io.IOException;
import java.nio.*;
import java.util.Arrays;

import ghidra.comm.packet.Packet;
import ghidra.comm.packet.err.PacketEncodeException;
import ghidra.comm.util.ByteBufferUtils;

/**
 * A codec for encoding packets as binary data into byte arrays
 */
public abstract class AbstractBinaryPacketCodec extends AbstractByteBufferPacketCodec<byte[]> {
	protected AbstractBinaryPacketCodec() {
	}

	/**
	 * The default byte order
	 * 
	 * @return the byte order
	 */
	protected abstract ByteOrder getDefaultByteOrder();

	@Override
	public void encodePacket(byte[] buf, Packet pkt) throws PacketEncodeException {
		encodePacketInto(ByteBuffer.wrap(buf), pkt);
	}

	@Override
	public ByteBuffer newDecodeBuffer(byte[] data) throws IOException {
		return ByteBuffer.wrap(data);
	}

	@Override
	public ByteBuffer newEncodeBuffer() throws IOException {
		ByteBuffer buf = ByteBuffer.allocate(1024);
		buf.order(getDefaultByteOrder());
		return buf;
	}

	@Override
	protected byte[] finishEncode(ByteBuffer buf) {
		return Arrays.copyOf(buf.array(), buf.position());
	}

	@Override
	public byte[] encodePacket(Packet pkt) throws PacketEncodeException {
		ByteBuffer buf;
		try {
			buf = newEncodeBuffer();
		}
		catch (IOException e) {
			throw new AssertionError("Internal error", e);
		}
		while (true) {
			try {
				encodePacketInto(buf, pkt);
				return finishEncode(buf);
			}
			catch (PacketEncodeException e) {
				throw e;
			}
			catch (BufferOverflowException e) {
				buf.clear();
				buf = ByteBufferUtils.upsize(buf);
			}
			catch (RuntimeException e) {
				throw e;
			}
			catch (Exception e) {
				throw new AssertionError("Internal error", e);
			}
		}
	}
}
