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
import java.nio.BufferOverflowException;
import java.nio.ByteBuffer;

import ghidra.comm.packet.Packet;
import ghidra.comm.packet.err.PacketEncodeException;
import ghidra.comm.util.ByteBufferUtils;

/**
 * A codec for encoding packets as binary data directly into or from a {@link ByteBuffer}
 * 
 * Unlike {@link BinaryPacketCodec} and {@link BinaryLEPacketCodec}, this codec expects the caller
 * to provide the encode or decode buffer. The caller is responsible for managing the buffer. For
 * example, the caller must configure the buffer's byte order. Additionally, if the buffer is too
 * small, the codec will allow the {@link BufferOverflowException} to propagate. The caller should
 * re-allocate the buffer and try again.
 */
public class ByteBufferPacketCodec extends AbstractByteBufferPacketCodec<ByteBuffer> {

	public static final ByteBufferPacketCodec INSTANCE = new ByteBufferPacketCodec();

	/**
	 * Get the singleton instance of this codec
	 * 
	 * @return the instance
	 */
	public static ByteBufferPacketCodec getInstance() {
		return INSTANCE;
	}

	protected ByteBufferPacketCodec() {
	}

	@Override
	public ByteBuffer encodePacket(Packet pkt) throws PacketEncodeException {
		ByteBuffer buf = ByteBuffer.allocate(1024);
		while (true) {
			try {
				encodePacketInto(buf, pkt);
				buf.flip();
				return buf;
			}
			catch (BufferOverflowException e) {
				buf = ByteBufferUtils.upsize(buf);
			}
		}
	}

	@Override
	protected ByteBuffer finishEncode(ByteBuffer buf) {
		return buf;
	}

	@Override
	public ByteBuffer newDecodeBuffer(ByteBuffer data) throws IOException {
		return data; // No conversion necessary
	}

	@Override
	public ByteBuffer newEncodeBuffer() throws IOException {
		throw new UnsupportedOperationException("Caller should provide its own encode buffer");
	}

	@Override
	public void encodePacket(ByteBuffer buf, Packet pkt) throws PacketEncodeException {
		encodePacketInto(buf, pkt);
	}
}
