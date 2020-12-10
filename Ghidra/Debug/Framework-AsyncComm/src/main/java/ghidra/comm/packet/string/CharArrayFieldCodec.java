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
package ghidra.comm.packet.string;

import java.io.IOException;
import java.lang.reflect.Field;
import java.nio.CharBuffer;

import ghidra.comm.packet.Packet;
import ghidra.comm.packet.PacketFactory;
import ghidra.comm.packet.err.PacketDecodeException;
import ghidra.comm.packet.err.PacketEncodeException;
import ghidra.comm.packet.fields.AbstractFieldCodec;
import ghidra.comm.packet.fields.FieldCodec;

/**
 * The {@link FieldCodec} for encoding character arrays for {@link StringPacketCodec}
 * 
 * This simply appends the array contents to the buffer for encoding, or consumes the remaining
 * contents of the buffer for decoding.
 */
class CharArrayFieldCodec extends AbstractFieldCodec<StringBuilder, CharBuffer, char[]> {
	private final StringPacketCodec codec;

	CharArrayFieldCodec(StringPacketCodec codec, Class<? extends Packet> pktType, Field field) {
		super(pktType, field);
		this.codec = codec;
	}

	@Override
	public char[] decodeField(Packet pkt, CharBuffer buf, Integer count, PacketFactory factory)
			throws IOException, PacketDecodeException {
		return codec.decodeCharArray(field, buf, count.intValue());
	}

	@Override
	public void encodeField(StringBuilder buf, Packet pkt, char[] val)
			throws IOException, PacketEncodeException {
		codec.encodeCharArray(buf, field, val);
	}
}
