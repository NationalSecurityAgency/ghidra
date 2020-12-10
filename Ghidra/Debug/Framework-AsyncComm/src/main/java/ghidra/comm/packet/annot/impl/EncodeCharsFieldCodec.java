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
package ghidra.comm.packet.annot.impl;

import java.io.IOException;
import java.lang.reflect.Field;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.charset.CharsetEncoder;

import ghidra.comm.packet.Packet;
import ghidra.comm.packet.PacketFactory;
import ghidra.comm.packet.annot.EncodeChars;
import ghidra.comm.packet.binary.ByteBufferPacketCodec;
import ghidra.comm.packet.codecs.PacketCodecInternal;
import ghidra.comm.packet.err.PacketDecodeException;
import ghidra.comm.packet.err.PacketEncodeException;
import ghidra.comm.packet.fields.AbstractFieldCodec;
import ghidra.comm.packet.fields.FieldCodec;

/**
 * The {@link FieldCodec} for fields annoted by {@link EncodeChars}
 * 
 * @see EncodeCharsWrapperFactory
 *
 * @param <ENCBUF> the type of temporary buffer used to encode
 * @param <DECBUF> the type of temporary buffer used to decode
 */
class EncodeCharsFieldCodec<ENCBUF, DECBUF>
		extends AbstractFieldCodec<ENCBUF, DECBUF, CharSequence> {
	private final PacketCodecInternal<?, ENCBUF, DECBUF> codec;
	private final FieldCodec<ENCBUF, DECBUF, byte[]> chainNext;
	private final Charset charset;

	EncodeCharsFieldCodec(Class<? extends Packet> pktType, Field field, Charset charset,
			PacketCodecInternal<?, ENCBUF, DECBUF> codec,
			FieldCodec<ENCBUF, DECBUF, byte[]> chainNext) {
		super(pktType, field);
		this.charset = charset;
		this.codec = codec;
		this.chainNext = chainNext;
	}

	@Override
	public CharSequence decodeField(Packet pkt, DECBUF buf, Integer count, PacketFactory factory)
			throws IOException, PacketDecodeException {
		int pos = codec.getDecodePosition(buf);
		byte[] all = chainNext.decodeField(pkt, buf, null, factory);
		ByteBuffer temp = ByteBuffer.wrap(all);
		CharSequence result =
			ByteBufferPacketCodec.getInstance().decodeCharSequence(field, temp, count, charset);
		// Rewind, and consume just enough for the result
		codec.setDecodePosition(buf, pos);
		chainNext.decodeField(pkt, buf, temp.position(), factory);
		return result;
	}

	@Override
	public void encodeField(ENCBUF buf, Packet pkt, CharSequence val)
			throws IOException, PacketEncodeException {
		CharsetEncoder ce = charset.newEncoder();
		ByteBuffer temp = ce.encode(CharBuffer.wrap(val));
		temp.flip();
		chainNext.encodeField(buf, pkt, temp.array());
	}
}
