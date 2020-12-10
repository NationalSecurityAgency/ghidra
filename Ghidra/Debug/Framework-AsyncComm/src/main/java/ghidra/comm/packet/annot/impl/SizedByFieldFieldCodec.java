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

import ghidra.comm.packet.Packet;
import ghidra.comm.packet.PacketFactory;
import ghidra.comm.packet.annot.SizedByField;
import ghidra.comm.packet.codecs.PacketCodecInternal;
import ghidra.comm.packet.err.PacketDecodeException;
import ghidra.comm.packet.err.PacketEncodeException;
import ghidra.comm.packet.fields.AbstractFieldCodec;
import ghidra.comm.packet.fields.FieldCodec;

/**
 * The {@link FieldCodec} for fields annotated by {@link SizedByField}
 * 
 * @see SizedByFieldWrapperFactory
 *
 * @param <ENCBUF> the type of temporary buffer used to encode
 * @param <DECBUF> the type of temporary buffer used to decode
 * @param <T> the type of the field as passed through the chain
 */
class SizedByFieldFieldCodec<ENCBUF, DECBUF, T> extends AbstractFieldCodec<ENCBUF, DECBUF, T> {
	private final Field sizingField;
	private final SizedByField annot;
	private final FieldCodec<ENCBUF, DECBUF, T> chainNext;
	private final PacketCodecInternal<?, ENCBUF, DECBUF> codec;

	SizedByFieldFieldCodec(Class<? extends Packet> pktType, Field sizedField, Field sizingField,
			SizedByField annot, PacketCodecInternal<?, ENCBUF, DECBUF> codec,
			FieldCodec<ENCBUF, DECBUF, T> chainNext) {
		super(pktType, sizedField);
		this.sizingField = sizingField;
		this.annot = annot;
		this.codec = codec;
		this.chainNext = chainNext;
	}

	@Override
	public T decodeField(Packet pkt, DECBUF buf, Integer count, PacketFactory factory)
			throws IOException, PacketDecodeException {
		try {
			int len = (int) getIntegralValue(sizingField.get(pkt)) + annot.adjust();
			int pos = codec.getDecodePosition(buf);
			int orig = codec.limitDecodeBuffer(buf, pos + len);
			T result = chainNext.decodeField(pkt, buf, count, factory);
			if (codec.measureDecodeRemaining(buf) != 0) {
				throw new PacketDecodeException("Gratuitous data in sized field");
				// TODO: Consider padding
			}
			codec.limitDecodeBuffer(buf, orig);
			return result;
		}
		catch (IllegalAccessException e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public void encodeField(ENCBUF buf, Packet pkt, T val)
			throws IOException, PacketEncodeException {
		chainNext.encodeField(buf, pkt, val); // TODO: Try to use a cache
	}
}
