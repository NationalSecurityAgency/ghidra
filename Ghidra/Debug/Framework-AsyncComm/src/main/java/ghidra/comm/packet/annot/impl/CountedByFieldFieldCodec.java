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
import ghidra.comm.packet.annot.CountedByField;
import ghidra.comm.packet.err.PacketDecodeException;
import ghidra.comm.packet.err.PacketEncodeException;
import ghidra.comm.packet.fields.AbstractFieldCodec;
import ghidra.comm.packet.fields.FieldCodec;

/**
 * The {@link FieldCodec} for fields annotated by {@link CountedByField}
 * 
 * @see CountedByFieldWrapperFactory
 *
 * @param <ENCBUF> the type of temporary buffer used to encode
 * @param <DECBUF> the type of temporary buffer used to decode
 * @param <T> the type of the field as passed through the chain
 */
class CountedByFieldFieldCodec<ENCBUF, DECBUF, T> extends AbstractFieldCodec<ENCBUF, DECBUF, T> {
	private final FieldCodec<ENCBUF, DECBUF, T> chainNext;
	private final Field countingField;

	CountedByFieldFieldCodec(Class<? extends Packet> pktType, Field countedField,
			Field countingField, FieldCodec<ENCBUF, DECBUF, T> chainNext) {
		super(pktType, countedField);
		this.countingField = countingField;
		this.chainNext = chainNext;
	}

	@Override
	public T decodeField(Packet pkt, DECBUF buf, Integer count, PacketFactory factory)
			throws IOException, PacketDecodeException {
		try {
			count = (int) getIntegralValue(countingField.get(pkt));
			return chainNext.decodeField(pkt, buf, count, factory);
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
