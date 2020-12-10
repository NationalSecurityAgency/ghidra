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
import java.util.List;
import java.util.Map;

import ghidra.comm.packet.Packet;
import ghidra.comm.packet.PacketFactory;
import ghidra.comm.packet.annot.TypedByLookahead;
import ghidra.comm.packet.codecs.PacketCodecInternal;
import ghidra.comm.packet.err.*;
import ghidra.comm.packet.fields.AbstractFieldCodec;
import ghidra.comm.packet.fields.FieldCodec;

/**
 * The {@link FieldCodec} for fields annotated by {@link TypedByLookahead}
 * 
 * @see TypedByLookaheadWrapperFactory
 *
 * @param <ENCBUF> the type of temporary buffer used to encode
 * @param <DECBUF> the type of temporary buffer used to decode
 * @param <T> the type of the field as passed through the chain
 */
class TypedByLookaheadFieldCodec<ENCBUF, DECBUF, T> extends AbstractFieldCodec<ENCBUF, DECBUF, T> {
	private final PacketCodecInternal<?, ENCBUF, DECBUF> codec;
	private final Map<Class<? extends T>, FieldCodec<ENCBUF, DECBUF, ? extends T>> chainMap;
	private final List<Class<? extends T>> types;

	TypedByLookaheadFieldCodec(Class<? extends Packet> pktType, Field field,
			List<Class<? extends T>> types, PacketCodecInternal<?, ENCBUF, DECBUF> codec,
			Map<Class<? extends T>, FieldCodec<ENCBUF, DECBUF, ? extends T>> chainMap) {
		super(pktType, field);
		this.types = types;
		this.codec = codec;
		this.chainMap = chainMap;
	}

	@Override
	public T decodeField(Packet pkt, DECBUF buf, Integer count, PacketFactory factory)
			throws IOException, PacketDecodeException {
		int mark = codec.getDecodePosition(buf);
		for (Map.Entry<Class<? extends T>, FieldCodec<ENCBUF, DECBUF, ? extends T>> ent : chainMap
			.entrySet()) {
			try {
				@SuppressWarnings("unchecked")
				FieldCodec<ENCBUF, DECBUF, T> fieldCodec =
					(FieldCodec<ENCBUF, DECBUF, T>) ent.getValue();
				return fieldCodec.decodeField(pkt, buf, count, factory);
			}
			catch (PacketFieldValueMismatchException | InvalidPacketException e) {
				/*
				 * Msg.debug(this, "Lookahead for " + ent.getKey() + " backtracked: " +
				 * e.getMessage(), e);
				 */
				codec.setDecodePosition(buf, mark);
				// Try the next
			}
		}
		throw new InvalidPacketException("No selectable lookahead type succeeded for " + field);
	}

	@Override
	public void encodeField(ENCBUF buf, Packet pkt, T val)
			throws IOException, PacketEncodeException {
		if (!types.contains(val.getClass())) {
			throw new PacketEncodeException(val + " is not a selectable type for " + field);
		}
		@SuppressWarnings("unchecked")
		FieldCodec<ENCBUF, DECBUF, T> fieldCodec =
			(FieldCodec<ENCBUF, DECBUF, T>) chainMap.get(val.getClass());
		fieldCodec.encodeField(buf, pkt, val);
	}
}
