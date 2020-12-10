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
import java.util.Map;

import org.apache.commons.collections4.BidiMap;

import ghidra.comm.packet.Packet;
import ghidra.comm.packet.PacketFactory;
import ghidra.comm.packet.annot.TypedByField;
import ghidra.comm.packet.err.*;
import ghidra.comm.packet.fields.AbstractFieldCodec;
import ghidra.comm.packet.fields.FieldCodec;

/**
 * The {@link FieldCodec} for fields annotated by {@link TypedByField}
 *
 * @see TypedByFieldWrapperFactory
 * 
 * @param <ENCBUF> the type of temporary buffer used to encode
 * @param <DECBUF> the type of temporary buffer used to decode
 * @param <T> the type of the field as passed through the chain
 */
class TypedByFieldFieldCodec<ENCBUF, DECBUF, T> extends AbstractFieldCodec<ENCBUF, DECBUF, T> {
	private final Field typingField;
	private final TypedByField annot;
	private final BidiMap<Object, Class<? extends T>> typeMap;
	private final Map<Class<? extends T>, FieldCodec<ENCBUF, DECBUF, ? extends T>> chainMap;

	TypedByFieldFieldCodec(Class<? extends Packet> pktType, Field field, Field typingField,
			TypedByField annot, BidiMap<Object, Class<? extends T>> typeMap,
			Map<Class<? extends T>, FieldCodec<ENCBUF, DECBUF, ? extends T>> chainMap) {
		super(pktType, field);
		this.typingField = typingField;
		this.annot = annot;
		this.typeMap = typeMap;
		this.chainMap = chainMap;
	}

	@Override
	public T decodeField(Packet pkt, DECBUF buf, Integer count, PacketFactory factory)
			throws IOException, PacketDecodeException {
		try {
			Object key = typingField.get(pkt);
			if (annot.types().length > 0) {
				key = getIntegralValue(key);
			}
			Class<? extends T> type = typeMap.get(key);
			if (type == null) {
				throw new InvalidPacketException("In " + pkt.getClass() + ": Do not know type of " +
					field.getName() + " for key:" + typingField + "=" + key);
			}
			@SuppressWarnings("unchecked")
			FieldCodec<ENCBUF, DECBUF, T> fieldCodec =
				(FieldCodec<ENCBUF, DECBUF, T>) chainMap.get(type);
			return fieldCodec.decodeField(pkt, buf, count, factory);
		}
		catch (IllegalAccessException e) {
			throw new RuntimeException(e);
		}
	}

	@SuppressWarnings("unchecked")
	@Override
	public void encodeField(ENCBUF buf, Packet pkt, T val)
			throws IOException, PacketEncodeException {
		FieldCodec<ENCBUF, DECBUF, T> fieldCodec;
		Class<?> cls = val.getClass();
		for (;;) {
			fieldCodec = (FieldCodec<ENCBUF, DECBUF, T>) chainMap.get(cls);
			if (fieldCodec != null) {
				break;
			}
			cls = cls.getSuperclass();
			if (cls == null) {
				throw new AssertionError();
			}
		}
		fieldCodec.encodeField(buf, pkt, val);
	}
}
