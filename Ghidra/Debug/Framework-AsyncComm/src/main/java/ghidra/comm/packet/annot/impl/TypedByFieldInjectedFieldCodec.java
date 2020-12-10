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

import org.apache.commons.collections4.BidiMap;

import ghidra.comm.packet.Packet;
import ghidra.comm.packet.PacketFactory;
import ghidra.comm.packet.annot.TypedByField;
import ghidra.comm.packet.err.PacketDecodeException;
import ghidra.comm.packet.err.PacketEncodeException;
import ghidra.comm.packet.fields.AbstractFieldCodec;
import ghidra.comm.packet.fields.FieldCodec;

/**
 * The {@link FieldCodec} for fields referred to by {@link TypedByField}
 *
 * @see TypedByFieldWrapperFactory
 * @see TypedByFieldInjectionFactory
 *
 * @param <ENCBUF> the type of temporary buffer used to encode
 * @param <DECBUF> the type of temporary buffer used to decode
 * @param <T> the type of the field as passed through the chain
 * @param <U> the type of the annotated field as passed through the chain
 */
class TypedByFieldInjectedFieldCodec<ENCBUF, DECBUF, T, U>
		extends AbstractFieldCodec<ENCBUF, DECBUF, T> {
	private final Class<? extends T> fldType;
	private final Field typedField;
	private final BidiMap<Object, Class<? extends U>> typeMap;
	private final FieldCodec<ENCBUF, DECBUF, T> chainNext;

	TypedByFieldInjectedFieldCodec(Class<? extends Packet> pktType, Field typingField,
			Class<? extends T> fldType, Field typedField,
			BidiMap<Object, Class<? extends U>> typeMap, FieldCodec<ENCBUF, DECBUF, T> chainNext) {
		super(pktType, typingField);
		this.fldType = fldType;
		this.typedField = typedField;
		this.typeMap = typeMap;
		this.chainNext = chainNext;
	}

	@Override
	public T decodeField(Packet pkt, DECBUF buf, Integer count, PacketFactory factory)
			throws IOException, PacketDecodeException {
		return chainNext.decodeField(pkt, buf, count, factory);
	}

	@SuppressWarnings("unchecked")
	@Override
	public void encodeField(ENCBUF buf, Packet pkt, T val)
			throws IOException, PacketEncodeException {
		try {
			Object typedVal = typedField.get(pkt);
			Object key;
			Class<?> cls = typedVal.getClass();
			for (;;) {
				key = typeMap.getKey(cls);
				if (key != null) {
					break;
				}
				// TODO: Cache superclass searches?
				cls = cls.getSuperclass();
				if (cls == null) {
					throw new PacketEncodeException(val + " is not a selectable type for " + field);
				}
			}
			T typeIdx;
			if (key instanceof Long) {
				typeIdx = getIntegralOfType(fldType, (Long) key);
			}
			else {
				typeIdx = (T) key;
			}
			field.set(pkt, typeIdx);
			chainNext.encodeField(buf, pkt, typeIdx);
		}
		catch (IllegalAccessException e) {
			throw new RuntimeException(e);
		}
	}
}
