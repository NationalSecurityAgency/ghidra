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

import static ghidra.comm.packet.fields.AbstractFieldCodec.isIntegralType;

import java.lang.reflect.Field;
import java.util.*;
import java.util.Map.Entry;

import org.apache.commons.collections4.BidiMap;
import org.apache.commons.collections4.bidimap.DualLinkedHashBidiMap;

import ghidra.comm.packet.Packet;
import ghidra.comm.packet.annot.TypedByField;
import ghidra.comm.packet.annot.TypedByField.TypeSelect;
import ghidra.comm.packet.codecs.PacketCodecInternal;
import ghidra.comm.packet.err.InvalidFieldNameException;
import ghidra.comm.packet.err.PacketAnnotationException;
import ghidra.comm.packet.fields.*;

/**
 * The factory implementing {@link TypedByField}
 *
 * @param <ENCBUF> the type of temporary buffer used to encode
 * @param <DECBUF> the type of temporary buffer used to decode
 */
public class TypedByFieldWrapperFactory<ENCBUF, DECBUF>
		extends AbstractWrapperFactory<ENCBUF, DECBUF> {
	@SuppressWarnings("unchecked")
	@Override
	public <T> FieldCodec<ENCBUF, DECBUF, T> getWrappedFieldCodecForType(
			Class<? extends Packet> pktType, Field field, Class<? extends T> fldType,
			PacketCodecInternal<?, ENCBUF, DECBUF> codec,
			Deque<FieldCodecFactory<ENCBUF, DECBUF>> chain) {
		TypedByField annot = field.getAnnotation(TypedByField.class);
		final Field typingField;
		try {
			typingField = pktType.getField(annot.by());
		}
		catch (NoSuchFieldException | SecurityException e) {
			throw new InvalidFieldNameException(pktType, field, annot, e.getMessage(), e);
		}
		if (annot.types().length > 0 && !isIntegralType(typingField.getType())) {
			throw new InvalidFieldNameException(pktType, typingField, annot,
				"Using types attribute requires field to be an integral type");
		}

		BidiMap<Object, Class<? extends T>> typeMap = new DualLinkedHashBidiMap<>();
		if (!"".equals(annot.map())) {
			if (annot.types().length > 0) {
				throw new PacketAnnotationException(pktType, field, annot,
					"Cannot use both types and map attributes");
			}
			try {
				Field mapField = pktType.getField(annot.map());
				Map<?, Class<? extends T>> map = (Map<?, Class<? extends T>>) mapField.get(pktType);
				for (Entry<?, Class<? extends T>> ent : map.entrySet()) {
					typeMap.put(ent.getKey(), ent.getValue());
				}
			}
			catch (NoSuchFieldException | SecurityException | IllegalAccessException
					| ClassCastException e) {
				throw new InvalidFieldNameException(pktType, field, annot, e.getMessage(), e);
			}
		}
		for (TypeSelect select : annot.types()) {
			Class<?> selType = select.type();
			if (!fldType.isAssignableFrom(selType)) {
				throw new PacketAnnotationException(pktType, field, annot,
					"Selectable types must be assignable to the annotated field");
			}
			typeMap.put(select.key(), (Class<? extends T>) selType);
		}
		if (typeMap.size() == 0) {
			throw new PacketAnnotationException(pktType, field, annot,
				"There must be at least one selectable type");
		}

		TypedByFieldInjectionFactory<ENCBUF, DECBUF, ? extends T> injected =
			new TypedByFieldInjectionFactory<>(field, typeMap);
		codec.injectChain(pktType, typingField, injected, field, annot);

		Map<Class<? extends T>, FieldCodec<ENCBUF, DECBUF, ? extends T>> chainMap = new HashMap<>();
		for (Class<? extends T> selType : typeMap.values()) {
			chainMap.put(selType, FieldCodecFactory.buildChainForType(pktType, field, selType,
				codec, new LinkedList<>(chain)));
		}
		return new TypedByFieldFieldCodec<>(pktType, field, typingField, annot, typeMap, chainMap);
	}
}
