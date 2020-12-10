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

import java.lang.reflect.Field;
import java.util.*;

import ghidra.comm.packet.Packet;
import ghidra.comm.packet.annot.TypedByLookahead;
import ghidra.comm.packet.codecs.PacketCodecInternal;
import ghidra.comm.packet.err.PacketAnnotationException;
import ghidra.comm.packet.fields.*;

/**
 * The factory implementing {@link TypedByLookahead}
 *
 * @param <ENCBUF> the type of temporary buffer used to encode
 * @param <DECBUF> the type of temporary buffer used to decode
 */
public class TypedByLookaheadWrapperFactory<ENCBUF, DECBUF>
		extends AbstractWrapperFactory<ENCBUF, DECBUF> {
	@SuppressWarnings("unchecked")
	@Override
	public <T> FieldCodec<ENCBUF, DECBUF, T> getWrappedFieldCodecForType(
			Class<? extends Packet> pktType, Field field, Class<? extends T> fldType,
			PacketCodecInternal<?, ENCBUF, DECBUF> codec,
			Deque<FieldCodecFactory<ENCBUF, DECBUF>> chain) {
		TypedByLookahead annot = field.getAnnotation(TypedByLookahead.class);
		if (annot.value().length == 0) {
			throw new PacketAnnotationException(pktType, field, annot,
				"Selectable type map cannot be empty");
		}
		List<Class<? extends T>> types = new ArrayList<>();
		for (Class<?> selType : annot.value()) {
			if (!fldType.isAssignableFrom(selType)) {
				throw new PacketAnnotationException(pktType, field, annot, "Selectable type " +
					selType + " must be assignable to the annotated field type " + fldType);
			}
			types.add((Class<? extends T>) selType);
		}
		final Map<Class<? extends T>, FieldCodec<ENCBUF, DECBUF, ? extends T>> chainMap =
			new LinkedHashMap<>();
		for (Class<? extends T> selType : types) {
			chainMap.put(selType, FieldCodecFactory.buildChainForType(pktType, field, selType,
				codec, new LinkedList<>(chain)));
		}
		return new TypedByLookaheadFieldCodec<>(pktType, field, types, codec, chainMap);
	}

	@SuppressWarnings("unchecked")
	public static <P extends Packet> List<Class<? extends P>> getSelectableOfType(Field field,
			Class<P> type) {
		List<Class<? extends P>> result = new ArrayList<>();
		TypedByLookahead annot = field.getAnnotation(TypedByLookahead.class);
		if (annot == null) {
			throw new IllegalArgumentException(
				field + " is not annotated by @" + TypedByLookahead.class.getSimpleName());
		}
		for (Class<? extends Packet> sel : annot.value()) {
			if (type.isAssignableFrom(sel)) {
				result.add((Class<? extends P>) sel);
			}
		}
		return Collections.unmodifiableList(result);
	}
}
