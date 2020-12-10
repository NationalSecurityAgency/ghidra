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

import static ghidra.comm.packet.codecs.PacketCodecInternal.getTypeParameterValue;

import java.lang.reflect.Field;
import java.lang.reflect.Type;
import java.util.Deque;

import org.apache.commons.lang3.reflect.TypeUtils;

import ghidra.comm.packet.Packet;
import ghidra.comm.packet.annot.BitmaskEncoded;
import ghidra.comm.packet.codecs.PacketCodecInternal;
import ghidra.comm.packet.err.PacketAnnotationException;
import ghidra.comm.packet.fields.*;
import ghidra.comm.util.BitmaskSet;
import ghidra.comm.util.BitmaskUniverse;

/**
 * The factory implementing {@link BitmaskEncoded}
 *
 * @param <ENCBUF> the type of temporary buffer used to encode
 * @param <DECBUF> the type of temporary buffer used to decode
 */
public class BitmaskEncodedFieldCodecWrapperFactory<ENCBUF, DECBUF>
		extends AbstractWrapperFactory<ENCBUF, DECBUF> {

	@SuppressWarnings("unchecked")
	public static <E extends Enum<E> & BitmaskUniverse> Class<E> getUniverse(
			Class<? extends Packet> pktType, Field field) {
		BitmaskEncoded annot = field.getAnnotation(BitmaskEncoded.class);
		final Type universeType;
		if (annot.universe() == BitmaskEncoded.DefaultUniverse.class) {
			universeType = getTypeParameterValue(field.getGenericType(), BitmaskSet.class, "E");
		}
		else {
			universeType = annot.universe();
		}
		if (universeType == null) {
			throw new PacketAnnotationException(pktType, field, annot,
				"Could not determine the universe");
		}
		return (Class<E>) TypeUtils.getRawType(universeType, Object.class);
	}

	@SuppressWarnings("unchecked")
	@Override
	public <T> FieldCodec<ENCBUF, DECBUF, T> getWrappedFieldCodecForType(
			Class<? extends Packet> pktType, Field field, Class<? extends T> fldType,
			PacketCodecInternal<?, ENCBUF, DECBUF> codec,
			Deque<FieldCodecFactory<ENCBUF, DECBUF>> chain) {
		BitmaskEncoded annot = field.getAnnotation(BitmaskEncoded.class);
		if (!BitmaskSet.class.isAssignableFrom(fldType)) {
			throw new PacketAnnotationException(pktType, field, annot,
				"Annotated field must be a BitmaskSet. Got " + fldType + " in the chain.");
		}

		Class<?> universe = getUniverse(pktType, field);

		Class<? extends Number> encType = annot.type();
		if (encType == Byte.class) {
			// Good
		}
		else if (encType == Short.class) {
			// Good
		}
		else if (encType == Integer.class) {
			// Good
		}
		else if (encType == Long.class) {
			// Good
		}
		else {
			throw new PacketAnnotationException(pktType, field, annot,
				"encoding type must be one of Byte, Short, Integer, or Long");
		}
		FieldCodec<ENCBUF, DECBUF, Number> chainNext =
			FieldCodecFactory.buildChainForType(pktType, field, encType, codec, chain);
		return (FieldCodec<ENCBUF, DECBUF, T>) new BitmaskEncodedFieldCodec<>(pktType, field,
			universe, encType, chainNext);
	}
}
