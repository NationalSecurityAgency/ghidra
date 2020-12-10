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
import java.util.Deque;

import ghidra.comm.packet.Packet;
import ghidra.comm.packet.annot.CountedByField;
import ghidra.comm.packet.codecs.PacketCodecInternal;
import ghidra.comm.packet.err.InvalidFieldNameException;
import ghidra.comm.packet.err.PacketAnnotationException;
import ghidra.comm.packet.fields.*;

/**
 * The factory implementing {@link CountedByField}
 *
 * @param <ENCBUF> the type of temporary buffer used to encode
 * @param <DECBUF> the type of temporary buffer used to decode
 */
public class CountedByFieldWrapperFactory<ENCBUF, DECBUF>
		extends AbstractWrapperFactory<ENCBUF, DECBUF> {
	@Override
	public <T> FieldCodec<ENCBUF, DECBUF, T> getWrappedFieldCodecForType(
			Class<? extends Packet> pktType, Field field, Class<? extends T> fldType,
			PacketCodecInternal<?, ENCBUF, DECBUF> codec,
			Deque<FieldCodecFactory<ENCBUF, DECBUF>> chain) {
		CountedByField annot = field.getAnnotation(CountedByField.class);
		if (fldType.isPrimitive()) {
			throw new PacketAnnotationException(pktType, field, annot,
				"Annotated field cannot be primitive (type is " + fldType + " in the chain)");
		}

		final Field countingField;
		try {
			countingField = pktType.getField(annot.value());
		}
		catch (NoSuchFieldException | SecurityException e) {
			throw new InvalidFieldNameException(pktType, field, annot, e.getMessage(), e);
		}
		if (!isIntegralType(countingField.getType())) {
			throw new InvalidFieldNameException(pktType, field, annot,
				"Field is not an integral type");
		}

		CountedByFieldInjectionFactory<ENCBUF, DECBUF> injected =
			new CountedByFieldInjectionFactory<>(field);
		codec.injectChain(pktType, countingField, injected, field, annot);

		FieldCodec<ENCBUF, DECBUF, T> chainNext =
			FieldCodecFactory.buildChainForType(pktType, field, fldType, codec, chain);
		return new CountedByFieldFieldCodec<>(pktType, field, countingField, chainNext);
	}
}
