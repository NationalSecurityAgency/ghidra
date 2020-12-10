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

import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.Type;
import java.util.Collection;
import java.util.Deque;

import org.apache.commons.lang3.reflect.TypeUtils;

import ghidra.comm.packet.Packet;
import ghidra.comm.packet.PacketFactory;
import ghidra.comm.packet.annot.RepeatedField;
import ghidra.comm.packet.codecs.*;
import ghidra.comm.packet.err.*;
import ghidra.comm.packet.fields.*;

/**
 * The factory implementing {@link RepeatedField}
 * 
 * @see ArrayFieldCodec
 * @see CollectionFieldCodec
 *
 * @param <ENCBUF> the type of temporary buffer used to encode
 * @param <DECBUF> the type of temporary buffer used to decode
 * @param <E> the type of element encoded, as passed through the chain
 */
public class RepeatedFieldWrapperFactory<ENCBUF, DECBUF, E>
		extends AbstractWrapperFactory<ENCBUF, DECBUF> implements ElementCodec<ENCBUF, DECBUF, E> {
	@SuppressWarnings("unchecked")
	@Override
	public <T> FieldCodec<ENCBUF, DECBUF, T> getWrappedFieldCodecForType(
			Class<? extends Packet> pktType, Field field, Class<? extends T> fldType,
			PacketCodecInternal<?, ENCBUF, DECBUF> codec,
			Deque<FieldCodecFactory<ENCBUF, DECBUF>> chain) {
		RepeatedField annot = field.getAnnotation(RepeatedField.class);
		if (Collection.class.isAssignableFrom(fldType)) {
			final Class<? extends Collection<E>> colType;
			if (annot.container() == RepeatedField.DefaultContainer.class) {
				colType = (Class<? extends Collection<E>>) fldType;
			}
			else if (!fldType.isAssignableFrom(annot.container())) {
				throw new PacketAnnotationException(pktType, field, annot, "Container type " +
					annot.container() + " must be assignable to the annotated field");
			}
			else {
				colType = (Class<? extends Collection<E>>) annot.container();
			}
			final Type elemType;
			if (annot.elements() == RepeatedField.DefaultElements.class) {
				elemType = getTypeParameterValue(field.getGenericType(), Collection.class, "E");
			}
			else {
				elemType = annot.elements();
			}
			if (elemType == null) {
				throw new PacketAnnotationException(pktType, field, annot,
					"Could not determine type of elements");
			}
			Class<E> elemRaw = (Class<E>) TypeUtils.getRawType(elemType, Object.class);
			FieldCodec<ENCBUF, DECBUF, E> chainNext =
				FieldCodecFactory.buildChainForType(pktType, field, elemRaw, codec, chain);
			return (FieldCodec<ENCBUF, DECBUF, T>) new CollectionFieldCodec<>(this, pktType, field,
				colType, elemRaw, codec, chainNext);
		}
		else if (fldType.isArray()) {
			Class<E> elemType = (Class<E>) fldType.getComponentType();
			if (annot.container() != RepeatedField.DefaultContainer.class) {
				throw new PacketAnnotationException(pktType, field, annot,
					"Cannot specify container type on array");
			}
			if (annot.elements() != RepeatedField.DefaultElements.class) {
				throw new PacketAnnotationException(pktType, field, annot,
					"Cannot specify element type on array");
			}

			FieldCodec<ENCBUF, DECBUF, E> chainNext =
				FieldCodecFactory.buildChainForType(pktType, field, elemType, codec, chain);
			return (FieldCodec<ENCBUF, DECBUF, T>) new ArrayFieldCodec<>(this, pktType, field,
				elemType, codec, chainNext);
		}
		return null;
	}

	@Override
	public E decodeElement(Packet pkt, Field field, DECBUF buf, Class<E> elemType, boolean last,
			FieldCodec<ENCBUF, DECBUF, E> chainNext, PacketFactory factory)
			throws IOException, PacketDecodeException {
		return chainNext.decodeField(pkt, buf, null, factory);
	}

	@Override
	public void encodeElement(ENCBUF buf, Packet pkt, Field field, E elem, boolean last,
			FieldCodec<ENCBUF, DECBUF, E> chainNext) throws IOException, PacketEncodeException {
		chainNext.encodeField(buf, pkt, elem);
	}
}
