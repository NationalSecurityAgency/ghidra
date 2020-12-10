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
package ghidra.comm.packet.codecs;

import java.io.EOFException;
import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.util.Collection;
import java.util.Iterator;

import ghidra.comm.packet.Packet;
import ghidra.comm.packet.PacketFactory;
import ghidra.comm.packet.annot.RepeatedField;
import ghidra.comm.packet.err.PacketDecodeException;
import ghidra.comm.packet.err.PacketEncodeException;
import ghidra.comm.packet.fields.AbstractFieldCodec;
import ghidra.comm.packet.fields.FieldCodec;

/**
 * The {@link FieldCodec} for encoding collections
 *
 * @see {@link RepeatedField}
 *
 * @param <ENCBUF> the type of temporary buffer used to encode
 * @param <DECBUF> the type of temporary buffer used to decode
 * @param <E> the type of element encoded, as passed through the chain
 */
public class CollectionFieldCodec<ENCBUF, DECBUF, E>
		extends AbstractFieldCodec<ENCBUF, DECBUF, Collection<E>> {
	private final ElementCodec<ENCBUF, DECBUF, E> elemCodec;
	private final Class<? extends Collection<E>> colType;
	private final Class<E> elemType;
	private final FieldCodec<ENCBUF, DECBUF, E> chainNext;
	private final PacketCodecInternal<?, ENCBUF, DECBUF> codec;

	public CollectionFieldCodec(ElementCodec<ENCBUF, DECBUF, E> elemCodec,
			Class<? extends Packet> pktType, Field field, Class<? extends Collection<E>> colType,
			Class<E> elemType, PacketCodecInternal<?, ENCBUF, DECBUF> codec,
			FieldCodec<ENCBUF, DECBUF, E> chainNext) {
		super(pktType, field);
		this.elemCodec = elemCodec;
		this.colType = colType;
		this.elemType = elemType;
		this.codec = codec;
		this.chainNext = chainNext;
	}

	@Override
	public void encodeField(ENCBUF buf, Packet pkt, Collection<E> val)
			throws IOException, PacketEncodeException {
		Iterator<E> it = val.iterator();
		while (it.hasNext()) {
			elemCodec.encodeElement(buf, pkt, field, it.next(), !it.hasNext(), chainNext);
		}
	}

	@SuppressWarnings("unchecked")
	@Override
	public Collection<E> decodeField(Packet pkt, DECBUF buf, Integer count, PacketFactory factory)
			throws IOException, PacketDecodeException {
		Collection<E> result;
		try {
			// Try to use a pre-constructed collection, if present.
			result = (Collection<E>) field.get(pkt);
			if (result == null) {
				result = factory.newCollection(colType, elemType);
			}
		}
		catch (InstantiationException | IllegalAccessException | IllegalArgumentException
				| InvocationTargetException | NoSuchMethodException | SecurityException e) {
			throw new RuntimeException(e);
		}
		try {
			int i;
			for (i = 0; (count == null || i < count) &&
				codec.measureDecodeRemaining(buf) > 0; i++) {
				E elem = elemCodec.decodeElement(pkt, field, buf, elemType,
					(count != null && i == count - 1), chainNext, factory);
				if (elem == null) {
					return result;
				}
				result.add(elem);
			}
			if (count != null && i < count) {
				throw new EOFException(
					"Reached end of buffer before decoding " + count + " elements");
			}
		}
		catch (EOFException e) {
			if (count != null) {
				throw e;
			}
		}
		return result;
	}
}
