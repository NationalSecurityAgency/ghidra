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
import java.lang.reflect.Array;
import java.lang.reflect.Field;
import java.util.ArrayList;

import ghidra.comm.packet.Packet;
import ghidra.comm.packet.PacketFactory;
import ghidra.comm.packet.annot.RepeatedField;
import ghidra.comm.packet.err.PacketDecodeException;
import ghidra.comm.packet.err.PacketEncodeException;
import ghidra.comm.packet.fields.AbstractFieldCodec;
import ghidra.comm.packet.fields.FieldCodec;

/**
 * The {@link FieldCodec} for encoding arrays
 * 
 * @see {@link RepeatedField}
 *
 * @param <ENCBUF> the type of temporary buffer used to encode
 * @param <DECBUF> the type of temporary buffer used to decode
 * @param <E> the type of element encoded, as passed through the chain
 */
public class ArrayFieldCodec<ENCBUF, DECBUF, E> extends AbstractFieldCodec<ENCBUF, DECBUF, Object> {
	private final ElementCodec<ENCBUF, DECBUF, E> elemCodec;
	private final Class<E> elemType;
	private final FieldCodec<ENCBUF, DECBUF, E> chainNext;
	private final PacketCodecInternal<?, ENCBUF, DECBUF> codec;

	public ArrayFieldCodec(ElementCodec<ENCBUF, DECBUF, E> elemCodec,
			Class<? extends Packet> pktType, Field field, Class<E> elemType,
			PacketCodecInternal<?, ENCBUF, DECBUF> codec, FieldCodec<ENCBUF, DECBUF, E> chainNext) {
		super(pktType, field);
		this.elemCodec = elemCodec;
		this.elemType = elemType;
		this.codec = codec;
		this.chainNext = chainNext;
	}

	@Override
	public void encodeField(ENCBUF buf, Packet pkt, Object arr)
			throws IOException, PacketEncodeException {
		int len = Array.getLength(arr);
		for (int i = 0; i < len; i++) {
			@SuppressWarnings("unchecked")
			E elem = (E) Array.get(arr, i);
			elemCodec.encodeElement(buf, pkt, field, elem, i == len - 1, chainNext);
		}
	}

	@Override
	public Object decodeField(Packet pkt, DECBUF buf, Integer count, PacketFactory factory)
			throws IOException, PacketDecodeException {
		if (count != null) {
			Object arr = factory.newArray(elemType, count.intValue());
			for (int i = 0; i < count; i++) {
				Array.set(arr, i, elemCodec.decodeElement(pkt, field, buf, elemType, i == count - 1,
					chainNext, factory));
			}
			return arr;
		}
		ArrayList<E> result = new ArrayList<>();
		try {
			while (codec.measureDecodeRemaining(buf) > 0) {
				result.add(
					elemCodec.decodeElement(pkt, field, buf, elemType, false, chainNext, factory));
			}
		}
		catch (EOFException e) {
			// finished
		}
		Object arr = factory.newArray(elemType, result.size());
		for (int i = 0; i < result.size(); i++) {
			Array.set(arr, i, result.get(i));
		}
		return arr;
	}
}
