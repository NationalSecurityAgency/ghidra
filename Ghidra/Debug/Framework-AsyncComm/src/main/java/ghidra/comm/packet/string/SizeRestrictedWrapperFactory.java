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
package ghidra.comm.packet.string;

import java.lang.reflect.Field;
import java.util.Deque;
import java.util.LinkedList;

import ghidra.comm.packet.Packet;
import ghidra.comm.packet.codecs.PacketCodecInternal;
import ghidra.comm.packet.err.PacketAnnotationException;
import ghidra.comm.packet.fields.*;

/**
 * The factory implementing {@link SizeRestricted}
 *
 * @param <ENCBUF> the type of temporary buffer used to encode
 * @param <DECBUF> the type of temporary buffer used to decode
 */
public class SizeRestrictedWrapperFactory<ENCBUF, DECBUF>
		extends AbstractWrapperFactory<ENCBUF, DECBUF> {
	@Override
	public <T> FieldCodec<ENCBUF, DECBUF, T> getWrappedFieldCodecForType(
			Class<? extends Packet> pktType, Field field, Class<? extends T> fldType,
			PacketCodecInternal<?, ENCBUF, DECBUF> codec,
			Deque<FieldCodecFactory<ENCBUF, DECBUF>> chain) {
		SizeRestricted annot = field.getAnnotation(SizeRestricted.class);
		int fixed = annot.value();
		final int min = fixed == Integer.MIN_VALUE ? annot.min() : fixed;
		final int max = fixed == Integer.MIN_VALUE ? annot.max() : fixed;
		if (min == max && min < 1) {
			throw new PacketAnnotationException(pktType, field, annot, "Cannot have fixed len < 1");
		}

		FieldCodec<ENCBUF, DECBUF, T> chainNext = FieldCodecFactory.buildChainForType(pktType,
			field, fldType, codec, new LinkedList<>(chain));
		FieldCodec<ENCBUF, DECBUF, Character> chainChar =
			FieldCodecFactory.buildChainForType(pktType, field, Character.class, codec, chain);
		return new SizeRestrictedFieldCodec<>(pktType, field, min, max, annot, codec, chainNext,
			chainChar);
	}
}
