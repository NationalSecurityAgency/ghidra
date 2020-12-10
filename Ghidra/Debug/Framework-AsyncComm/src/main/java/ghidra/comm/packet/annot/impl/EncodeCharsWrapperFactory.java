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
import java.nio.charset.*;
import java.util.Deque;

import ghidra.comm.packet.Packet;
import ghidra.comm.packet.annot.EncodeChars;
import ghidra.comm.packet.codecs.PacketCodecInternal;
import ghidra.comm.packet.err.PacketAnnotationException;
import ghidra.comm.packet.fields.*;

/**
 * The factory implementing {@link EncodeChars}
 *
 * @param <ENCBUF> the type of temporary buffer used to encode
 * @param <DECBUF> the type of temporary buffer used to decode
 */
public class EncodeCharsWrapperFactory<ENCBUF, DECBUF>
		extends AbstractWrapperFactory<ENCBUF, DECBUF> {
	@SuppressWarnings("unchecked")
	@Override
	public <T> FieldCodec<ENCBUF, DECBUF, T> getWrappedFieldCodecForType(
			Class<? extends Packet> pktType, Field field, Class<? extends T> fldType,
			PacketCodecInternal<?, ENCBUF, DECBUF> codec,
			Deque<FieldCodecFactory<ENCBUF, DECBUF>> chain) {
		EncodeChars annot = field.getAnnotation(EncodeChars.class);

		final Charset charset;
		try {
			charset = Charset.forName(annot.value());
		}
		catch (IllegalCharsetNameException | UnsupportedCharsetException e) {
			throw new PacketAnnotationException(pktType, field, annot,
				"Cannot find charset " + annot.value(), e);
		}

		if (CharSequence.class.isAssignableFrom(fldType)) {
			FieldCodec<ENCBUF, DECBUF, byte[]> chainNext =
				FieldCodecFactory.buildChainForType(pktType, field, byte[].class, codec, chain);
			return (FieldCodec<ENCBUF, DECBUF, T>) new EncodeCharsFieldCodec<>(pktType, field,
				charset, codec, chainNext);
		}
		return null;
	}
}
