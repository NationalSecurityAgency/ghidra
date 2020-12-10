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

import java.io.IOException;
import java.lang.reflect.Field;
import java.nio.CharBuffer;
import java.util.Deque;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.comm.packet.Packet;
import ghidra.comm.packet.PacketFactory;
import ghidra.comm.packet.annot.RepeatedField;
import ghidra.comm.packet.annot.impl.RepeatedFieldWrapperFactory;
import ghidra.comm.packet.codecs.PacketCodecInternal;
import ghidra.comm.packet.err.*;
import ghidra.comm.packet.fields.FieldCodec;
import ghidra.comm.packet.fields.FieldCodecFactory;

/**
 * The factory implementing {@link RegexSeparated}
 * 
 * @see RepeatedField
 *
 * @param <E> the type of element encoded
 */
class RegexSeparatedWrapperFactory<E>
		extends RepeatedFieldWrapperFactory<StringBuilder, CharBuffer, E> {
	private RegexSeparated annot;

	@Override
	public E decodeElement(Packet pkt, Field field, CharBuffer buf, Class<E> elemType, boolean last,
			FieldCodec<StringBuilder, CharBuffer, E> chain, PacketFactory factory)
			throws IOException, PacketDecodeException {
		if (!last) {
			/* This will be a lot like {@link String#split(String, int)} */
			Pattern pat = Pattern.compile(annot.exp());
			Matcher mat = pat.matcher(buf);
			if (!mat.find()) {
				if (!annot.optional()) {
					throw new InvalidPacketException(
						"Missing terminator token [" + annot.exp() + "]");
				}
				return super.decodeElement(pkt, field, buf, elemType, last, chain, factory);
			}
			CharBuffer part = buf.subSequence(0, mat.start());
			buf.position(buf.position() + mat.end());
			E result = super.decodeElement(pkt, field, part, elemType, last, chain, factory);
			if (part.hasRemaining()) {
				throw new InvalidPacketException(field + " did not consume buffer " + part);
			}
			return result;
		}
		return super.decodeElement(pkt, field, buf, elemType, last, chain, factory);
	}

	@Override
	public void encodeElement(StringBuilder buf, Packet pkt, Field field, E elem, boolean last,
			FieldCodec<StringBuilder, CharBuffer, E> chain)
			throws IOException, PacketEncodeException {
		super.encodeElement(buf, pkt, field, elem, last, chain);
		if (!last) {
			buf.append(annot.tok());
		}
	}

	@Override
	public <T> FieldCodec<StringBuilder, CharBuffer, T> getWrappedFieldCodecForType(
			Class<? extends Packet> pktType, Field field, Class<? extends T> fldType,
			PacketCodecInternal<?, StringBuilder, CharBuffer> codec,
			Deque<FieldCodecFactory<StringBuilder, CharBuffer>> chain) {
		annot = field.getAnnotation(RegexSeparated.class);
		if ("".equals(annot.tok())) {
			// Do nothing
		}
		else if (!Pattern.matches(annot.exp(), annot.tok())) {
			throw new PacketAnnotationException(pktType, field, annot,
				"Token does not match token expression");
		}
		if (chain.pop().getClass() != RepeatedFieldWrapperFactory.class) {
			throw new PacketAnnotationException(pktType, field, annot,
				"Must be applied directly below @" + RepeatedField.class.getSimpleName());
		}
		// No need for a whole new field codec
		// The behavior is changed by overriding decodeElement and encodeElement
		return super.getWrappedFieldCodecForType(pktType, field, fldType, codec, chain);
	}
}
