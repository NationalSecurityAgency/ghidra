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

import java.io.EOFException;
import java.io.IOException;
import java.lang.reflect.Field;
import java.nio.CharBuffer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.comm.packet.Packet;
import ghidra.comm.packet.PacketFactory;
import ghidra.comm.packet.codecs.PacketCodecInternal;
import ghidra.comm.packet.err.*;
import ghidra.comm.packet.fields.AbstractFieldCodec;
import ghidra.comm.packet.fields.FieldCodec;

/**
 * The {@link FieldCodec} for fields annotated by {@link RegexTerminated}
 *
 * @see RegexTerminatedWrapperFactory
 *
 * @param <T> the type of field encoded
 */
public class RegexTerminatedFieldCodec<T> extends AbstractFieldCodec<StringBuilder, CharBuffer, T> {
	private final Field condField;
	private final RegexTerminated annot;
	private final PacketCodecInternal<?, StringBuilder, CharBuffer> codec;
	private final FieldCodec<StringBuilder, CharBuffer, T> chainNext;

	public RegexTerminatedFieldCodec(Class<? extends Packet> pktType, Field field, Field condField,
			RegexTerminated annot, PacketCodecInternal<?, StringBuilder, CharBuffer> codec,
			FieldCodec<StringBuilder, CharBuffer, T> chainNext) {
		super(pktType, field);
		this.condField = condField;
		this.chainNext = chainNext;
		this.codec = codec;
		this.annot = annot;
	}

	@Override
	public T decodeField(Packet pkt, CharBuffer buf, Integer count, PacketFactory factory)
			throws IOException, PacketDecodeException {
		// TODO: This ought to decode the token through the chain....
		/** This will be a lot like {@link String#split(String, int)} */
		Pattern pat = Pattern.compile(annot.exp());
		Matcher mat = pat.matcher(buf);
		if (!mat.find()) {
			if (condField != null) {
				return chainNext.decodeField(pkt, buf, count, factory);
			}
			else if (codec.measureDecodeRemaining(buf) == 0) {
				throw new EOFException("Buffer is empty");
			}
			else {
				throw new InvalidPacketException("Missing terminator token [" + annot.exp() + "]");
			}
		}
		CharBuffer part = buf.subSequence(0, mat.start());
		if ("".equals(annot.tok())) {
			// Token is empty, so something else is expected to consume it
			buf.position(buf.position() + mat.start());
		}
		else {
			// Token is given, so consume whatever the expression matched
			buf.position(buf.position() + mat.end());
		}
		T result = chainNext.decodeField(pkt, part, count, factory);
		if (codec.measureDecodeRemaining(part) != 0) {
			throw new InvalidPacketException(field + " did not consume buffer " + part);
		}
		return result;
	}

	@Override
	public void encodeField(StringBuilder buf, Packet pkt, T val)
			throws IOException, PacketEncodeException {
		try {
			chainNext.encodeField(buf, pkt, val);
			if (condField == null || condField.get(pkt) != null) {
				buf.append(annot.tok());
			}
		}
		catch (IllegalAccessException e) {
			throw new RuntimeException(e);
		}
	}
}
