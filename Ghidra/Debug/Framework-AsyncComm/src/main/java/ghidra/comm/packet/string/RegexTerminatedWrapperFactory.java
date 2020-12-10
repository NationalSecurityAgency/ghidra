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
import java.nio.CharBuffer;
import java.util.Deque;
import java.util.regex.Pattern;

import ghidra.comm.packet.Packet;
import ghidra.comm.packet.codecs.PacketCodecInternal;
import ghidra.comm.packet.err.PacketAnnotationException;
import ghidra.comm.packet.fields.*;

/**
 * The factory implementing {@link RegexTerminated}
 */
public class RegexTerminatedWrapperFactory
		extends AbstractWrapperFactory<StringBuilder, CharBuffer> {
	@Override
	public <T> FieldCodec<StringBuilder, CharBuffer, T> getWrappedFieldCodecForType(
			Class<? extends Packet> pktType, Field field, Class<? extends T> fldType,
			PacketCodecInternal<?, StringBuilder, CharBuffer> codec,
			Deque<FieldCodecFactory<StringBuilder, CharBuffer>> chain) {
		RegexTerminated annot = field.getAnnotation(RegexTerminated.class);
		if (!"".equals(annot.tok()) && !Pattern.matches(annot.exp(), annot.tok())) {
			throw new PacketAnnotationException(pktType, field, annot,
				"Token does not match token expression");
		}

		Field condField;
		if ("".equals(annot.cond())) {
			condField = null;
		}
		else {
			try {
				condField = Packet.getPacketField(pktType, annot.cond());
			}
			catch (NoSuchFieldException | SecurityException e) {
				throw new PacketAnnotationException(pktType, field, annot, e.getMessage(), e);
			}
		}

		FieldCodec<StringBuilder, CharBuffer, T> chainNext =
			FieldCodecFactory.buildChainForType(pktType, field, fldType, codec, chain);
		return new RegexTerminatedFieldCodec<>(pktType, field, condField, annot, codec, chainNext);
	}
}
