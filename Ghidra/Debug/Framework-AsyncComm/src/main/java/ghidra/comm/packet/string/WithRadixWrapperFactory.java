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

import ghidra.comm.packet.Packet;
import ghidra.comm.packet.codecs.PacketCodecInternal;
import ghidra.comm.packet.err.PacketAnnotationException;
import ghidra.comm.packet.fields.*;

/**
 * The factory implementing {@link WithRadix}
 */
public class WithRadixWrapperFactory extends AbstractWrapperFactory<StringBuilder, CharBuffer> {
	@SuppressWarnings("unchecked")
	@Override
	public <T> FieldCodec<StringBuilder, CharBuffer, T> getWrappedFieldCodecForType(
			Class<? extends Packet> pktType, Field field, Class<? extends T> fldType,
			PacketCodecInternal<?, StringBuilder, CharBuffer> codec,
			Deque<FieldCodecFactory<StringBuilder, CharBuffer>> chain) {
		if (!(codec instanceof StringPacketCodec)) {
			return FieldCodecFactory.buildChainForType(pktType, field, fldType, codec, chain);
		}
		StringPacketCodec strCodec = (StringPacketCodec) codec;
		WithRadix annot = field.getAnnotation(WithRadix.class);
		int radix = annot.value();
		if (radix == 10) {
			// Do nothing, floats with radix 10 are allowed
		}
		else if (radix == 16) {
			// Do nothing, floats with radix 16 are allowed
		}
		else if (fldType == float.class || fldType == float[].class || fldType == double.class ||
			fldType == double[].class) {
			throw new PacketAnnotationException(pktType, field, annot,
				"Floating-point field must have radix 10 or 16");
		}
		else if (Float.class.isAssignableFrom(fldType) || Double.class.isAssignableFrom(fldType)) {
			throw new PacketAnnotationException(pktType, field, annot,
				"Floating-point field must have radix 10 or 16");
		}

		FieldCodec<StringBuilder, CharBuffer, String> chainNext =
			FieldCodecFactory.buildChainForType(pktType, field, String.class, codec, chain);
		if (fldType == byte.class || Byte.class.isAssignableFrom(fldType)) {
			return (FieldCodec<StringBuilder, CharBuffer, T>) new WithRadixByteFieldCodec(pktType,
				field, radix, strCodec, chainNext);
		}
		else if (fldType == short.class || Short.class.isAssignableFrom(fldType)) {
			return (FieldCodec<StringBuilder, CharBuffer, T>) new WithRadixShortFieldCodec(pktType,
				field, radix, strCodec, chainNext);
		}
		else if (fldType == int.class || Integer.class.isAssignableFrom(fldType)) {
			return (FieldCodec<StringBuilder, CharBuffer, T>) new WithRadixIntegerFieldCodec(
				pktType, field, radix, strCodec, chainNext);
		}
		else if (fldType == long.class || Long.class.isAssignableFrom(fldType)) {
			return (FieldCodec<StringBuilder, CharBuffer, T>) new WithRadixLongFieldCodec(pktType,
				field, radix, strCodec, chainNext);
		}
		else if (fldType == float.class || Float.class.isAssignableFrom(fldType)) {
			return (FieldCodec<StringBuilder, CharBuffer, T>) new WithRadixFloatFieldCodec(pktType,
				field, radix, strCodec, chainNext);
		}
		else if (fldType == double.class || Double.class.isAssignableFrom(fldType)) {
			return (FieldCodec<StringBuilder, CharBuffer, T>) new WithRadixDoubleFieldCodec(pktType,
				field, radix, strCodec, chainNext);
		}
		return null;
	}
}
