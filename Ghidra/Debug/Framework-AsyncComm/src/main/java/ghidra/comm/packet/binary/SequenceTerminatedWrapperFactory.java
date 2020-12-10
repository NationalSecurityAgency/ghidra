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
package ghidra.comm.packet.binary;

import java.lang.reflect.Field;
import java.nio.ByteBuffer;
import java.util.Deque;

import ghidra.comm.packet.Packet;
import ghidra.comm.packet.codecs.PacketCodecInternal;
import ghidra.comm.packet.err.PacketAnnotationException;
import ghidra.comm.packet.fields.*;

/**
 * The factory implementing {@link SequenceTerminated} for {@link ByteBufferPacketCodec}
 */
public class SequenceTerminatedWrapperFactory
		extends AbstractWrapperFactory<ByteBuffer, ByteBuffer> {
	@Override
	public <T> FieldCodec<ByteBuffer, ByteBuffer, T> getWrappedFieldCodecForType(
			Class<? extends Packet> pktType, Field field, Class<? extends T> fldType,
			PacketCodecInternal<?, ByteBuffer, ByteBuffer> codec,
			Deque<FieldCodecFactory<ByteBuffer, ByteBuffer>> chain) {
		SequenceTerminated annot = field.getAnnotation(SequenceTerminated.class);
		if (annot.value().length < 1) {
			throw new PacketAnnotationException(pktType, field, annot,
				"Cannot have sequence length < 1");
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

		FieldCodec<ByteBuffer, ByteBuffer, T> chainNext =
			FieldCodecFactory.buildChainForType(pktType, field, fldType, codec, chain);
		return new SequenceTerminatedFieldCodec<>(pktType, field, annot.value(), condField,
			chainNext);
	}
}
