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
package ghidra.comm.packet.fields;

import java.lang.reflect.Field;
import java.util.Deque;

import ghidra.comm.packet.AbstractPacketCodec;
import ghidra.comm.packet.Packet;
import ghidra.comm.packet.codecs.PacketCodecInternal;
import ghidra.comm.packet.err.PacketFieldDeclarationException;

/**
 * A factory of {@link FieldCodec}s
 * 
 * More than likely, this interface is implemented by extending {@link AbstractPacketCodec} or
 * {@link AbstractWrapperFactory}. During packet registration, these are stored in lists called
 * "chains." Each factory may request a {@link FieldCodec} for a particular type from the next
 * factory up the chain. If each factory can provide one, then the type of the field is successfully
 * linked to the primitive field codec, which encodes or decodes the value in the buffer.
 * 
 * @see AbstractPacketCodec
 *
 * @param <ENCBUF> the type of temporary buffer used to encode
 * @param <DECBUF> the type of temporary buffer used to decode
 */
public interface FieldCodecFactory<ENCBUF, DECBUF> {

	/**
	 * The method used by packet codecs and wrapper factories to obtain a field codec
	 * 
	 * For packet codecs, this obtains the field codec at the bottom of the chain, which may be the
	 * only link in the chain. For wrapper factories, this obtains the field codec from the next
	 * factory up the chain. The last (top-most) field codec will be the primitive one. In summary,
	 * this takes a chain of field codec factories, given as a {@link Deque}, and recursively
	 * constructs a chain of field codecs. The returned {@link FieldCodec} keeps a reference to the
	 * next field codec up the resolved chain, if applicable.
	 * 
	 * @see #getFieldCodecForType(Class, Field, Class)
	 * @see WrapperFactory#getWrappedFieldCodecForType(Class, Field, Class, PacketCodecInternal,
	 *      Deque)
	 * 
	 * @param pktType the packet type being registered
	 * @param field the field being registered
	 * @param fldType the type requested from the next factory down the chain
	 * @param codec the packet codec requesting the field codec
	 * @param chain the factories remaining in the chain, the next one up being at index 0
	 * @return the constructed field codec chain
	 */
	public static <ENCBUF, DECBUF, T> FieldCodec<ENCBUF, DECBUF, T> buildChainForType(
			Class<? extends Packet> pktType, Field field, Class<? extends T> fldType,
			PacketCodecInternal<?, ENCBUF, DECBUF> codec,
			Deque<FieldCodecFactory<ENCBUF, DECBUF>> chain) {
		FieldCodecFactory<ENCBUF, DECBUF> next = chain.pop();
		FieldCodec<ENCBUF, DECBUF, T> result = null;
		if (next instanceof WrapperFactory) {
			WrapperFactory<ENCBUF, DECBUF> wrap = (WrapperFactory<ENCBUF, DECBUF>) next;
			result = wrap.getWrappedFieldCodecForType(pktType, field, fldType, codec, chain);
		}
		else if (!chain.isEmpty()) {
			throw new AssertionError("INTERNAL: Chain is not empty, yet");
		}
		else if (next instanceof PrimitiveFactory) {
			PrimitiveFactory<ENCBUF, DECBUF> primitive = (PrimitiveFactory<ENCBUF, DECBUF>) next;
			result = primitive.getFieldCodecForType(pktType, field, fldType);
		}
		if (result == null) {
			throw new PacketFieldDeclarationException(pktType, field,
				next + " cannot provide encoder for " + fldType);
		}
		return result;
	}

	/**
	 * If this factory only supports a certain decode buffer class, return it
	 * 
	 * The default implementation provided by {@link AbstractFieldCodecFactory} examines the type
	 * variables and returns the appropriate value automatically.
	 * 
	 * @return the supported decode buffer class, or {@code null} if universal
	 */
	public Class<? extends DECBUF> getDecodingBufferClass();

	/**
	 * If this factory only supports a certain encode buffer class, return it
	 * 
	 * The default implementation provided by {@link AbstractFieldCodecFactory} examines the type
	 * variables and returns the appropriate value automatically.
	 * 
	 * @return the supported encode buffer class, or {@code null} if universal
	 */
	public Class<? extends ENCBUF> getEncodingBufferClass();
}
