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

import ghidra.comm.packet.AbstractPacketCodec;
import ghidra.comm.packet.Packet;

/**
 * A factory of {@link FieldCodec}s that encode and decode actual packet data, i.e., the top-most
 * link in a chain
 *
 * This interface is most likely implemented by extending {@link AbstractPacketCodec}
 *
 * @param <ENCBUF> the type of temporary buffer used to encode
 * @param <DECBUF> the type of temporary buffer used to decode
 */
public interface PrimitiveFactory<ENCBUF, DECBUF> extends FieldCodecFactory<ENCBUF, DECBUF> {

	/**
	 * Request a {@link FieldCodec} for a particular type
	 * 
	 * @param pktType the packet type being registered
	 * @param field the field being registered
	 * @param fldType the type of field codec requested from this factory
	 * @return the constructed field codec
	 */
	public <T> FieldCodec<ENCBUF, DECBUF, T> getFieldCodecForType(Class<? extends Packet> pktType,
			Field field, Class<? extends T> fldType);
}
