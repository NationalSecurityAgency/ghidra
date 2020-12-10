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

import static ghidra.comm.packet.codecs.PacketCodecInternal.getTypeParameterRaw;

/**
 * A partial implementation of {@link FieldCodecFactory}.
 * 
 * This provides default implementations for {@link #getEncodingBufferClass()} and
 * {@link #getDecodingBufferClass()} using reflection of the type parameters.
 *
 * @param <ENCBUF> the type of temporary buffer used to encode
 * @param <DECBUF> the type of temporary buffer used to decode
 */
public abstract class AbstractFieldCodecFactory<ENCBUF, DECBUF>
		implements FieldCodecFactory<ENCBUF, DECBUF> {
	@SuppressWarnings("unchecked")
	@Override
	public Class<? extends ENCBUF> getEncodingBufferClass() {
		Class<? extends ENCBUF> type =
			(Class<? extends ENCBUF>) getTypeParameterRaw(this.getClass(),
				AbstractFieldCodecFactory.class, "ENCBUF");
		if (type == null) {
			return (Class<? extends ENCBUF>) Object.class;
		}
		return type;
	}

	@SuppressWarnings("unchecked")
	@Override
	public Class<? extends DECBUF> getDecodingBufferClass() {
		Class<? extends DECBUF> type =
			(Class<? extends DECBUF>) getTypeParameterRaw(this.getClass(),
				AbstractFieldCodecFactory.class, "DECBUF");
		if (type == null) {
			return (Class<? extends DECBUF>) Object.class;
		}
		return type;
	}
}
