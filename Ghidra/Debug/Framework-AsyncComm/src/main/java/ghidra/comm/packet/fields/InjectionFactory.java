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

/**
 * A special factory used to inject a {@link FieldCodec} into another chain
 * 
 * This interface does not introduce any methods, but it ensures that only factories meant for
 * injection are in fact used for injection.
 *
 * @param <ENCBUF> the type of temporary buffer used to encode
 * @param <DECBUF> the type of temporary buffer used to decode
 */
public interface InjectionFactory<ENCBUF, DECBUF> extends WrapperFactory<ENCBUF, DECBUF> {
	// A type placeholder
}
