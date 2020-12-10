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
package ghidra.comm.packet.annot;

import java.lang.annotation.*;

import ghidra.comm.packet.annot.impl.OptionalFieldWrapperFactory;
import ghidra.comm.packet.err.PacketDecodeException;
import ghidra.comm.packet.fields.ImplementedBy;

/**
 * An annotation that indicates a given field is optional
 * 
 * This annotation is only useful for non-primitive types, because the field must be able to take a
 * {@code null} value. It can use boxed primitives, e.g., {@link Integer}. Ordinarily, attempting to
 * encode any {@code null} value will result in a {@link NullPointerException}. This annotation will
 * cause the encoder to skip the field if its value is {@code null}. During decode, an optional
 * field is given a value of {@code null} if the decode buffer is at its limit. If there is data
 * remaining in the buffer, but it is not enough data to decode the optional field, it will still
 * cause a {@link PacketDecodeException}.
 * 
 * Take care to design the protocol carefully when using optional fields. They are generally only
 * useful at the end of a packet or sub-packet.
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.FIELD)
@ImplementedBy(OptionalFieldWrapperFactory.class)
public @interface OptionalField {
	// No attributes
}
