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

import static java.lang.annotation.ElementType.FIELD;
import static java.lang.annotation.RetentionPolicy.RUNTIME;

import java.lang.annotation.Retention;
import java.lang.annotation.Target;

/**
 * An annotation to encode a signed integral type
 * 
 * As a design decision, the {@link StringPacketCodec} encodes its integral types as if unsigned,
 * despite Java's insistence on signed types. Applying this annotation overrides this behavior. This
 * is only meaningful when encoding an integer as a {@link String}, i.e., using a string-based codec
 * or {@link WithRadix}.
 */
@Retention(RUNTIME)
@Target(FIELD)
public @interface WithSign {
	// No attributes
}
