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

import java.lang.annotation.*;

import ghidra.comm.packet.PacketCodec;

/**
 * An annotation to modify the radix of an encoded numeric value
 * 
 * This annotation transforms a numeric type into a {@link String}. This may have unintended
 * consequences if the {@link PacketCodec} encodes to bytes. Most string codecs will apply a radix
 * of 16 by default, so this annotation provides a way to override that default. For floating-point
 * types, the radix must be 10 or 16. All others may use a radix from 2 to 36, inclusive.
 * 
 * @see Long#toString(int, int)
 * @see Float#toString(float)
 * @see Float#toHexString(float)
 * @see Double#toString(double)
 * @see Double#toHexString(double)
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.FIELD)
public @interface WithRadix {
	/**
	 * The radix to use for string encoding
	 * 
	 * @return the radix
	 */
	int value();
}
