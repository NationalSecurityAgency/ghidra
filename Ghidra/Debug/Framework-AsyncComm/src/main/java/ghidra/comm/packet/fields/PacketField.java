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

import java.lang.annotation.*;

/**
 * An annotation applied to all fields that will be serialized into a {@link Packet}
 * 
 * This annotation is only meaningful when applied to classes extending {@link Packet}. By
 * convention, it is the first packet-related annotation applied to the field. In this way, the
 * {@link PacketField} annotation stands for the encoded field, while the field declaration stands
 * for the decoded field. The annotations between represent any applicable transformations applied
 * to encode or decode the field.
 * 
 * If required, the attributes of this annotation can re-order the encoding of the fields.
 * Otherwise, the fields are encoded in declaration order. Note, that since JDK6, the method
 * {@link Class#getDeclaredFields()} has returned the fields in declaration order, despite the
 * documentation saying otherwise. This may not be the case for other Java implementations, e.g.,
 * Dalvik. To be certain about field order, specify it explicitly.
 * 
 * For a {@link Packet} that extends another {@link Packet}, the two sets of declared fields must
 * have an explicit order. It is usually sufficient to declare the first field in the extended
 * packet as coming {@link #after()} the last of the base packet.
 * 
 * Example:
 * 
 * <pre>
 * public class Person extends Packet {
 * 	&#64;PacketField
 * 	&#64;NullTerminated
 * 	public String name;
 * 
 * 	&#64;PacketField
 * 	&#64;NullTerminated
 * 	public String address;
 * }
 * 
 * public class Employee extends Person {
 * 	&#64;PacketField(after = "address")
 * 	public int dateOfHire;
 * }
 * </pre>
 */

@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.FIELD)
public @interface PacketField {
	/**
	 * The names of fields, all of which this field must precede
	 * 
	 * @return the array of names
	 */
	String[] before() default {};

	/**
	 * The names of fields, all of which the field must follow
	 * 
	 * @return the array of names
	 */
	String[] after() default {};
}
