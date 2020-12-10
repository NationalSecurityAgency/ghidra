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

import ghidra.comm.packet.annot.impl.SizedByFieldWrapperFactory;
import ghidra.comm.packet.fields.ImplementedBy;

/**
 * An annotation that indicate the encoded length of this field is given by the value of another
 * 
 * The annotated field is called the "sized field," and the field to which this annotation refers is
 * called the "sizing field." Both of these fields must be declared in the same {@link Packet}.
 * Furthermore, the sizing field must precede the sized field.
 * 
 * Example:
 * 
 * <pre>
 * &#64;PacketField
 * public int length;
 * 
 * &#64;PacketField
 * &#64;SizedByField("length");
 * public String name;
 * </pre>
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.FIELD)
@ImplementedBy(SizedByFieldWrapperFactory.class)
public @interface SizedByField {
	/**
	 * The amount of extra length to give when decoding the annotated field
	 * 
	 * For example, if {@code name} in the example above were encoded to 6 bytes, and {@code adjust}
	 * were set to 2, then {@code length} would be set to 4.
	 */
	int adjust() default 0;

	/**
	 * The name of the field that gives the length
	 * 
	 * @return the name of the sizing field
	 */
	String value();
}
