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
import java.util.Map;

import ghidra.comm.packet.annot.impl.TypedByFieldWrapperFactory;
import ghidra.comm.packet.fields.ImplementedBy;

/**
 * An annotation that indicates the type of this field is selected by the value of another
 * 
 * The annotated field is called the "typed field," and the field to which this annotation referes
 * is called the "typing field." Both of these fields must be declared in the same {@link Packet}.
 * Furthermore, the typing field must precede the typed field.
 * 
 * Example:
 * 
 * <pre>
 * public class Command extends Packet {
 * 	&#64;PacketField
 * 	public int code;
 * 
 * 	&#64;PacketField
 * 	&#64;TypedByField(by = "op", types = { &#64;TypeSelect(key = 1, type = Put.class),
 * 		&#64;TypeSelect(key = 2, type = Get.class) })
 * 	public Op op;
 * }
 * 
 * public abstract class Op extends Packet {
 * 	// Type placeholder
 * }
 * 
 * public class Put extends Op {
 * 	// Fields for "PUT" operation
 * }
 * 
 * public class Get extends Op {
 * 	// Fields for "GET" operation
 * }
 * </pre>
 * 
 * Technically, the {@code Op} placeholder class in the example is not required, but it is a useful
 * convention to avoid mistakes later. The map of typing field value to typed field type must be
 * invertible, i.e., one-to-one, since the encoding process will set the typing field value
 * according to the type present in the typed field.
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.FIELD)
@ImplementedBy(TypedByFieldWrapperFactory.class)
public @interface TypedByField {
	/**
	 * Used in the {@link TypedByField#types()} attribute to associate keys with types
	 */
	public static @interface TypeSelect {
		/**
		 * The value of the typing field that selects this type
		 * 
		 * @return the key
		 */
		long key();

		/**
		 * The type, a subclass of the typed field's declared type, to select for the given key
		 * 
		 * @return the subclass
		 */
		Class<?> type();
	}

	/**
	 * The name of the field that selects the type
	 * 
	 * @return the name of the typing field
	 */
	String by();

	/**
	 * The name of a {@code static final} {@link Map} to use as a map
	 * 
	 * This attribute may be used instead of or in combination with {@link #types()}. Technically,
	 * the map does not have to be {@code static} or {@code final}, but the map is consumed as-is at
	 * the time of packet registration.
	 * 
	 * @return
	 */
	String map() default "";

	/**
	 * An array of key-type pairs mapping typing field values to typed field types
	 * 
	 * @return the array of pairs
	 */
	TypeSelect[] types() default {};
}
