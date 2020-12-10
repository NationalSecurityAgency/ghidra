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

import ghidra.comm.packet.annot.impl.WithFlagWrapperFactory;
import ghidra.comm.packet.fields.ImplementedBy;
import ghidra.comm.util.BitmaskSet;

/**
 * An annotation that indicates a field is only present if a flag is (or is not) present in another
 * field
 * 
 * The annotated field is called the "controlled field," and the field to which this annotation
 * refers is called the "flags field." Both of these fields must be declared in the same
 * {@link Packet}. Furthermore, the flag field must precede the controlled field, and the flag field
 * must have type {@link BitmaskSet}.
 * 
 * The annotated field must not be a primitive type, since its flag's absence (or presence, if
 * {@link #mode} is {@link Mode#ABSENT}) will cause it to decode to {@code null}.
 * 
 * Example:
 * 
 * <pre>
 * public enum ExampleUniverse implements BitmaskUniverse {
 * 	FIRST(1 << 0), SECOND(1 << 1), THIRD(1 << 2);
 * 
 * 	private final long mask;
 * 
 * 	ExampleUniverse(long mask) {
 * 		this.mask = mask;
 * 	}
 * }
 * 
 * public class ExamplePacket extends Packet {
 * 	&#64;PacketField
 * 	&#64;BitmaskEncoded(universe = ExampleUniverse.class)
 * 	public BitmaskSet<ExampleUniverse> flags;
 * 
 * 	&#64;PacketField
 * 	&#64;WithFlag(by = "flags", flag = "FIRST")
 * 	public FirstPart first;
 * 
 * 	&#64;PacketField
 * 	&#64;WithFlag(by = "flags", flag = "SECOND")
 * 	public SecondPart second;
 * 
 * 	&#64;PacketField
 * 	&#64;WithFlag(by = "flags", flag = "THIRD")
 * 	public ThirdPart third;
 * }
 * </pre>
 * 
 * Please see {@link BitmaskSet} regarding the population count of flag constants. All flags named
 * in a {@link WithFlag} annotation referring to the same flags field must not share any bits. If
 * they do, the behavior is undefined.
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.FIELD)
@ImplementedBy(WithFlagWrapperFactory.class)
public @interface WithFlag {
	/**
	 * A mode specifying the annotated field should be decoded if the flag is present or absent
	 */
	enum Mode {
		/**
		 * Decode only if the flag is present (default)
		 */
		PRESENT,
		/**
		 * Decode only if the flag is absent
		 */
		ABSENT;
	}

	/**
	 * The name of the field containing the flags
	 * 
	 * @return the name of the flags field
	 */
	String by();

	/**
	 * The name of the enumeration constant representing the flag
	 * 
	 * @return the name of the flag
	 */
	String flag();

	/**
	 * Specifies when to decode the controlled field
	 * 
	 * @return {@link Mode#PRESENT} to decode when set, or {@link Mode#ABSENT} to decode when
	 *         cleared
	 */
	Mode mode() default Mode.PRESENT;
}
