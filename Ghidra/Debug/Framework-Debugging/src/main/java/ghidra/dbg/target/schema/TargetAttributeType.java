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
package ghidra.dbg.target.schema;

import java.lang.annotation.*;

import ghidra.dbg.target.TargetObject;

/**
 * A schema annotation to describe a model attribute.
 * 
 * <p>
 * It can be used in {@link TargetObjectSchemaInfo#attributes()} or be applied to a public, possibly
 * inherited, getter method for the attribute.
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface TargetAttributeType {
	/**
	 * The name of the attribute
	 * 
	 * <p>
	 * When used in {@link TargetObjectSchemaInfo#attributes()}, the default {@code ""} matches any
	 * attribute name and should rarely, if ever, be used. When applied to a getter, the default
	 * indicates the name should be derived from the method name, by removing {@code get}, and
	 * converting from {@code CamelCase} to {@code lower_case_with_underscores}.
	 * 
	 * @return the attribute name
	 */
	String name() default "";

	/**
	 * The Java class best representing the attribute's type.
	 * 
	 * <p>
	 * When applied to a getter, {@code type} can be omitted. In that case, the getter's return type
	 * will be used to derive the attribute's schema instead.
	 * 
	 * @return the type
	 */
	Class<?> type() default TargetObject.class;

	/**
	 * True if the attribute must be set before the object exists.
	 * 
	 * @return true if required, false if optional
	 */
	boolean required() default false;

	/**
	 * True if the attribute can only be set once.
	 * 
	 * @return true if fixed/final/immutable, false if mutable
	 */
	boolean fixed() default false;

	/**
	 * Whether or not this attribute should be displayed by default
	 * 
	 * <p>
	 * This is purely a UI hint and has no other semantic consequences.
	 * 
	 * @return true if hidden, false if visible
	 */
	boolean hidden() default false;
}
