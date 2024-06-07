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
package ghidra.app.util.bin.format.golang.structmapping;

import static java.lang.annotation.ElementType.*;
import static java.lang.annotation.RetentionPolicy.*;

import java.lang.annotation.Retention;
import java.lang.annotation.Target;

/**
 * Indicates that the tagged java field corresponds to a field in a Ghidra structure.
 * <p>
 * If the name of the java field does not match the Ghidra structure field name, the 
 * {@link #fieldName()} property can be used to manually specify the Ghidra field name.
 * <p>
 * The type of the tagged java field can be a java primitive, or a 
 * {@link StructureMapping structure mapped} class.
 * <p>
 * Supported java primitive types:
 * <ul>
 * 	<li>long, int, short, byte
 * 	<li>char
 * </ul>
 * 
 */
@Retention(RUNTIME)
@Target(FIELD)
public @interface FieldMapping {
	/**
	 * Overrides the field name that is matched in the structure.
	 * <p>
	 * Can be a single name, or a list of names that will be used to find the structure
	 * field.  The name is case-insensitive.
	 * 
	 * @return name, or list of names (case insensitive), of the structure field to map,
	 * or unset to use the java field's name
	 */
	String[] fieldName() default "";

	/**
	 * Marks this field as optional.
	 * <p>
	 * When marked optional, if a binding between the tagged java field and a structure field is
	 * not successfully found, this field definition will be skipped.
	 * 
	 * @return boolean flag, if true this field is optional, if false or unset, the field is 
	 * required
	 */
	boolean optional() default false;

	/**
	 * Specifies the name of a setter method that will be used to assign the deserialized value
	 * to the java field.
	 * <p>
	 * If unset, a "void setFieldname(field_type)" method will be searched for.
	 * <p>
	 * If no setter method is present, the field's value will be directly assigned.
	 * 
	 * @return optional name of a setter method
	 */
	String setter() default "";

	/**
	 * Optional function that will deserialize the tagged field.
	 * 
	 * @return {@link FieldReadFunction}
	 */
	@SuppressWarnings("rawtypes")
	Class<? extends FieldReadFunction> readFunc() default FieldReadFunction.class;

	/**
	 * Allows override the length of the structure field 
	 * 
	 * @return length of the structure field, or unset to use the field's data type
	 */
	int length() default -1;

	/**
	 * Override the signedness of the underlying numeric field.
	 * 
	 * @return {@link Signedness} enum, or unset to use the data type's normal signedness
	 */
	Signedness signedness() default Signedness.Unspecified;
}
