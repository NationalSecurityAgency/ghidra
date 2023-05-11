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

import static java.lang.annotation.ElementType.FIELD;
import static java.lang.annotation.RetentionPolicy.RUNTIME;

import java.lang.annotation.Retention;
import java.lang.annotation.Target;

import ghidra.program.model.data.DataType;

/**
 * Indicates that the tagged java field is to be included when constructing a variable length
 * Ghidra structure data type.
 * <p>
 * Using this annotation on a field indicates that the containing Ghidra structure has 
 * variable length fields, and the containing class must implement the 
 * {@link StructureReader} interface to allow deserialization of instances of the containing class.
 */
@Retention(RUNTIME)
@Target(FIELD)
public @interface FieldOutput {
	Class<? extends FieldOutputFunction> fieldOutputFunc() default FieldOutputFunction.class;

	int ordinal() default -1;

	int offset() default -1;

	/**
	 * Specifies the name of a Ghidra {@link DataType} that will be used for this field when
	 * creating a Ghidra structure.
	 * 
	 * @return
	 */
	String dataTypeName() default "";

	/**
	 * Marks this field as variable length, which will cause the Ghidra structure containing
	 * this field to have a "_NN" name suffix that specifies the length of this instance.
	 * 
	 * @return
	 */
	boolean isVariableLength() default false;

	/**
	 * Specifies a method that will return a Ghidra {@link DataType} that should be used for this
	 * field when creating a Ghidra structure.
	 * 
	 * @return
	 */
	String getter() default "";

}
