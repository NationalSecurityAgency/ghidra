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
	/**
	 * Overrides the default logic used to add the marked field to the structure.
	 * 
	 * @return {@link FieldOutputFunction} class that implements custom logic
	 */
	@SuppressWarnings("rawtypes")
	Class<? extends FieldOutputFunction> fieldOutputFunc() default FieldOutputFunction.class;

	/**
	 * Optional ordinal of the marked field in the structure that will be created.
	 * <p>
	 * If unset, the order of the marked fields in the java class would be preserved.
	 *   
	 * @return integer field ordinal, or if unset, the native java field order
	 */
	int ordinal() default -1;

	/**
	 * Optional offset for the marked field to be added at.
	 * <p>
	 * If the structure under construction is smaller than the specified offset, padding will be
	 * added to the structure.  If the structure is already larger than the specified offset,
	 * an error will occur.
	 *  
	 * @return integer offset for the marked field, or if unset, the next location in the
	 * structure will be used
	 */
	int offset() default -1;

	/**
	 * Specifies the name of a Ghidra {@link DataType} that will be used for this field when
	 * creating a Ghidra structure.
	 * <p>
	 * If unset, the type of the java field will be consulted to pick a Ghidra {@link DataType}
	 * for the structure field.
	 * 
	 * @return name of the data type to use for this field, or if unset, the java field's type
	 * will be used to pick the data type
	 */
	String dataTypeName() default "";

	/**
	 * Marks this field as variable length, which will cause the Ghidra structure containing
	 * this field to have a "_NN" name suffix that specifies the length of this instance.
	 * 
	 * @return boolean true if the marked field's length varies between instances of the same
	 * structure, false if it is a fixed length field
	 */
	boolean isVariableLength() default false;

	/**
	 * Specifies a method that will return a Ghidra {@link DataType} that should be used for this
	 * field when creating a Ghidra structure.
	 * 
	 * @return optional name of getter method that will return a Ghidra {@link DataType}
	 */
	String getter() default "";

}
