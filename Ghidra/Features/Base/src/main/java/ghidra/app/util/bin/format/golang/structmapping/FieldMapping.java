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

/**
 * Indicates that the tagged java field corresponds to a field in a Ghidra structure.
 * <p>
 * If the name of the java field does not match the Ghidra structure field name, the 
 * {@link #fieldName()} property can be used to manually specify the Ghidra field name.
 * <p>
 * The type of the tagged java field can be a java primitive, or a 
 * {@link StructureMapping structure mapped} class.
 * 
 */
@Retention(RUNTIME)
@Target(FIELD)
public @interface FieldMapping {
	String fieldName() default "";

	@SuppressWarnings("rawtypes")
	Class<? extends FieldReadFunction> readFunc() default FieldReadFunction.class;

	int length() default -1;

	/**
	 * Override the signedness the underlying numeric field.
	 * 
	 * @return
	 */
	Signedness signedness() default Signedness.Unspecified;
}
