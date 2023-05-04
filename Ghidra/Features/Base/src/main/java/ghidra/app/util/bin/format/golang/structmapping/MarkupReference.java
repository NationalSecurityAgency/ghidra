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

import ghidra.program.model.address.Address;

/**
 * Indicates that the <b>target</b> of the tagged field should be decorated in Ghidra as
 * receiving a data reference from the location of the field.
 * <p>
 * The tagged field must have a 'getter' method that returns something that can be converted
 * to an {@link Address}.  This can either be an actual Address return value, or a return value
 * that is an instance of an object that can be mapped to an address in the program.
 * <p>
 * The name of the 'getter' method can be overridden by providing a string that directly specifies
 * the getter method name, or its sans-"get" name (eg. for getter method getXyz(), "getXyz", or
 * "Xyz" are equally valid)
 */
@Retention(RUNTIME)
@Target(FIELD)
public @interface MarkupReference {
	String value() default "";
}
