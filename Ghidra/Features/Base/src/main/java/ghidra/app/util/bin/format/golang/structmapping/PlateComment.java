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
import static java.lang.annotation.ElementType.TYPE;
import static java.lang.annotation.RetentionPolicy.RUNTIME;

import java.lang.annotation.Retention;
import java.lang.annotation.Target;

/**
 * Indicates that the tagged class or field should have an plate comment placed
 * before each instance of the object or field, using the return value of the field's
 * getter method, or if a class, the object's "toString()" method.
 */
@Retention(RUNTIME)
@Target({ FIELD, TYPE })
public @interface PlateComment {
	/**
	 * Name of a "getter" method that's return value will be converted to a string and used
	 * as the comment
	 * 
	 * @return
	 */
	String value() default "";
}
