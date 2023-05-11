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
 * Indicates that the tagged field should have an "end-of-line" comment placed
 * at each instance of the field, using the return value of a getter method for the field
 * or the return value of a specified method as the string.
 */
@Retention(RUNTIME)
@Target({ FIELD })
public @interface EOLComment {
	/**
	 * Name of a "getter" method that's return value will be converted to a string and used
	 * as the EOL comment
	 * 
	 * @return
	 */
	String value() default "";
}
