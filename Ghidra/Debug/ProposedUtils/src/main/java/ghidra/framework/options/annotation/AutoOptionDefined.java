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
package ghidra.framework.options.annotation;

import java.beans.PropertyEditor;
import java.lang.annotation.*;

import ghidra.framework.options.OptionType;

@Target(ElementType.FIELD)
@Retention(RetentionPolicy.RUNTIME)
public @interface AutoOptionDefined {
	String[] category() default {};

	OptionType type() default OptionType.NO_TYPE;

	String[] name();

	HelpInfo help() default @HelpInfo(topic = {});

	String description();

	Class<? extends PropertyEditor> editor() default PropertyEditor.class;
}
