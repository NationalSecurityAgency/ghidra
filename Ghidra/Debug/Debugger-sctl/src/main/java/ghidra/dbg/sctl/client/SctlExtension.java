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
package ghidra.dbg.sctl.client;

import static java.lang.annotation.ElementType.*;

import java.lang.annotation.*;

/**
 * Indicates that some portion of the code implements a feature not part of the standard SCTL spec
 * 
 * This is for documentation purposes only
 */
@Documented
@Retention(RetentionPolicy.CLASS)
@Target({ TYPE, FIELD, METHOD, CONSTRUCTOR, ANNOTATION_TYPE, PACKAGE })
public @interface SctlExtension {
	/**
	 * Describe the extension, very briefly
	 * 
	 * @return the description
	 */
	String value();
}
