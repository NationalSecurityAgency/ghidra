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
package ghidra.lifecycle;

import static java.lang.annotation.ElementType.*;

import java.lang.annotation.Target;

/**
 * An annotation for things internal to an implementation
 * 
 * For organization, some interfaces and classes exist in packages outside where they are used, and
 * method access is required. Java allows those methods to be accessed from any package. This
 * annotation is applied to public methods which should not be accessed outside the implementation.
 * 
 * A decent way to manually verify this is to ensure that any method marked with this annotation is
 * not listed in the exported interface. Generally, this means no method should have both
 * {@link Override} and {@link Internal} applied.
 */
@Target({ TYPE, FIELD, METHOD, CONSTRUCTOR, ANNOTATION_TYPE, PACKAGE })
public @interface Internal {
	// TODO: Is it possible to warn when used outside the jar?
	// TODO: Is it possible to warn when also overrides an interface method?
}
