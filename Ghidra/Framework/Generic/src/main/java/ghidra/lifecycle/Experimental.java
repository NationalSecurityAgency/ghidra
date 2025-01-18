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
 * An annotation for experimental things
 * 
 * <p>
 * The items are intended to become part of the public API, but the interfaces are unstable, and
 * there's no guarantee they will ever become public.
 */
@Target({ TYPE, FIELD, METHOD, CONSTRUCTOR, ANNOTATION_TYPE, PACKAGE, PARAMETER })
public @interface Experimental {
}
