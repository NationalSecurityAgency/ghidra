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
package generic.test.rule;

import java.lang.annotation.*;

import ghidra.lifecycle.Unfinished.TODOException;

/**
 * Ignore failures due to {@link TODOException}
 * 
 * <p>
 * As a matter of practice, tests ought not to be committed into source control with this
 * annotation. Or, if they are, they should only have this for a short period. Production code ought
 * not to be throwing {@link TODOException}, anyway, but the reality is, sometimes things are
 * "production ready," despite having some unfinished components. This annotation allows tests that
 * identify those unfinished portions to remain active, but ignored. During development, the
 * developer may also apply this annotation to distinguish "real" failures from those already
 * identified as "unfinished." The annotation ought to be removed when it's time to finish those
 * components, so that failures due to unfinished code are quickly identified.
 */
@Retention(RetentionPolicy.RUNTIME)
@Target({ ElementType.METHOD, ElementType.TYPE })
public @interface IgnoreUnfinished {
}
