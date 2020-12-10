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
package ghidra.app.plugin.core.debug.workflow;

import java.lang.annotation.*;

@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
public @interface DisassemblyInjectInfo {
	/**
	 * A list of language IDs for which this inject applies
	 * 
	 * @see DisassemblyInject#isApplicable(ghidra.trace.model.Trace)
	 * @return the language ID strings
	 */
	String[] langIDs();

	/**
	 * The "position" of this inject's invocation
	 * 
	 * <p>
	 * Injects are ordered by priority, lowest first, so that later invocations get to choose how to
	 * resolve conflicts.
	 * 
	 * @see DisassemblyInject#getPriority()
	 * @return the priority, where lower values indicate lower priority.
	 */
	int priority() default 100;
}
