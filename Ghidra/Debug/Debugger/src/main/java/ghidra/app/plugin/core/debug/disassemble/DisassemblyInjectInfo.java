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
package ghidra.app.plugin.core.debug.disassemble;

import java.lang.annotation.*;

/**
 * Information about the applicability of a disassembly inject
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
public @interface DisassemblyInjectInfo {
	/**
	 * A language-compiler-ID pair
	 */
	public @interface CompilerInfo {
		/**
		 * The language ID, e.g., "x86:64:LE:default"
		 * 
		 * @return the language id
		 */
		String langID();

		/**
		 * The compiler ID, e.g., "gcc" or "windows"
		 * 
		 * <p>
		 * Leave as the default ("") to apply to all compilers for the language
		 * 
		 * @return the compiler id
		 */
		String compilerID() default "";
	}

	/**
	 * A list of language-compiler-ID pairs for which this inject applies
	 * 
	 * @see DisassemblyInject#isApplicable(ghidra.trace.model.Trace)
	 * @return the language-compiler-ID pairs
	 */
	CompilerInfo[] compilers();

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
