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
package ghidra.pcode.emu;

import ghidra.program.model.lang.Language;
import ghidra.util.classfinder.ExtensionPoint;

/**
 * An extension for preparing execution state for sleigh emulation
 * 
 * <p>
 * As much as possible, it's highly-recommended to use SLEIGH execution to perform any
 * modifications. This will help it remain portable to various state types.
 * 
 * <p>
 * TODO: Implement annotation-based {@link #isApplicable(Language)}?
 */
public interface PcodeStateInitializer extends ExtensionPoint {

	/**
	 * Check if this initializer applies to the given language
	 * 
	 * @param language the language to check
	 * @return true if it applies, false otherwise
	 */
	boolean isApplicable(Language language);

	/**
	 * The machine's memory state has just been initialized from a "real" target, and additional
	 * initialization is needed for SLEIGH execution
	 * 
	 * <p>
	 * There's probably not much preparation of memory
	 * 
	 * @param <T> the type of values in the machine state
	 * @param machine the newly-initialized machine
	 */
	default <T> void initializeMachine(PcodeMachine<T> machine) {
	}

	/**
	 * The thread's register state has just been initialized from a "real" target, and additional
	 * initialization is needed for SLEIGH execution
	 * 
	 * <p>
	 * Initialization generally consists of setting "virtual" registers using data from the real
	 * ones. Virtual registers are those specified in the SLEIGH, but which don't actually exist on
	 * the target processor. Often, they exist to simplify static analysis, but unfortunately cause
	 * a minor headache for dynamic execution.
	 * 
	 * @param <T> the type of values in the machine state
	 * @param thread the newly-initialized thread
	 */
	default <T> void initializeThread(PcodeThread<T> thread) {
	}
}
