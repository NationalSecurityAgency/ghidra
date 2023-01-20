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
package ghidra.dbg;

import ghidra.dbg.util.ConfigurableFactory;
import ghidra.program.model.listing.Program;
import ghidra.util.classfinder.ExtensionPoint;

/**
 * A factory for a debugger model
 * 
 * <p>
 * This provides a discoverable means of configuring and creating a debug model.
 */
public interface DebuggerModelFactory
		extends ExtensionPoint, ConfigurableFactory<DebuggerObjectModel> {

	/**
	 * Get the priority for selecting this factory by default for the given program
	 * 
	 * <p>
	 * A default factory is selected when the current factory and the last successful factory are
	 * incompatible with the current program, or if this is the very first time connecting. Of those
	 * factories compatible with the current program, the one with the highest priority (larger
	 * numerical value) is selected. If none are compatible, then the current selection is left as
	 * is.
	 * 
	 * <p>
	 * Note that negative priorities imply the factory is not compatible with the given program or
	 * local system.
	 * 
	 * @param program the current program, or null
	 * @return the priority, higher values mean higher priority
	 */
	default int getPriority(Program program) {
		return 0;
	}

	/**
	 * Check if this factory is compatible with the local system and given program.
	 * 
	 * <p>
	 * <b>WARNING:</b> Implementations should not likely override this method. If one does, it must
	 * behave in the same manner as given in this default implementation: If
	 * {@link #getPriority(Program)} would return a non-negative result for the program, then this
	 * factory is compatible with that program. If negative, this factory is not compatible.
	 * 
	 * @param program the current program, or null
	 * @return true if compatible
	 */
	default boolean isCompatible(Program program) {
		return getPriority(program) >= 0;
	}
}
