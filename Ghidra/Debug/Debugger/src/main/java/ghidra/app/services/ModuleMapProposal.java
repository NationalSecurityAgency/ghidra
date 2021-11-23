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
package ghidra.app.services;

import ghidra.app.services.ModuleMapProposal.ModuleMapEntry;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.listing.Program;
import ghidra.trace.model.modules.TraceModule;

/**
 * A proposed mapping of module to program
 */
public interface ModuleMapProposal extends MapProposal<TraceModule, Program, ModuleMapEntry> {

	interface ModuleMapEntry extends MapEntry<TraceModule, Program> {
		/**
		 * Get the module for this entry
		 * 
		 * @return the module
		 */
		TraceModule getModule();

		/**
		 * Get the address range of the module in the trace, as computed from the matched program's
		 * image size
		 * 
		 * @return the module range
		 */
		AddressRange getModuleRange();

		/**
		 * Set the matched program
		 * 
		 * <p>
		 * This is generally used in UIs to let the user tweak and reassign, if desired. This will
		 * also re-compute the module range based on the new program's image size.
		 * 
		 * @param program the program
		 */
		void setProgram(Program program);
	}

	/**
	 * Get the trace module of this proposal
	 * 
	 * @return the module
	 */
	TraceModule getModule();
}
