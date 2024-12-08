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
package ghidra.app.plugin.core.debug.gui.action;

import docking.ActionContext;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.trace.model.program.TraceProgramView;

public interface DebuggerProgramLocationActionContext extends ActionContext {
	default TraceProgramView getProgram() {
		ProgramLocation location = getLocation();
		return location == null ? null : (TraceProgramView) location.getProgram();
	}

	ProgramLocation getLocation();

	boolean hasSelection();

	ProgramSelection getSelection();

	boolean hasHighlight();

	ProgramSelection getHighlight();

	Address getAddress();

	CodeUnit getCodeUnit();
}
