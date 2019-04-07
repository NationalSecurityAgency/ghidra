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
package ghidra.app.plugin.core.diff;

import java.awt.Component;
import java.net.URL;

import ghidra.app.services.ProgramManager;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;

/**
 * A stubbed {@link ProgramManager} that used the 'second program' at the current program.  This
 * is used to secondary views in order to install the right program.
 */
public class DiffProgramManager implements ProgramManager {
	ProgramDiffPlugin programDiffPlugin;

	public DiffProgramManager(ProgramDiffPlugin programDiffPlugin) {
		this.programDiffPlugin = programDiffPlugin;
	}

	@Override
	public Program getCurrentProgram() {
		return programDiffPlugin.getSecondProgram();
	}

	@Override
	public boolean closeOtherPrograms(boolean ignoreChanges) {
		return false;
	}

	@Override
	public boolean closeAllPrograms(boolean ignoreChanges) {
		return false;
	}

	@Override
	public boolean closeProgram() {
		return false;
	}

	@Override
	public boolean closeProgram(Program program, boolean ignoreChanges) {
		return false;
	}

	@Override
	public Program[] getAllOpenPrograms() {
		return null;
	}

	@Override
	public Program getProgram(Address addr) {
		return null;
	}

	@Override
	public boolean isVisible(Program program) {
		return false;
	}

	@Override
	public Program openProgram(URL ghidraURL, int state) {
		return null;
	}

	@Override
	public Program openProgram(DomainFile domainFile) {
		return null;
	}

	@Override
	public Program openProgram(DomainFile df, int version) {
		return null;
	}

	@Override
	public Program openProgram(DomainFile domainFile, Component dialogParent) {
		return null;
	}

	@Override
	public Program openProgram(DomainFile domainFile, int version, int state) {
		return null;
	}

	@Override
	public void openProgram(Program program) {
		// stub
	}

	@Override
	public void openProgram(Program program, boolean current) {
		// stub
	}

	@Override
	public void openProgram(Program program, int state) {
		// stub
	}

	@Override
	public void releaseProgram(Program program, Object persistentOwner) {
		// stub
	}

	@Override
	public void setCurrentProgram(Program p) {
		// stub
	}

	@Override
	public boolean setPersistentOwner(Program program, Object owner) {
		return false;
	}

	@Override
	public boolean isLocked() {
		return false;
	}

	@Override
	public void lockDown(boolean state) {
		// Not doing anything
	}
}
