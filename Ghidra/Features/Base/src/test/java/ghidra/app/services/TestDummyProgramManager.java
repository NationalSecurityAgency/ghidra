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

import java.awt.Component;
import java.net.URL;

import ghidra.framework.model.DomainFile;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;

/**
 * A stub of the {@link ProgramManager} interface.  This can be used to supply a test program 
 * manager or to spy on system internals by overriding methods as needed.
 */
public class TestDummyProgramManager implements ProgramManager {

	@Override
	public Program getCurrentProgram() {
		// stub
		return null;
	}

	@Override
	public boolean isVisible(Program program) {
		// stub
		return false;
	}

	@Override
	public boolean closeProgram() {
		// stub
		return false;
	}

	@Override
	public Program openProgram(URL ghidraURL, int state) {
		// stub
		return null;
	}

	@Override
	public Program openProgram(DomainFile domainFile) {
		// stub
		return null;
	}

	@Override
	public Program openProgram(DomainFile domainFile, Component dialogParent) {
		// stub
		return null;
	}

	@Override
	public Program openProgram(DomainFile df, int version) {
		// stub
		return null;
	}

	@Override
	public Program openProgram(DomainFile domainFile, int version, int state) {
		// stub
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
	public boolean setPersistentOwner(Program program, Object owner) {
		// stub
		return false;
	}

	@Override
	public void releaseProgram(Program program, Object persistentOwner) {
		// stub
	}

	@Override
	public boolean closeProgram(Program program, boolean ignoreChanges) {
		// stub
		return false;
	}

	@Override
	public boolean closeOtherPrograms(boolean ignoreChanges) {
		// stub
		return false;
	}

	@Override
	public boolean closeAllPrograms(boolean ignoreChanges) {
		// stub
		return false;
	}

	@Override
	public void setCurrentProgram(Program p) {
		// stub
	}

	@Override
	public Program getProgram(Address addr) {
		// stub
		return null;
	}

	@Override
	public Program[] getAllOpenPrograms() {
		// stub
		return null;
	}

	@Override
	public void lockDown(boolean state) {
		// stub
	}

	@Override
	public boolean isLocked() {
		// stub
		return false;
	}

}
