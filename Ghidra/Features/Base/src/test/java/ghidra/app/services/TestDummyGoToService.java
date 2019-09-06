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

import ghidra.app.nav.Navigatable;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.util.ProgramLocation;
import ghidra.util.task.TaskMonitor;

/**
 * A stub of the {@link GoToService} interface.   This can be used to supply a test version
 * of the service or to spy on system internals by overriding methods as needed.
 */
public class TestDummyGoToService implements GoToService {

	@Override
	public boolean goTo(ProgramLocation loc) {
		// stub
		return false;
	}

	@Override
	public boolean goTo(ProgramLocation loc, Program program) {
		// stub
		return false;
	}

	@Override
	public boolean goTo(Navigatable navigatable, ProgramLocation loc, Program program) {
		// stub
		return false;
	}

	@Override
	public boolean goTo(Navigatable navigatable, Program program, Address address,
			Address refAddress) {
		// stub
		return false;
	}

	@Override
	public boolean goTo(Address currentAddress, Address goToAddress) {
		// stub
		return false;
	}

	@Override
	public boolean goTo(Navigatable navigatable, Address goToAddress) {
		// stub
		return false;
	}

	@Override
	public boolean goTo(Address goToAddress) {
		// stub
		return false;
	}

	@Override
	public boolean goTo(Address goToAddress, Program program) {
		// stub
		return false;
	}

	@Override
	public boolean goToExternalLocation(ExternalLocation externalLoc,
			boolean checkNavigationOption) {
		// stub
		return false;
	}

	@Override
	public boolean goToExternalLocation(Navigatable navigatable, ExternalLocation externalLoc,
			boolean checkNavigationOption) {
		// stub
		return false;
	}

	@Override
	public boolean goToQuery(Address fromAddr, QueryData queryData, GoToServiceListener listener,
			TaskMonitor monitor) {
		// stub
		return false;
	}

	@Override
	public boolean goToQuery(Navigatable navigatable, Address fromAddr, QueryData queryData,
			GoToServiceListener listener, TaskMonitor monitor) {
		// stub
		return false;
	}

	@Override
	public GoToOverrideService getOverrideService() {
		// stub
		return null;
	}

	@Override
	public void setOverrideService(GoToOverrideService override) {
		// stub

	}

	@Override
	public Navigatable getDefaultNavigatable() {
		// stub
		return null;
	}

}
