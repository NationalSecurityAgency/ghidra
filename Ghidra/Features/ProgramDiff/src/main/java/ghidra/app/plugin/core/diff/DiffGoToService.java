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

import ghidra.app.nav.Navigatable;
import ghidra.app.plugin.core.gotoquery.GoToHelper;
import ghidra.app.services.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.util.ProgramLocation;
import ghidra.util.task.TaskMonitor;

/**
 * A service that provides the ability to go to a particular address or location in the 
 * right-hand listing of the Diff.
 */
public class DiffGoToService implements GoToService {

	private GoToService goToService;
	private ProgramDiffPlugin diffPlugin;
	private GoToHelper helper;

	/**
	 * Creates a service that provides the ability to go to a particular address or location 
	 * in the right-hand listing of the Diff.
	 * @param goToService basic GoToService for the left-side listing that this will override
	 * so it can go to addresses and locations in the right-side listing.
	 * @param diffPlugin the plugin which provides the Diff capability.
	 */
	public DiffGoToService(GoToService goToService, ProgramDiffPlugin diffPlugin) {
		this.goToService = goToService;
		this.diffPlugin = diffPlugin;
		helper = new GoToHelper(diffPlugin.getTool());
	}

	@Override
	public GoToOverrideService getOverrideService() {
		return goToService.getOverrideService();
	}

	@Override
	public boolean goTo(ProgramLocation loc) {
		return diffGoTo(loc);
	}

	@Override
	public boolean goTo(Navigatable navigatable, Program program, Address address,
			Address refAddress) {
		ProgramLocation location = helper.getLocation(program, refAddress, address);
		return goTo(navigatable, location, program);
	}

	@Override
	public boolean goTo(ProgramLocation loc, Program program) {
		if (program == null || program == diffPlugin.getSecondProgram()) {
			return diffGoTo(loc);
		}
		showProgramFailureStatus();
		return false;
	}

	@Override
	public boolean goTo(Navigatable navigatable, ProgramLocation loc, Program program) {
		if (loc == null || loc.getAddress() == null) {
			return false;
		}
		if (program == null) {
			program = navigatable.getProgram();
		}
		if (program == null) {
			return false;
		}
		if (program == diffPlugin.getSecondProgram()) {
			return diffGoTo(loc);
		}
		return false;
	}

	@Override
	public boolean goTo(Navigatable navigatable, Address goToAddress) {
		if (goToAddress == null) {
			return false;
		}
		if (navigatable == null) {
			return diffGoTo(goToAddress);
		}

		Program program = navigatable.getProgram();
		if (program != null) {
			Memory memory = program.getMemory();
			if (!memory.contains(goToAddress)) {
				return false;
			}
		}

		return goTo(goToAddress, program);
	}

	@Override
	public boolean goTo(Address currentAddress, Address goToAddress) {
		if (diffGoTo(goToAddress)) {
			return true;
		}
		return goToService.goTo(currentAddress, goToAddress);
	}

	@Override
	public boolean goTo(Address goToAddress) {
		return diffGoTo(goToAddress);
	}

	@Override
	public boolean goTo(Address goToAddress, Program program) {
		if (program == null || program == diffPlugin.getSecondProgram()) {
			return diffGoTo(goToAddress);
		}
		showProgramFailureStatus();
		return false;
	}

	@Override
	public boolean goToExternalLocation(ExternalLocation extLoc, boolean checkNavigationOption) {
		showProgramFailureStatus();
		return false; // Can only go to locations in the Diff's second program.
	}

	@Override
	public boolean goToExternalLocation(Navigatable navigatable, ExternalLocation extLoc,
			boolean checkNavigationOption) {
		showProgramFailureStatus();
		return false; // Can only go to locations in the Diff's second program.
	}

	@Override
	public boolean goToQuery(Address fromAddr, QueryData queryData, GoToServiceListener listener,
			TaskMonitor monitor) {
		// Does this need to do something different here? Maybe if Diff becomes searchable?
		return goToService.goToQuery(fromAddr, queryData, listener, monitor);
	}

	@Override
	public boolean goToQuery(Navigatable navigatable, Address fromAddr, QueryData queryData,
			GoToServiceListener listener, TaskMonitor monitor) {
		// Does this need to do something different here? Maybe if Diff becomes searchable?
		return goToService.goToQuery(navigatable, fromAddr, queryData, listener, monitor);
	}

	@Override
	public void setOverrideService(GoToOverrideService override) {
		// Do nothing. (May need to change this later if there is reason to override Diff.)
	}

	@Override
	public Navigatable getDefaultNavigatable() {
		return goToService.getDefaultNavigatable();
	}

	private void showProgramFailureStatus() {
		diffPlugin.getTool().setStatusInfo(
			"Can't navigate from the Diff program to another program.");
	}

	/**
	 * Go to the specified program location in the right hand Diff listing.
	 * @param loc go to this location
	 * @return true if the listing went to the location.
	 */
	private boolean diffGoTo(ProgramLocation loc) {
		if (loc == null) {
			return false;
		}
		Address addr = loc.getAddress();
		if (addr == null) {
			return false;
		}
		saveLocation();
		boolean went = diffPlugin.getListingPanel().goTo(loc);
		saveLocation();
		return went;
	}

	/**
	 * Go to the specified address in the right hand Diff listing.
	 * @param addr go to this address
	 * @return true if the listing went to the address.
	 */
	private boolean diffGoTo(Address addr) {
		if (addr == null) {
			return false;
		}
		saveLocation();
		boolean went = diffPlugin.getListingPanel().goTo(addr);
		saveLocation();
		return went;
	}

	/**
	 * Saving the first program's location (the left listing) in the navigation history.
	 * The second program's location (the right listing) isn't saved since the navigation is
	 * relative to a program in the tool's main listing. Also, if the second program's
	 * locations were saved in the history, their program wouldn't be found and would cause
	 * errors when restarting the application with the tool and primary program displayed, but 
	 * no Diff program.
	 */
	private void saveLocation() {
		Program firstProgram = diffPlugin.getFirstProgram();
		if (firstProgram == null) {
			return;
		}
		NavigationHistoryService historyService =
			diffPlugin.getTool().getService(NavigationHistoryService.class);
		if (historyService != null) {
			historyService.addNewLocation(goToService.getDefaultNavigatable());
		}
	}
}
