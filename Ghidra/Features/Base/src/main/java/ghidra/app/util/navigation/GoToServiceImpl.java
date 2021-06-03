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
package ghidra.app.util.navigation;

import ghidra.app.nav.Navigatable;
import ghidra.app.plugin.core.gotoquery.GoToHelper;
import ghidra.app.services.*;
import ghidra.framework.plugintool.Plugin;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.util.ProgramLocation;
import ghidra.util.task.TaskMonitor;

public class GoToServiceImpl implements GoToService {

	private final Navigatable defaultNavigatable;
	private GoToOverrideService override;
	private GoToHelper helper;
	protected final Plugin plugin;

	public GoToServiceImpl(Plugin plugin, Navigatable defaultNavigatable) {
		this.plugin = plugin;
		this.defaultNavigatable = defaultNavigatable;
		helper = new GoToHelper(plugin.getTool());
	}

	@Override
	public GoToOverrideService getOverrideService() {
		return override;
	}

	@Override
	public boolean goTo(ProgramLocation loc) {
		return helper.goTo(defaultNavigatable, loc, loc.getProgram());
	}

	@Override
	public boolean goTo(ProgramLocation loc, Program program) {
		return helper.goTo(defaultNavigatable, loc, program);
	}

	@Override
	public boolean goTo(Navigatable navigatable, ProgramLocation loc, Program program) {
		if (navigatable == null || navigatable.isConnected()) {
			navigatable = defaultNavigatable;
		}
		return helper.goTo(navigatable, loc, program);
	}

	@Override
	public boolean goTo(Navigatable navigatable, Address goToAddress) {
		if (goToAddress == null) {
			return false;
		}
		if (navigatable == null) {
			navigatable = defaultNavigatable;
		}

		Program program = navigatable.getProgram();
		Address currentAddress = navigatable.getLocation().getAddress();
		ProgramLocation location = helper.getLocation(program, currentAddress, goToAddress);
		if (navigatable.isConnected()) {
			navigatable = defaultNavigatable;
		}
		return helper.goTo(navigatable, location, program);
	}

	@Override
	public boolean goTo(Navigatable navigatable, Program program, Address address,
			Address refAddress) {
		ProgramLocation location = helper.getLocation(program, refAddress, address);
		return helper.goTo(navigatable, location, program);
	}

	@Override
	public boolean goTo(Address currentAddress, Address goToAddress) {
		Program program = defaultNavigatable.getProgram();
		ProgramLocation location = helper.getLocation(program, currentAddress, goToAddress);
		return helper.goTo(defaultNavigatable, location, program);
	}

	@Override
	public boolean goTo(Address goToAddress) {
		if (goToAddress == null) {
			return false;
		}
		ProgramLocation programLocation = null;
		Program program = defaultNavigatable.getProgram();
		// override has precedence
		if (override != null) {
			programLocation = override.goTo(goToAddress);
		}
		if (programLocation == null) {
			programLocation = GoToHelper.getProgramLocationForAddress(goToAddress, program);
		}
		else {
			program = programLocation.getProgram();
		}

		return helper.goTo(defaultNavigatable, programLocation, program);
	}

	@Override
	public boolean goTo(Address goToAddress, Program program) {
		ProgramLocation location = GoToHelper.getProgramLocationForAddress(goToAddress, program);
		return helper.goTo(defaultNavigatable, location, program);
	}

	@Override
	public boolean goToExternalLocation(ExternalLocation extLoc, boolean checkNavigationOption) {
		return helper.goToExternalLocation(defaultNavigatable, extLoc, checkNavigationOption);
	}

	@Override
	public boolean goToExternalLocation(Navigatable navigatable, ExternalLocation extLoc,
			boolean checkNavigationOption) {
		return helper.goToExternalLocation(navigatable, extLoc, checkNavigationOption);
	}

	@Override
	public boolean goToQuery(Navigatable navigatable, Address fromAddr, QueryData queryData,
			GoToServiceListener listener, TaskMonitor monitor) {

		if (navigatable == null || navigatable.isConnected()) {
			navigatable = defaultNavigatable;
		}

		GoToQuery query = new GoToQuery(navigatable, plugin, this, queryData, fromAddr, listener,
			helper.getOptions(), monitor);

		return query.processQuery();
	}

	@Override
	public boolean goToQuery(Address fromAddr, QueryData queryData, GoToServiceListener listener,
			TaskMonitor monitor) {
		return goToQuery(defaultNavigatable, fromAddr, queryData, listener, monitor);
	}

	@Override
	public void setOverrideService(GoToOverrideService override) {
		this.override = override;
	}

	@Override
	public Navigatable getDefaultNavigatable() {
		return defaultNavigatable;
	}

}
