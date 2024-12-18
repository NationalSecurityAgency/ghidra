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

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.app.nav.Navigatable;
import ghidra.app.plugin.core.gotoquery.GoToQueryResultsTableModel;
import ghidra.app.plugin.core.navigation.NavigationOptions;
import ghidra.app.plugin.core.table.TableComponentProvider;
import ghidra.app.services.*;
import ghidra.app.util.SearchConstants;
import ghidra.app.util.query.TableService;
import ghidra.framework.options.Options;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.util.AddressEvaluator;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import ghidra.util.Swing;
import ghidra.util.table.GhidraProgramTableModel;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskMonitor;

public class GoToQuery {

	/**
	 * Regex used for going to a file offset.  We expect something of the form <code>file(n)</code>,
	 * where <code>n</code> can be hex or decimal.  Spaces should be ignored. 
	 */
	private Pattern FILE_OFFSET_REGEX = Pattern
			.compile("file\\s*\\(\\s*((0x[0-9a-fA-F]+|[0-9]+))\\s*\\)", Pattern.CASE_INSENSITIVE);

	private QueryData queryData;
	private Address fromAddress;
	private TaskMonitor monitor;

	private GoToService goToService;
	private final int maxHits;
	private final Plugin plugin;
	private final Navigatable navigatable;
	private NavigationOptions navigationOptions;

	private PluginTool tool;

	public GoToQuery(Navigatable navigatable, Plugin plugin, GoToService goToService,
			QueryData queryData, Address fromAddr, NavigationOptions navigationOptions,
			TaskMonitor monitor) {

		this.navigatable = navigatable;
		this.queryData = queryData;
		this.plugin = plugin;
		this.goToService = goToService;
		this.navigationOptions = navigationOptions;
		this.tool = plugin.getTool();

		Options options = plugin.getTool().getOptions(SearchConstants.SEARCH_OPTION_NAME);
		this.maxHits =
			options.getInt(SearchConstants.SEARCH_LIMIT_NAME, SearchConstants.DEFAULT_SEARCH_LIMIT);
		this.fromAddress = fromAddr;
		this.monitor = monitor;
	}

	public boolean processQuery() {
		// Queries can be of several different types. Handle all the non-symbol types first since
		// they are faster to try, as they don't require searching through all the program's
		// symbols.

		if (processFileOffset()) {
			return true;
		}

		if (processAddressExpression()) {
			return true;
		}

		if (processAddress()) {
			return true;
		}

		// none of the specialized query handlers matched, so try to process the query
		// as a symbol (label, function name, variable name, etc.)
		return processSymbols();
	}

	private boolean processFileOffset() {
		String input = queryData.getQueryString();
		Matcher matcher = FILE_OFFSET_REGEX.matcher(input);
		if (matcher.matches()) {
			try {
				long offset = Long.decode(matcher.group(1));
				Program currentProgram = navigatable.getProgram();
				Memory mem = currentProgram.getMemory();
				List<Address> addresses = mem.locateAddressesForFileOffset(offset);
				if (addresses.size() > 0) {
					goToAddresses(currentProgram, addresses.toArray(new Address[0]));
					return true;
				}
			}
			catch (NumberFormatException e) {
				// fall through to return false
			}
		}
		return false;
	}

	private boolean processAddressExpression() {
		String queryInput = queryData.getQueryString();
		if (!isAddressExpression(queryInput)) {
			return false;
		}

		// checking for leading "+" or "-", ignoring spaces.  
		boolean relative = queryInput.matches("^\\s*[+-].*");
		Address baseAddr = relative ? fromAddress : null;
		for (Program program : getSearchPrograms()) {
			Address evalAddr = AddressEvaluator.evaluate(program, baseAddr, queryInput);
			if (evalAddr != null) {
				return goTo(program, new ProgramLocation(program, evalAddr));
			}
		}
		return false;
	}

	private boolean processAddress() {

		String queryString = queryData.getQueryString();
		for (Program program : getSearchPrograms()) {
			Address[] addresses = program.parseAddress(queryString, queryData.isCaseSensitive());
			Address[] validAddresses = validateAddresses(program, addresses);
			if (validAddresses.length > 0) {
				return goToAddresses(program, validAddresses);
			}
		}

		// check once more if the current location has an address for the address string.  This
		// will catch the case where the current location is in FILE space.
		Program currentProgram = navigatable.getProgram();
		Address fileAddress = getFileAddress(currentProgram, queryString);
		if (fileAddress != null) {
			return goToAddresses(currentProgram, new Address[] { fileAddress });
		}

		return false;
	}

	private boolean processSymbols() {
		GoToSymbolSearchTask task =
			new GoToSymbolSearchTask(queryData, getSearchPrograms(), maxHits);
		TaskLauncher.launch(task);

		List<ProgramLocation> locations = task.getResults();
		if (locations.isEmpty()) {
			return false;
		}

		Program program = locations.get(0).getProgram();
		return goToProgramLocations(program, locations);
	}

	private List<ProgramLocation> toProgramLocations(Address[] addresses, Program program) {
		return Arrays.stream(addresses).map(a -> new ProgramLocation(program, a)).toList();
	}

	private Address getFileAddress(Program program, String addressString) {
		if (fromAddress == null) {
			return null;
		}
		try {
			Address address = fromAddress.getAddressSpace().getAddress(addressString);
			if (address != null && program.getMemory().contains(address)) {
				return address;
			}
		}
		catch (AddressFormatException e) {
			// ignore and return null
		}
		return null;
	}

	private boolean goToAddresses(Program program, Address[] validAddresses) {
		List<ProgramLocation> locations = toProgramLocations(validAddresses, program);
		return goToProgramLocations(program, locations);
	}

	private boolean goToProgramLocations(Program program, List<ProgramLocation> locations) {

		if (locations.size() == 1) {
			return goTo(program, locations.get(0));
		}

		Swing.runIfSwingOrRunLater(() -> showResultsInTable(locations));
		return true;
	}

	private void showResultsInTable(List<ProgramLocation> locations) {
		Program program = locations.get(0).getProgram();
		if (locations.size() > maxHits) {
			showMaxSearchWarning(locations.size());
		}
		showModelInTable(new GoToQueryResultsTableModel(program, tool, locations, monitor));

	}

	private void showModelInTable(GhidraProgramTableModel<?> model) {

		TableService service = tool.getService(TableService.class);
		TableComponentProvider<?> provider = service.showTable(
			"Goto " + queryData.getQueryString(), "Goto", model, "Go To", navigatable);
		provider.requestFocus();

	}

	/**
	 * Returns the programs to search. If searching more than the current program, make sure
	 * the current program is first in the list.
	 * @return the list of program to search with the current program first
	 */
	private List<Program> getSearchPrograms() {
		Program currentProgram = navigatable.getProgram();
		List<Program> searchPrograms = new ArrayList<>();
		searchPrograms.add(currentProgram);
		if (!navigationOptions.isGoToRestrictedToCurrentProgram()) {
			ProgramManager programManager = plugin.getTool().getService(ProgramManager.class);
			Program[] allOpenPrograms = programManager.getAllOpenPrograms();
			for (Program program : allOpenPrograms) {
				if (program != currentProgram) {
					searchPrograms.add(program);
				}
			}
		}
		return searchPrograms;
	}

	private boolean isAddressExpression(String input) {
		return (input.indexOf('+') >= 0 || input.indexOf('-') >= 0 || input.indexOf('*') > 0);
	}

	private Address[] validateAddresses(Program program, Address[] addrs) {
		Memory memory = program.getMemory();
		ArrayList<Address> list = new ArrayList<>();
		for (Address element : addrs) {

			boolean isValid = memory.contains(element);
			if (!isValid) {
				continue;
			}

			if (isPreferredAddress(element)) {
				return new Address[] { element };
			}

			list.add(element);
		}

		if (list.size() == addrs.length) {
			return addrs;
		}
		Address[] a = new Address[list.size()];
		return list.toArray(a);
	}

	private boolean isPreferredAddress(Address address) {
		if (!navigationOptions.preferCurrentAddressSpace()) {
			return false; // no preferred address when we are showing them all
		}
		return isInCurrentAddressSpace(address);
	}

	private boolean isInCurrentAddressSpace(Address address) {
		if (fromAddress == null) {
			return true;
		}

		AddressSpace currentSpace = fromAddress.getAddressSpace();
		return currentSpace.equals(address.getAddressSpace());
	}

	private boolean goTo(Program program, ProgramLocation loc) {
		if (loc == null) {
			return false;
		}
		if (program == null) {
			program = navigatable.getProgram();
		}

		return goToService.goTo(navigatable, loc, program);
	}

	private void showMaxSearchWarning(int matchCount) {
		Msg.showWarn(getClass(), null,
			"Search Limit Exceeded!",
			"Stopped search after finding " + matchCount + " matches.\n" +
				"The search limit can be changed at Edit->Tool Options, under Search.");
	}
}
