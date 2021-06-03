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

import java.awt.Component;
import java.util.*;

import javax.swing.SwingUtilities;

import docking.widgets.table.threaded.ThreadedTableModelListener;
import ghidra.GhidraOptions;
import ghidra.app.nav.Navigatable;
import ghidra.app.nav.NavigationUtils;
import ghidra.app.plugin.core.gotoquery.GoToHelper;
import ghidra.app.plugin.core.gotoquery.GoToQueryResultsTableModel;
import ghidra.app.plugin.core.navigation.NavigationOptions;
import ghidra.app.plugin.core.table.TableComponentProvider;
import ghidra.app.services.*;
import ghidra.app.util.PluginConstants;
import ghidra.app.util.query.TableService;
import ghidra.framework.options.Options;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.program.util.AddressEvaluator;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import ghidra.util.SystemUtilities;
import ghidra.util.table.AddressArrayTableModel;
import ghidra.util.table.GhidraProgramTableModel;
import ghidra.util.task.TaskMonitor;

public class GoToQuery {
	private QueryData queryData;
	private Address fromAddress;
	private GhidraProgramTableModel<?> model;
	private GoToServiceListener listener;
	private TaskMonitor monitor;

	protected ProgramGroup programs;
	private GoToService goToService;
	private GoToQueryThreadedTableModelListener tableModelListener;
	private final int maxHits;
	private final Plugin plugin;
	private final Navigatable navigatable;
	private NavigationOptions navigationOptions;

	public GoToQuery(Navigatable navigatable, Plugin plugin, GoToService goToService,
			QueryData queryData, Address fromAddr, GoToServiceListener listener,
			NavigationOptions navigationOptions, TaskMonitor monitor) {

		this.navigatable = navigatable;
		this.queryData = queryData;
		this.plugin = plugin;
		this.goToService = goToService;
		this.navigationOptions = navigationOptions;
		Options opt = plugin.getTool().getOptions(PluginConstants.SEARCH_OPTION_NAME);

		if (!opt.contains(GhidraOptions.OPTION_SEARCH_LIMIT)) {
			opt.registerOption(GhidraOptions.OPTION_SEARCH_LIMIT,
				PluginConstants.DEFAULT_SEARCH_LIMIT, null,
				"The maximum number of search hits before stopping.");
		}
		this.maxHits =
			opt.getInt(GhidraOptions.OPTION_SEARCH_LIMIT, PluginConstants.DEFAULT_SEARCH_LIMIT);
		this.fromAddress = fromAddr;
		this.monitor = monitor;

		if (listener != null) {
			this.listener = listener;
		}
		else {
			this.listener = new DummyGoToServiceListener();
		}

		programs = getAllPrograms();
		tableModelListener = new GoToQueryThreadedTableModelListener();
	}

	private ProgramGroup getAllPrograms() {
		ProgramManager progService = plugin.getTool().getService(ProgramManager.class);
		return new ProgramGroup(progService.getAllOpenPrograms(), navigatable.getProgram());
	}

	public boolean processQuery() {
		if (processAddressExpression()) {
			return true;
		}
		if (processWildCard()) {
			return true;
		}
		if (processSymbolInParsedScope()) {
			return true;
		}
		if (processSymbolInCurrentProgram()) {
			return true;
		}
		if (!navigationOptions.isGoToRestrictedToCurrentProgram()) {
			if (processInputAsSymbolInAllPrograms()) {
				return true;
			}
		}
		if (processAddress()) {
			return true;
		}
		if (processDynamicOrCaseInsensitive()) {
			return true;
		}
		notifyListener(false);
		return false;
	}

	private boolean checkForOverride() {
		GoToOverrideService override = goToService.getOverrideService();
		if (override == null) {
			return false;
		}

		ProgramLocation pLoc = override.goTo(queryData.getQueryString());
		if (pLoc != null) {
			goToService.goTo(navigatable, pLoc, pLoc.getProgram());
			notifyListener(true);
			return true;
		}
		return false;
	}

	private boolean processAddress() {
		if (checkForOverride()) {
			return true;
		}

		String queryString = queryData.getQueryString();

		for (Program program : programs) {
			Address[] addresses = program.parseAddress(queryString, queryData.isCaseSensitive());
			Address[] validAddresses = validateAddresses(program, addresses);
			if (validAddresses.length > 0) {
				goToAddresses(program, validAddresses);
				return true;
			}
		}
		// check once more if the current location has an address for the address string.  This
		// will catch the case where the current location is in FILE space.
		Program currentProgram = navigatable.getProgram();
		Address fileAddress = getFileAddress(currentProgram, queryString);
		if (fileAddress != null) {
			goToAddresses(currentProgram, new Address[] { fileAddress });
			return true;
		}

		return false;
	}

	private Address getFileAddress(Program program, String queryString) {
		if (fromAddress == null) {
			return null;
		}
		try {
			Address address = fromAddress.getAddressSpace().getAddress(queryString);
			if (address != null && program.getMemory().contains(address)) {
				return address;
			}
		}
		catch (AddressFormatException e) {
			// ignore and return null
		}
		return null;
	}

	private void goToAddresses(final Program program, final Address[] validAddresses) {
		if (validAddresses.length == 1) {
			goTo(program, validAddresses[0], fromAddress);
			notifyListener(true);
			return;
		}

		SystemUtilities.runIfSwingOrPostSwingLater(() -> {
			model = new AddressArrayTableModel("Goto: ", plugin.getTool(), program, validAddresses,
				monitor);
			model.addInitialLoadListener(tableModelListener);
		});
	}

	private void goToProgramLocations(final Program program,
			final List<ProgramLocation> locations) {

		if (locations.size() == 1) {
			goTo(program, locations.get(0));
			notifyListener(true);
			return;
		}

		SystemUtilities.runIfSwingOrPostSwingLater(() -> {
			model = new GoToQueryResultsTableModel(program, plugin.getTool(), locations, monitor);
			model.addInitialLoadListener(tableModelListener);
		});
	}

	private boolean processDynamicOrCaseInsensitive() {
		if (!queryData.isIncludeDynamicLables() && queryData.isCaseSensitive()) {
			return false;
		}

		SystemUtilities.runIfSwingOrPostSwingLater(() -> {
			model = new GoToQueryResultsTableModel(navigatable.getProgram(), queryData,
				plugin.getTool(), maxHits, monitor);
			model.addInitialLoadListener(tableModelListener);
		});

		return true;
	}

	private boolean processInputAsSymbolInAllPrograms() {
		for (Program program : programs) {
			List<ProgramLocation> programLocations = getValidSymbolLocationsForProgram(program);
			if (programLocations.size() > 0) {
				goToProgramLocations(program, programLocations);
				return true;
			}
		}
		return false;
	}

	private List<ProgramLocation> getValidSymbolLocationsForProgram(Program program) {
		List<ProgramLocation> list = new ArrayList<>();
		SymbolTable symTable = program.getSymbolTable();
		SymbolIterator it = symTable.getSymbols(queryData.getQueryString());

		while (it.hasNext() && (list.size() < maxHits)) {
			Symbol symbol = it.next();
			ProgramLocation location = getProgramLocationForSymbol(symbol, program);
			if (location != null) {
				list.add(location);
			}
			else {
				list.addAll(getExtenalLinkageLocations(symbol));
			}
		}

		return list;
	}

	private Collection<ProgramLocation> getExtenalLinkageLocations(Symbol symbol) {
		Collection<ProgramLocation> locations = new ArrayList<>();
		Program program = symbol.getProgram();

		Address[] externalLinkageAddresses =
			NavigationUtils.getExternalLinkageAddresses(program, symbol.getAddress());
		for (Address address : externalLinkageAddresses) {
			ProgramLocation location = GoToHelper.getProgramLocationForAddress(address, program);
			if (location != null) {
				locations.add(location);
			}
		}
		return locations;
	}

	private ProgramLocation getProgramLocationForSymbol(Symbol symbol, Program program) {
		Address symbolAddress = symbol.getAddress();
		if (symbolAddress.isExternalAddress()) {
			return null;
		}

		if ((symbolAddress.isMemoryAddress() && !program.getMemory().contains(symbolAddress))) {
			return null;
		}

		return symbol.getProgramLocation();
	}

	private boolean processSymbolInParsedScope() {
		String queryInput = queryData.getQueryString();
		int colonPos = queryInput.lastIndexOf("::");
		if (colonPos < 0) {
			return false;
		}

		String scopeName = queryInput.substring(0, colonPos);
		String symbolName = queryInput.substring(colonPos + 2);
		if (goToSymbolInScope(scopeName, symbolName)) {
			notifyListener(true);
			return true;
		}

		return false;
	}

	private boolean processAddressExpression() {
		String queryInput = queryData.getQueryString();
		if (!isAddressExpression(queryInput)) {
			return false;
		}
		boolean relative = queryInput.matches("^\\s*[+-].*");
		Address baseAddr = relative ? fromAddress : null;
		for (Program program : programs) {
			Address evalAddr = AddressEvaluator.evaluate(program, baseAddr, queryInput);
			if (evalAddr != null) {
				boolean success = goTo(program, new ProgramLocation(program, evalAddr));
				notifyListener(success);
				return true;
			}
		}
		return false;
	}

	private QueryData cleanupQuery(Program program, QueryData qData) {
		String input = qData.getQueryString();
		int colonPosition = input.indexOf("::");
		if (colonPosition >= 0) {
			String preColonString = input.substring(0, colonPosition);
			if (isAddressSpaceName(program, preColonString) ||
				isBlockName(program, preColonString)) {
				// strip off block name or the address space name part
				input = input.substring(colonPosition + 2); // 2 for both ':' chars
				qData =
					new QueryData(input, qData.isCaseSensitive(), qData.isIncludeDynamicLables());
			}
		}
		return qData;
	}

	private boolean processWildCard() {
		if (!isWildCard()) {
			return false;
		}

		SystemUtilities.runIfSwingOrPostSwingLater(() -> {
			Program program = navigatable.getProgram();
			model = new GoToQueryResultsTableModel(program, cleanupQuery(program, queryData),
				plugin.getTool(), maxHits, monitor);
			model.addInitialLoadListener(tableModelListener);
		});
		return true;
	}

	public boolean isWildCard() {
		String queryInput = queryData.getQueryString();
		return queryInput.indexOf(PluginConstants.ANYSUBSTRING_WILDCARD_CHAR) > -1 ||
			queryInput.indexOf(PluginConstants.ANYSINGLECHAR_WILDCARD_CHAR) > -1;
	}

	private boolean isAddressExpression(String input) {
		return (input.indexOf('+') >= 0 || input.indexOf('-') >= 0 || input.indexOf('*') > 0);
	}

	private boolean isAddressSpaceName(Program program, String input) {
		return program.getAddressFactory().getAddressSpace(input) != null;
	}

	private boolean isBlockName(Program program, String input) {
		MemoryBlock[] blocks = program.getMemory().getBlocks();
		for (MemoryBlock element : blocks) {
			if (element.getName().equals(input)) {
				return true;
			}
		}
		return false;
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

	private boolean goToSymbolInScope(String scopeName, String symbolStr) {
		for (Program program : programs) {
			SymbolTable symTable = program.getSymbolTable();
			Namespace scope = getScope(program, program.getGlobalNamespace(), scopeName);
			if (scope != null) {
				List<Symbol> symbols = symTable.getSymbols(symbolStr, scope);
				if (!symbols.isEmpty()) {
					return gotoLabels(program, symbols);
				}
			}
			//else see if scopeName is really memoryBlock name.
			return goToSymbolInMemoryBlock(scopeName, symbolStr, program);
		}
		return false;
	}

	private boolean gotoLabels(Program program, List<Symbol> symbols) {
		if (symbols.size() == 1) {
			return gotoLabel(program, symbols.get(0));
		}

		List<ProgramLocation> programLocations = new ArrayList<>();

		for (Symbol symbol : symbols) {
			ProgramLocation programLocation = symbol.getProgramLocation();
			if (programLocation != null) {
				programLocations.add(symbol.getProgramLocation());
			}
		}

		goToProgramLocations(program, programLocations);

		return true;
	}

	private boolean goToSymbolInMemoryBlock(String scopeName, String symbolStr, Program program) {

		List<Symbol> globalSymbols =
			program.getSymbolTable().getLabelOrFunctionSymbols(symbolStr, null);
		if (globalSymbols.isEmpty()) {
			return false;
		}

		List<Symbol> matchingSymbols = new ArrayList<>();
		for (Symbol symbol : globalSymbols) {
			Address address = symbol.getAddress();
			MemoryBlock block = program.getMemory().getBlock(address);
			if (block != null && block.getName().equals(scopeName)) {
				matchingSymbols.add(symbol);
			}
		}

		if (matchingSymbols.isEmpty()) {
			return false;
		}

		return gotoLabels(program, matchingSymbols);
	}

	private Namespace getScope(Program program, Namespace parent, String scopeName) {
		int colonIndex = scopeName.lastIndexOf("::");
		if (colonIndex >= 0) {
			String parentScopeName = scopeName.substring(0, colonIndex);
			scopeName = scopeName.substring(colonIndex + 1);
			parent = getScope(program, parent, parentScopeName);
			if (parent == null) {
				return null;
			}
		}
		SymbolTable symTable = program.getSymbolTable();
		Namespace namespace = symTable.getNamespace(scopeName, parent);
		if (namespace != null) {
			return namespace;
		}
		return null;
	}

	private boolean processSymbolInCurrentProgram() {
		Program program = navigatable.getProgram();
		SymbolTable symTable = program.getSymbolTable();

		List<Symbol> symbols = new ArrayList<Symbol>();
		SymbolIterator symbolIterator = symTable.getSymbols(queryData.getQueryString());
		while (symbolIterator.hasNext()) {
			Symbol symbol = symbolIterator.next();
			symbols.add(symbol);
		}

		if (!symbols.isEmpty()) {
			gotoLabels(program, symbols);
			notifyListener(true);
			return true;
		}
		return false;
	}

	private boolean gotoLabel(Program program, Symbol symbol) {
		if (symbol == null) {
			return false;
		}

		ProgramLocation loc = symbol.getProgramLocation();
		if (loc == null) {
			return false;
		}

		if (goToService.goTo(navigatable, loc, program)) {
			return true;
		}
		return false;
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

	private boolean goTo(Program program, Address gotoAddress, Address refAddress) {
		if (program == null) {
			program = navigatable.getProgram();
		}

		if (program.getMemory().contains(gotoAddress)) {
			goToService.goTo(navigatable, program, gotoAddress, refAddress);
			return true;
		}
		return false;
	}

	private void notifyListener(boolean hasData) {
		listener.gotoCompleted(queryData.getQueryString(), hasData);
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	/**
	 * A class to maintain our collection of open programs and to provide an <code>Iterator</code>
	 * when we need to process the collection.  The {@link #iterator()} method has a side-effect
	 * of putting the current program at the front of the <code>Iterator</code> so that the current
	 * program is always searched first when processing the collection of programs.
	 */
	protected class ProgramGroup implements Iterable<Program> {

		private List<Program> programList;

		public ProgramGroup(Program[] programs, Program navigatableProgram) {
			programList = new ArrayList<>(Arrays.asList(programs));
			if (!programList.contains(navigatableProgram)) {
				programList.add(navigatableProgram);
			}
		}

		@Override
		public Iterator<Program> iterator() {
			List<Program> newList = new ArrayList<>(programList);

			Program currentProgram = navigatable.getProgram();
			int index = newList.indexOf(currentProgram);
			Collections.swap(newList, 0, index);

			return newList.iterator();
		}
	}

	private class GoToQueryThreadedTableModelListener implements ThreadedTableModelListener {

		@Override
		public void loadPending() {
			// don't care
		}

		@Override
		public void loadingStarted() {
			// don't care
		}

		@Override
		public void loadingFinished(boolean wasCancelled) {
			int rowCount = model.getRowCount();
			boolean hasData = rowCount > 0;
			if (!hasData) {
				notifyListener(false);
				return;
			}

			if (rowCount == 1) {
				goTo(null, model.getProgramLocation(0, 0));
				notifyListener(true);
				return;
			}

			PluginTool tool = plugin.getTool();
			if (tool == null) {
				return; // this can happen if a search is taking place when the tool is closed
			}

			TableService service = tool.getService(TableService.class);
			TableComponentProvider<?> provider = service.showTable(
				"Goto " + queryData.getQueryString(), "Goto", model, "Go To", navigatable);
			if (model.getRowCount() >= maxHits) {
				showMaxSearchWarning(provider.getComponent(), model.getRowCount());
			}

			notifyListener(true);
		}

		private void showMaxSearchWarning(final Component parent, final int matchCount) {
			// to parent the following dialog properly, we must make sure the above query results
			// component has been shown (it gets shown in an invoke later during a docking windows update)
			SwingUtilities.invokeLater(() -> Msg.showWarn(getClass(), parent,
				"Search Limit Exceeded!",
				"Stopped search after finding " + matchCount + " matches.\n" +
					"The Search limit can be changed in the Edit->Options, under Tool Options"));
		}
	}

	private class DummyGoToServiceListener implements GoToServiceListener {
		@Override
		public void gotoCompleted(String queryString, boolean foundResults) {
			// stubbed
		}

		@Override
		public void gotoFailed(Exception exc) {
			// stubbed
		}
	}
}
