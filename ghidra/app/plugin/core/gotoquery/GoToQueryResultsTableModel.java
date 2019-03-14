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
package ghidra.app.plugin.core.gotoquery;

import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.app.services.QueryData;
import ghidra.app.util.PluginConstants;
import ghidra.app.util.query.ProgramLocationPreviewTableModel;
import ghidra.framework.model.DomainObjectException;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;
import ghidra.program.util.ProgramLocation;
import ghidra.util.UserSearchUtils;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.ClosedException;
import ghidra.util.task.TaskMonitor;

public class GoToQueryResultsTableModel extends ProgramLocationPreviewTableModel {
	private QueryData queryData;
	private int maxSearchHits;
	private List<ProgramLocation> locations;

	private SymbolTable symbolTable;

	public GoToQueryResultsTableModel(Program prog, QueryData queryData,
			ServiceProvider serviceProvider, int maxSearchHits, TaskMonitor monitor) {
		super("Goto", serviceProvider, prog, monitor);

		this.symbolTable = prog.getSymbolTable();
		this.queryData = queryData;
		this.maxSearchHits = maxSearchHits;
	}

	public GoToQueryResultsTableModel(Program prog, ServiceProvider serviceProvider,
			List<ProgramLocation> locations, TaskMonitor monitor) {
		super("Goto", serviceProvider, prog, monitor);
		this.locations = locations;
	}

	@Override
	public Address getAddress(int row) {
		return filteredData.get(row).getAddress();
	}

	@Override
	protected void doLoad(Accumulator<ProgramLocation> accumulator, TaskMonitor monitor)
			throws CancelledException {

		if (locations != null) {
			accumulator.addAll(locations);
			return;
		}

		try {
			doLoadMaybeWithExceptions(accumulator, monitor);
		}
		catch (DomainObjectException doe) {
			// Super Special Code:
			// There comes a time when this table is asked to load, but the program from whence
			// the load comes is no longer open.  Normal table models we would dispose, but this
			// one is special in that nobody that has a handle to it will get notification of
			// the program being closed.  So, we must anticipate the problem and deal with it
			// ourselves.
			Throwable cause = doe.getCause();
			if (!(cause instanceof ClosedException)) {
				throw doe;
			}
			cancelAllUpdates();
		}
	}

	private void doLoadMaybeWithExceptions(Accumulator<ProgramLocation> accumulator,
			TaskMonitor monitor) throws CancelledException {

		searchDefinedSymbols(accumulator, monitor);
		searchDynamicSymbols(accumulator, monitor);
	}

	private void searchDynamicSymbols(Accumulator<ProgramLocation> accumulator, TaskMonitor monitor)
			throws CancelledException {
		if (!queryData.isIncludeDynamicLables()) {
			return;
		}

		String queryString = queryData.getQueryString();
		if (!isWildQuery(queryString)) {
			// if no wild cards, just parse off the address from the string and go there.
			parseDynamic(accumulator, queryString);
			return;
		}

		boolean caseSensitive = queryData.isCaseSensitive();
		Pattern pattern = UserSearchUtils.createSearchPattern(queryString, caseSensitive);

		ReferenceManager refMgr = getProgram().getReferenceManager();
		AddressSet addressSet = getProgram().getAddressFactory().getAddressSet();
		AddressIterator addrIt = refMgr.getReferenceDestinationIterator(addressSet, true);
		while (addrIt.hasNext() && accumulator.size() < maxSearchHits) {
			monitor.checkCanceled();
			Address addr = addrIt.next();
			Symbol s = symbolTable.getPrimarySymbol(addr);
			if (!s.isDynamic()) {
				continue;
			}

			Matcher matcher = pattern.matcher(s.getName());
			if (matcher.matches()) {
				ProgramLocation programLocation = s.getProgramLocation();
				if (programLocation != null) {
					accumulator.add(programLocation);
				}
			}
		}
	}

	private boolean isWildQuery(String queryString) {
		return queryString.indexOf(PluginConstants.ANYSUBSTRING_WILDCARD_CHAR) > -1 ||
			queryString.indexOf(PluginConstants.ANYSINGLECHAR_WILDCARD_CHAR) > -1;
	}

	private void parseDynamic(Accumulator<ProgramLocation> accumulator, String queryString) {
		Address address =
			SymbolUtilities.parseDynamicName(getProgram().getAddressFactory(), queryString);

		if (address == null) {
			return;
		}
		Symbol s = symbolTable.getPrimarySymbol(address);
		if (s == null) {
			return;
		}
		if (s.getName().equalsIgnoreCase(queryString)) {
			accumulator.add(s.getProgramLocation());
		}
	}

	private boolean searchDefinedSymbols(Accumulator<ProgramLocation> accumulator,
			TaskMonitor monitor) throws CancelledException {

		SymbolIterator it =
			symbolTable.getSymbolIterator(queryData.getQueryString(), queryData.isCaseSensitive());

		while (it.hasNext() && accumulator.size() < maxSearchHits) {
			monitor.checkCanceled();
			Symbol s = it.next();
			ProgramLocation programLocation = s.getProgramLocation();
			if (programLocation != null) {
				accumulator.add(programLocation);
			}
		}

		return false;
	}
}
