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

import java.util.ArrayList;
import java.util.List;

import ghidra.app.nav.NavigationUtils;
import ghidra.app.plugin.core.gotoquery.GoToHelper;
import ghidra.app.services.QueryData;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.*;
import ghidra.program.util.ProgramLocation;
import ghidra.util.task.TaskMonitor;

/**
 * Class for searching for symbols that match a given query string.
 * <P>
 * The query string may include full or partial (absolute or relative) namespace path information.
 * The standard namespace delimiter ("::") is used to separate the query into it separate pieces,
 * with each piece used to either match a namespace or a symbol name, with the symbol
 * name piece always being the last piece (or the only piece).
 * <P>
 * Both the namespace pieces and the symbol name piece may contain wildcards ("*" or "?") and those
 * wildcards only apply to a single element. For example, if a symbol's full path was "a::b::c::d"
 * and the query was "a::*::d", it would not match as the "*" can only match one element. 
 * <P>
 * By default all queries are considered relative. In other words, the first namespace element
 * does not need to be at the root global level. For example, in the "a::b::c::d" example, the "d"
 * symbol could be found by "d", "c::d", "b::c::d". To avoid this behavior, the query may begin
 * with a "::" delimiter which means the path is absolute and the first element must be at the
 * root level. So, in the previous example, "::a::b::c::d" would match but, "::c::d" would not.
 * <P>
 * There are also two parameters in the QueryData object that affect how the search algorithm is
 * conducted. One is "Case Sensitive" and the other is "Include Dynamic Labels". If the search
 * is case insensitive or there are wild cards in the symbol name, the only option is to do a full
 * search of all defined symbols, looking for matches. If that is not the case, the search can
 * do a direct look up of matching symbols using the program database's symbol index.
 * <P>
 * If the "Include Dynamic Labels" options is on, then a brute force of the defined references is
 * also performed, looking at all addresses that a reference points to, getting the dynamic 
 * (not stored) symbol at that address and checking if it matches.
 * <P>
 * One last behavior to note is that the search takes a list of programs to search. However, it
 * only returns results from the FIRST program to have any results. If the need to search all
 * programs completely is ever needed, a second "find" method could easily be added.
 */
public class SymbolSearcher {

	private SymbolMatcher symbolMatcher;
	private QueryData queryData;
	private int limit;
	private TaskMonitor monitor;

	public SymbolSearcher(QueryData data, int limit, TaskMonitor monitor) {
		this.queryData = data;
		this.limit = limit;
		this.monitor = monitor;
		this.symbolMatcher =
			new SymbolMatcher(queryData.getQueryString(), queryData.isCaseSensitive());
	}

	public List<ProgramLocation> findMatchingSymbolLocations(List<Program> searchPrograms) {

		List<ProgramLocation> locations = new ArrayList<>();
		for (Program program : searchPrograms) {
			if (monitor.isCancelled()) {
				break;
			}
			if (findMatchingSymbolLocations(program, locations)) {
				return locations;
			}
		}

		return locations;
	}

	private boolean findMatchingSymbolLocations(Program program, List<ProgramLocation> locations) {

		if (!findSymbolsByDirectLookup(program, locations)) {
			findSymbolsByBruteForce(program, locations);
		}

		return !locations.isEmpty();
	}

	private boolean findSymbolsByDirectLookup(Program program, List<ProgramLocation> locations) {

		// can only do direct lookup of symbol name if it has no wildcards and is case sensitive
		if (!symbolMatcher.hasFullySpecifiedName()) {
			return false;
		}

		String symbolName = symbolMatcher.getSymbolName();
		return scanSymbols(program, program.getSymbolTable().getSymbols(symbolName), locations);
	}

	private void findSymbolsByBruteForce(Program program, List<ProgramLocation> locations) {

		// only need to do this if the name is fuzzy; otherwise a direct lookup already happened
		if (!symbolMatcher.hasFullySpecifiedName()) {
			searchDefinedSymbols(program, locations);
		}

		// if dynamic symbols are on, we also need to search through references, looking for default
		// symbol names (LAB*, FUN*, etc.)
		if (queryData.isIncludeDynamicLables()) {
			searchDynamicSymbolsByReference(program, locations);
		}
	}

	private void searchDynamicSymbolsByReference(Program program, List<ProgramLocation> locations) {

		if (!symbolMatcher.hasWildCardsInSymbolName()) {
			// if no wild cards, just parse off the address from the string and go there.
			parseDynamic(program, locations);
			return;
		}

		SymbolTable symbolTable = program.getSymbolTable();
		ReferenceManager refMgr = program.getReferenceManager();
		AddressSet addressSet = program.getAddressFactory().getAddressSet();
		AddressIterator addrIt = refMgr.getReferenceDestinationIterator(addressSet, true);
		while (addrIt.hasNext() && locations.size() < limit) {
			if (monitor.isCancelled()) {
				return;
			}
			Address addr = addrIt.next();
			Symbol s = symbolTable.getPrimarySymbol(addr);
			if (s.isDynamic()) {
				addSymbolIfMatches(s, locations);
			}
		}
	}

	private boolean addSymbolIfMatches(Symbol s, List<ProgramLocation> locations) {
		if (symbolMatcher.matches(s)) {
			ProgramLocation programLocation = getProgramLocationForSymbol(s);
			if (programLocation != null) {
				locations.add(programLocation);
				return true;
			}
			return addExternalLinkageLocations(s, locations);
		}
		return false;
	}

	private boolean addExternalLinkageLocations(Symbol symbol, List<ProgramLocation> locations) {
		boolean addedLocations = false;
		Program program = symbol.getProgram();
		Address[] externalLinkageAddresses =
			NavigationUtils.getExternalLinkageAddresses(program, symbol.getAddress());
		for (Address address : externalLinkageAddresses) {
			ProgramLocation location = GoToHelper.getProgramLocationForAddress(address, program);
			if (location != null) {
				addedLocations = true;
				locations.add(location);
			}
		}
		return addedLocations;
	}

	private void parseDynamic(Program program, List<ProgramLocation> locations) {
		AddressFactory addressFactory = program.getAddressFactory();
		String symbolName = symbolMatcher.getSymbolName();
		Address address = SymbolUtilities.parseDynamicName(addressFactory, symbolName);

		if (address == null) {
			return;
		}
		Symbol s = program.getSymbolTable().getPrimarySymbol(address);
		if (s != null && s.isDynamic()) { // non-dynamic symbols have already been searched (ex, FUN_12345678)
			addSymbolIfMatches(s, locations);
		}
	}

	private void searchDefinedSymbols(Program program, List<ProgramLocation> locations) {
		String symbolName = symbolMatcher.getSymbolName();
		SymbolTable symbolTable = program.getSymbolTable();
		SymbolIterator it = symbolTable.getSymbolIterator(symbolName, queryData.isCaseSensitive());

		scanSymbols(program, it, locations);
	}

	private boolean scanSymbols(Program program, SymbolIterator it,
			List<ProgramLocation> locations) {

		boolean addedSymbols = false;
		while (it.hasNext() && locations.size() < limit) {
			if (monitor.isCancelled()) {
				break;
			}
			Symbol symbol = it.next();
			addedSymbols |= addSymbolIfMatches(symbol, locations);
		}
		return addedSymbols;
	}

	private ProgramLocation getProgramLocationForSymbol(Symbol symbol) {
		Address symbolAddress = symbol.getAddress();

		if (symbolAddress.isExternalAddress()) {
			return null;
		}

		Memory memory = symbol.getProgram().getMemory();
		if ((symbolAddress.isMemoryAddress() && !memory.contains(symbolAddress))) {
			return null;
		}

		return symbol.getProgramLocation();
	}

}
