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
package ghidra.features.base.replace.handler;

import static ghidra.program.model.symbol.SymbolType.*;

import java.util.HashSet;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.features.base.quickfix.QuickFix;
import ghidra.features.base.replace.*;
import ghidra.features.base.replace.items.RenameSymbolQuickFix;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * {@link SearchAndReplaceHandler} for handling search and replace for symbols. Specifically, it
 * provides {@link SearchType}s for renaming labels, functions, namespaces, classes, local 
 * variables, and parameters.
 */
public class SymbolsSearchAndReplaceHandler extends SearchAndReplaceHandler {

	public SymbolsSearchAndReplaceHandler() {
		//@formatter:off
		addType(new SymbolSearchType(LABEL, "Labels", "Search and replace label names"));
		addType(new SymbolSearchType(FUNCTION, "Functions", "Search and replace function names"));
		addType(new SymbolSearchType(NAMESPACE, "Namespaces", "Search and replace generic namespace names"));
		addType(new SymbolSearchType(CLASS, "Classes", "Search and replace class names"));
		addType(new SymbolSearchType(LOCAL_VAR, "Local Variables", "Search and replace local variable names"));
		addType(new SymbolSearchType(PARAMETER, "Parameters", "Search and replace parameter names"));
		//@formatter:on
	}

	@Override
	public void findAll(Program program, SearchAndReplaceQuery query,
			Accumulator<QuickFix> accumulator, TaskMonitor monitor) throws CancelledException {

		SymbolTable symbolTable = program.getSymbolTable();
		int symbolCount = symbolTable.getNumSymbols();
		monitor.initialize(symbolCount, "Searching Labels...");

		Pattern pattern = query.getSearchPattern();

		Set<SymbolType> selectedSymbolTypes = getSelectedSymbolTypes(query);

		for (Symbol symbol : symbolTable.getDefinedSymbols()) {
			monitor.increment();
			if (symbol.isExternal()) {
				continue;
			}

			SymbolType symbolType = symbol.getSymbolType();

			if (selectedSymbolTypes.contains(symbolType)) {
				if (symbolType == SymbolType.FUNCTION) {
					Function function = (Function) symbol.getObject();
					// Thunks can't be renamed directly
					if (function.isThunk()) {
						continue;
					}
				}
				Matcher matcher = pattern.matcher(symbol.getName());
				if (matcher.find()) {
					String newName = matcher.replaceAll(query.getReplacementText());
					RenameSymbolQuickFix item = new RenameSymbolQuickFix(symbol, newName);
					accumulator.add(item);
				}
			}
		}
	}

	private Set<SymbolType> getSelectedSymbolTypes(SearchAndReplaceQuery query) {
		Set<SymbolType> symbolTypes = new HashSet<>();

		Set<SearchType> selectedSearchTypes = query.getSelectedSearchTypes();
		for (SearchType searchType : selectedSearchTypes) {
			if (searchType instanceof SymbolSearchType symbolSearchType) {
				symbolTypes.add(symbolSearchType.getSymbolType());
			}
		}
		return symbolTypes;
	}

	private class SymbolSearchType extends SearchType {
		private final SymbolType symbolType;

		SymbolSearchType(SymbolType symbolType, String name, String description) {
			super(SymbolsSearchAndReplaceHandler.this, name, description);
			this.symbolType = symbolType;
		}

		SymbolType getSymbolType() {
			return symbolType;
		}
	}
}
