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
package ghidra.app.util.viewer.field;

import java.util.*;

import generic.json.Json;
import ghidra.program.database.symbol.FunctionSymbol;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;

/**
 * A simple class to load all symbols for a given code unit
 */
public class LabelFieldSymbolLoader {

	private boolean displayFunctionLabel;
	private Symbols symbols;

	private boolean hasMore;

	public LabelFieldSymbolLoader(CodeUnit cu, int max, boolean displayFunctionLabel) {

		this.displayFunctionLabel = displayFunctionLabel;

		symbols = new Symbols();
		gatherRealSymbols(cu, max);
		gatherOffcutSymbols(cu, max);
	}

	public Symbols getSymbols() {
		return symbols;
	}

	public boolean hasMore() {
		return hasMore;
	}

	private void gatherRealSymbols(CodeUnit cu, int max) {

		Address addr = cu.getMinAddress();
		Program program = cu.getProgram();

		//
		// Place the primary symbol to the front so that it is always rendered, even if we hit the
		// symbol limit. Also, remove the function symbol if the user doesn't want to see it.
		//
		SymbolTable st = program.getSymbolTable();
		SymbolIterator it = st.getSymbolsAsIterator(addr);
		Symbol primary = st.getPrimarySymbol(addr);
		if (primary == null) {
			return;
		}

		boolean showPrimary = !ignoreSymbol(primary);
		int remaining = showPrimary ? max - 1 : max;

		while (it.hasNext()) {
			Symbol s = it.next();
			if (s.isPrimary()) {
				continue;
			}

			if (remaining == symbols.size()) {
				hasMore = true;
				break;
			}

			if (ignoreSymbol(s)) {
				continue;
			}

			symbols.add(s);
		}

		if (showPrimary) {
			symbols.add(primary);
		}
	}

	private boolean ignoreSymbol(Symbol s) {
		if (s instanceof FunctionSymbol) {
			return !displayFunctionLabel;
		}
		return false;
	}

	private void gatherOffcutSymbols(CodeUnit cu, int max) {

		if (max == 0) {
			return;
		}

		Address startAddr = cu.getMinAddress();
		if (!startAddr.isMemoryAddress()) {
			return;
		}

		Program program = cu.getProgram();
		if (cu.getLength() == 1) {
			return;
		}

		Address nextAddr = startAddr.next();
		if (nextAddr == null) {
			return;
		}

		SymbolTable symbolTable = program.getSymbolTable();
		Address endAddress = cu.getMaxAddress();
		ReferenceManager referenceManager = program.getReferenceManager();
		AddressIterator it = referenceManager.getReferenceDestinationIterator(nextAddr, true);
		while (it.hasNext()) {

			Address addr = it.next();
			if (addr.compareTo(endAddress) > 0 ||
				// Note: check for wrapping - temporary work-around
				addr.compareTo(cu.getMinAddress()) <= 0) {
				break;
			}

			if (max == symbols.size()) {
				hasMore = true;
				return;
			}

			Symbol s = symbolTable.getPrimarySymbol(addr);
			symbols.addOffcut(s);
		}

		SymbolIterator symIter = symbolTable.getSymbolIterator(nextAddr, true);
		while (symIter.hasNext()) {

			Symbol s = symIter.next();
			Address addr = s.getAddress();
			if (addr.compareTo(endAddress) > 0 ||
				// Note: check for wrapping - temporary work-around
				addr.compareTo(cu.getMinAddress()) <= 0) {
				break;
			}

			if (max == symbols.size()) {
				hasMore = true;
				return;
			}

			// remove to handle the case where this symbol was added in the above loop
			symbols.removeOffct(s);
			symbols.addOffcut(s);
		}
	}

	/**
	 * A simple class to hold all real and offcut symbols for a given code unit.  The client will
	 * limit the number of symbols added to this class.  The real symbols are loaded first, with any
	 * remaining space filled with existing offcut symbols.
	 */
	public class Symbols {

		private List<Symbol> realSymbols = new ArrayList<>();
		private List<Symbol> offcutSymbols = new ArrayList<>();

		void addOffcut(Symbol s) {
			offcutSymbols.add(s);
		}

		void removeOffct(Symbol s) {
			offcutSymbols.remove(s);
		}

		void add(Symbol s) {
			realSymbols.add(s);
		}

		void add(int index, Symbol s) {
			realSymbols.add(index, s);
		}

		void remove(Symbol s) {
			realSymbols.remove(s);
		}

		int size() {
			return offcutSymbols.size() + realSymbols.size();
		}

		Symbol get(int index) {

			if (index < offcutSymbols.size()) {
				return offcutSymbols.get(index);
			}

			int updatedIndex = index - offcutSymbols.size();
			return realSymbols.get(updatedIndex);
		}

		public List<Symbol> getAllSymbols() {
			List<Symbol> list = new ArrayList<>();

			list.addAll(realSymbols);
			list.addAll(offcutSymbols);

			return list;
		}

		List<Symbol> getOffcuts() {
			return Collections.unmodifiableList(offcutSymbols);
		}

		void reverseSymbols() {
			realSymbols = realSymbols.reversed();
		}

		@Override
		public String toString() {
			return Json.toString(this);
		}
	}
}
