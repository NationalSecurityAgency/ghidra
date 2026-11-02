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
package ghidra.app.plugin.core.symboltree;

import static ghidra.program.model.symbol.SymbolType.*;

import ghidra.framework.options.SaveState;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolType;

/**
 * Class for recording the filter state for the symbol tree. Includes methods for
 * for creating a new filter object with just one of the filter states changed.
 * <P>
 * @param showImports if true, show the imports category 
 * @param showExports if true, show the exports category
 * @param showGlobals if true, show global functions and labels
 * @param showNamespaces if true, show non-global functions and labels, organized by namespaces/class
 * @param includeLabels if false, filter out all labels symbols from the tree
 * @param includeFunctions if false, filter out all function symbols from the tree
 */
public record SymbolTreeFilterState(boolean showImports, boolean showExports, boolean showGlobals,
		boolean showNamespaces, boolean includeLabels, boolean includeFunctions) {
	private static final String INCLUDE_FUNCTIONS = "Include Functions";
	private static final String INCLUDE_LABELS = "Include Labels";
	private static final String SHOW_NAMESPACES = "Show Namespaces";
	private static final String SHOW_GLOBALS = "Show Globals";
	private static final String SHOW_EXPORTS = "Show Exports";
	private static final String SHOW_IMPORTS = "Show Imports";

	/**
	 * Default constructor where all symbols categories are displayed and both functions and label
	 * symbols are included.
	 */
	public SymbolTreeFilterState() {
		this(true, true, true, true, true, true);
	}

	/**
	 * Returns true if the given symbol should be included in the symbol tree.
	 * @param s the symbol to test
	 * @return true if the given symbol should be included in the symbol tree
	 */
	public boolean passesFilter(Symbol s) {
		SymbolType symbolType = s.getSymbolType();

		if (symbolType == FUNCTION || symbolType == PARAMETER || symbolType == LOCAL_VAR) {
			return includeFunctions;
		}
		if (symbolType == LABEL) {
			return includeLabels;
		}
		return true;
	}

	/**
	 * Returns a new SymbolTreeSettings instance with all the same settings as this instance, except
	 * with a new value for showing the imports category.
	 * @param b if true, show the imports category
	 * @return a new SymbolTreeSettings instance with a new value for showing the imports category
	 */
	public SymbolTreeFilterState withImports(boolean b) {
		if (showImports == b) {
			return this;
		}
		return new SymbolTreeFilterState(b, showExports, showGlobals, showNamespaces,
			includeLabels, includeFunctions);
	}

	/**
	 * Returns a new SymbolTreeSettings instance with all the same settings as this instance, except
	 * with a new value for showing the exports category.
	 * @param b if true, show the exports category
	 * @return a new SymbolTreeSettings instance with a new value for showing the exports category
	 */
	public SymbolTreeFilterState withExports(boolean b) {
		if (showExports == b) {
			return this;
		}
		return new SymbolTreeFilterState(showImports, b, showGlobals, showNamespaces,
			includeLabels, includeFunctions);
	}

	/**
	 * Returns a new SymbolTreeSettings instance with all the same settings as this instance, except
	 * with a new value for showing the globals category.
	 * @param b if true, show the globals category
	 * @return a new SymbolTreeSettings instance with a new value for showing the globals category
	 */
	public SymbolTreeFilterState withGlobals(boolean b) {
		if (showGlobals == b) {
			return this;
		}
		return new SymbolTreeFilterState(showImports, showExports, b, showNamespaces,
			includeLabels, includeFunctions);
	}

	/**
	 * Returns a new SymbolTreeSettings instance with all the same settings as this instance, except
	 * with a new value for showing the namespaces category.
	 * @param b if true, show the namespaces category
	 * @return a new SymbolTreeSettings instance with a new value for showing the namespaces category
	 */
	public SymbolTreeFilterState withNamespaces(boolean b) {
		if (showNamespaces == b) {
			return this;
		}
		return new SymbolTreeFilterState(showImports, showExports, showGlobals, b,
			includeLabels, includeFunctions);
	}

	/**
	 * Returns a new SymbolTreeSettings instance with all the same settings as this instance, except
	 * with a new value for including label symbols.
	 * @param b if true, include labels in the tree
	 * @return a new SymbolTreeSettings instance with a new value for including label symbols
	 */
	public SymbolTreeFilterState withLabels(boolean b) {
		if (includeLabels == b) {
			return this;
		}
		return new SymbolTreeFilterState(showImports, showExports, showGlobals, showNamespaces,
			b, includeFunctions);
	}

	/**
	 * Returns a new SymbolTreeSettings instance with all the same settings as this instance, except
	 * with a new value for including function symbols.
	 * @param b if true, include function in the tree
	 * @return a new SymbolTreeSettings instance with a new value for including function symbols
	 */
	public SymbolTreeFilterState withFunctions(boolean b) {
		if (includeFunctions == b) {
			return this;
		}
		return new SymbolTreeFilterState(showImports, showExports, showGlobals, showNamespaces,
			includeLabels, b);
	}

	/**
	 * {@return true if at lease one category is selected to be shown}
	 */
	public boolean includesAtLeastOneCateogry() {
		return showImports || showExports || showGlobals || showNamespaces;
	}

	/**
	 * Saves the current filter state to the given SaveState
	 * @param saveState the SaveState to save to
	 */
	public void save(SaveState saveState) {
		saveState.putBoolean(SHOW_IMPORTS, showImports);
		saveState.putBoolean(SHOW_EXPORTS, showExports);
		saveState.putBoolean(SHOW_GLOBALS, showGlobals);
		saveState.putBoolean(SHOW_NAMESPACES, showNamespaces);
		saveState.putBoolean(INCLUDE_LABELS, includeLabels);
		saveState.putBoolean(INCLUDE_FUNCTIONS, includeFunctions);
	}

	/**
	 * Create a new SymbolTreeFilterState using values from the given SaveState.
	 * @param saveState the saveState that has values stored for a SymbolTreeFilterState
	 * @return a new SymbolTreeFilterState using values from the given SaveState
	 */
	public static SymbolTreeFilterState restore(SaveState saveState) {
		boolean showImports = saveState.getBoolean(SHOW_IMPORTS, true);
		boolean showExports = saveState.getBoolean(SHOW_EXPORTS, true);
		boolean showGlobals = saveState.getBoolean(SHOW_GLOBALS, true);
		boolean showNamespaces = saveState.getBoolean(SHOW_NAMESPACES, true);
		boolean includeLabels = saveState.getBoolean(INCLUDE_LABELS, true);
		boolean includeFunctions = saveState.getBoolean(INCLUDE_FUNCTIONS, true);
		return new SymbolTreeFilterState(showImports, showExports, showGlobals, showNamespaces,
			includeLabels, includeFunctions);
	}

}
