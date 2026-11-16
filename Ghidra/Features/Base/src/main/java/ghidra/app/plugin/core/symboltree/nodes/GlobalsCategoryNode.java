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
package ghidra.app.plugin.core.symboltree.nodes;

import static util.CollectionUtils.*;

import java.awt.datatransfer.DataFlavor;
import java.util.Comparator;
import java.util.List;

import javax.swing.Icon;

import docking.widgets.tree.GTreeNode;
import generic.theme.GIcon;
import ghidra.app.plugin.core.symboltree.SymbolCategory;
import ghidra.app.plugin.core.symboltree.SymbolTreeFilterState;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;

/**
 * Symbol Tree category node for showing global label and function symbols. If the number of global
 * symbols exceeds the organization limit, the are organized in groups based on common prefixes.
 */
public class GlobalsCategoryNode extends SymbolCategoryNode {

	public static final Icon OPEN_FOLDER_GLOBALS_ICON =
		new GIcon("icon.plugin.symboltree.node.category.globals.open");
	public static final Icon CLOSED_FOLDER_GLOBALS_ICON =
		new GIcon("icon.plugin.symboltree.node.category.globals.closed");

	public GlobalsCategoryNode(Program program, SymbolTreeFilterState filterState) {
		super(SymbolCategory.GLOBALS, program, filterState);
	}

	@Override
	public Icon getIcon(boolean expanded) {
		return expanded ? OPEN_FOLDER_GLOBALS_ICON : CLOSED_FOLDER_GLOBALS_ICON;
	}

	@Override
	public String getToolTip() {
		return "Symbols for Global Functions and Labels";
	}

	@Override
	public boolean supportsDataFlavors(DataFlavor[] dataFlavors) {
		for (DataFlavor flavor : dataFlavors) {
			if (flavor == FUNCTION_DATA_FLAVOR || flavor == LABEL_DATA_FLAVOR) {
				return true;
			}
		}
		return false;
	}

	@Override
	public Comparator<GTreeNode> getChildrenComparator() {
		// this category node uses OrganizationNodes
		return OrganizationNode.COMPARATOR;
	}

	@Override
	protected List<SymbolNode> createSearchKeys(Symbol symbol, String name, Namespace ns) {
		if (isGlobalLabelOrFunction(symbol, ns)) {
			return asList(SearchNode.create(symbol, name));
		}

		// The only other type of symbol we support in this category are symbols that live inside
		// global functions. Therefore, the symbol must be a function variable and 'ns' must be
		// a global function (verified by supportsSymbol()).
		return asList(SearchNode.create(ns), SearchNode.create(symbol, name));
	}

	@Override
	protected boolean supportsSymbolAtCatogryRoot(Symbol symbol) {
		return isGlobalLabelOrFunction(symbol, symbol.getParentNamespace());
	}

	@Override
	protected boolean supportsSymbol(Symbol symbol, Namespace namespace) {
		if (isGlobalLabelOrFunction(symbol, namespace)) {
			return true;
		}
		// also allow symbols that live in a global function
		if (isGlobalLabelOrFunction(namespace.getSymbol(), namespace.getParentNamespace())) {
			return true;
		}

		return false;
	}

	private boolean isGlobalLabelOrFunction(Symbol symbol, Namespace namespace) {
		if (namespace == null || !namespace.isGlobal()) {
			return false;
		}
		SymbolType type = symbol.getSymbolType();
		return type == SymbolType.FUNCTION || type == SymbolType.LABEL;
	}
}
