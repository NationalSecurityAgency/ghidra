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

import java.awt.datatransfer.DataFlavor;
import java.util.*;

import javax.swing.Icon;

import generic.theme.GIcon;
import ghidra.app.plugin.core.symboltree.SymbolCategory;
import ghidra.app.plugin.core.symboltree.SymbolTreeFilterState;
import ghidra.app.util.NamespaceUtils;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;

/**
 * Symbol Tree category node for showing non-global label and function symbols, classes, and
 * namespaces. All nodes are organized by namespace.
 */
public class NamespaceCategoryNode extends SymbolCategoryNode {

	private static final Icon OPEN_FOLDER_NAMESPACES_ICON =
		new GIcon("icon.plugin.symboltree.node.category.namespace.open");
	private static final Icon CLOSED_FOLDER_NAMESPACES_ICON =
		new GIcon("icon.plugin.symboltree.node.category.namespace.closed");

	static final Set<DataFlavor> supportedFlavors = Set.of(
		NAMESPACE_DATA_FLAVOR,
		CLASS_DATA_FLAVOR,
		FUNCTION_DATA_FLAVOR,
		LABEL_DATA_FLAVOR);

	public NamespaceCategoryNode(Program program, SymbolTreeFilterState filterState) {
		super(SymbolCategory.NAMESPACES, program, filterState);
	}

	@Override
	public Icon getIcon(boolean expanded) {
		return expanded ? OPEN_FOLDER_NAMESPACES_ICON : CLOSED_FOLDER_NAMESPACES_ICON;
	}

	@Override
	protected boolean supportsSymbolAtCatogryRoot(Symbol symbol) {
		if (!symbol.getParentNamespace().isGlobal()) {
			return false;
		}
		SymbolType symbolType = symbol.getSymbolType();
		return symbolType == SymbolType.NAMESPACE || symbolType == SymbolType.CLASS;
	}

	@Override
	protected boolean supportsSymbol(Symbol symbol, Namespace namespace) {

		if (symbol.isExternal()) {
			return false;
		}

		SymbolType symbolType = symbol.getSymbolType();
		if (symbolType == SymbolType.NAMESPACE || symbolType == SymbolType.CLASS) {
			return true;
		}

		// symbols in the global namespace are under other categories (Functions, Labels, Classes)
		return namespace != null && !namespace.isGlobal();
	}

	@Override
	protected List<SymbolNode> createSearchKeys(Symbol symbol, String name, Namespace ns) {
		List<SymbolNode> keys = new ArrayList<>();
		List<Namespace> parents = NamespaceUtils.getNamespaceParts(ns);
		for (Namespace parent : parents) {
			keys.add(SearchNode.create(parent));
		}
		keys.add(SearchNode.create(symbol, name));

		return keys;
	}

	@Override
	public boolean supportsDataFlavors(DataFlavor[] dataFlavors) {
		for (DataFlavor flavor : dataFlavors) {
			if (supportedFlavors.contains(flavor)) {
				return true;
			}
		}
		return false;
	}

}
