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
import java.util.ArrayList;
import java.util.List;

import javax.swing.Icon;

import generic.theme.GIcon;
import ghidra.app.plugin.core.symboltree.SymbolCategory;
import ghidra.app.plugin.core.symboltree.SymbolTreeFilterState;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;
import util.CollectionUtils;

/**
 * Symbol Tree category node for showing exported symbols. This node displays all functions or 
 * labels that have been tagged as entry points into this program.
 */
class ExportsCategoryNode extends SymbolCategoryNode {
	private static final Icon OPEN_FOLDER =
		new GIcon("icon.plugin.symboltree.node.category.exports.open");
	private static final Icon CLOSED_FOLDER =
		new GIcon("icon.plugin.symboltree.node.category.exports.closed");

	public ExportsCategoryNode(Program program, SymbolTreeFilterState filterState) {
		super(SymbolCategory.EXPORTS, program, filterState);
	}

	@Override
	protected SymbolIterator getPotentialSymbols() {
		List<Symbol> symbols = new ArrayList<>();
		AddressIterator iterator = symbolTable.getExternalEntryPointIterator();
		while (iterator.hasNext()) {
			Symbol symbol = symbolTable.getPrimarySymbol(iterator.next());
			if (symbol != null) {
				symbols.add(symbol);
			}
		}
		return new SymbolIteratorAdapter(symbols.iterator());

	}

	@Override
	protected List<SymbolNode> createSearchKeys(Symbol symbol, String name,
			Namespace parentNamespace) {
		return CollectionUtils.asList(SearchNode.create(symbol, name));
	}

	@Override
	public Icon getIcon(boolean expanded) {
		return expanded ? OPEN_FOLDER : CLOSED_FOLDER;
	}

	@Override
	protected boolean supportsSymbolAtCatogryRoot(Symbol symbol) {
		if (!symbol.isPrimary()) {
			return false;
		}
		return symbol.isExternalEntryPoint();
	}

	@Override
	protected boolean supportsSymbol(Symbol symbol, Namespace namespace) {
		if (!symbol.isPrimary()) {
			return false;
		}

		if (symbol.isExternalEntryPoint()) {
			return true;
		}

		// this allows the GUI to show function params and locals from the exports category
		Symbol parent = namespace.getSymbol();
		return parent != null && parent.isExternalEntryPoint();
	}

	@Override
	public boolean supportsDataFlavors(DataFlavor[] dataFlavors) {
		return false;
	}
}
