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

import java.util.*;

import javax.swing.Icon;

import docking.widgets.tree.GTreeNode;
import generic.theme.GIcon;
import ghidra.app.plugin.core.symboltree.SymbolCategory;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.task.TaskMonitor;

class ExportsCategoryNode extends SymbolCategoryNode {
	private static final Icon OPEN_FOLDER =
		new GIcon("icon.plugin.symboltree.node.category.exports.open");
	private static final Icon CLOSED_FOLDER =
		new GIcon("icon.plugin.symboltree.node.category.exports.closed");

	public ExportsCategoryNode(Program program) {
		super(SymbolCategory.EXPORTS_CATEGORY, program);
	}

	@Override
	public List<GTreeNode> generateChildren(TaskMonitor monitor) {
		if (!isEnabled) {
			return Collections.emptyList();
		}

		List<GTreeNode> list = new ArrayList<>();
		List<Symbol> functionSymbolList = getExportSymbols();
		for (Symbol symbol : functionSymbolList) {
			list.add(SymbolNode.createNode(symbol, program));
		}

		Collections.sort(list, getChildrenComparator());

		return list;
	}

	private List<Symbol> getExportSymbols() {
		List<Symbol> symbols = new ArrayList<>();
		AddressIterator iterator = symbolTable.getExternalEntryPointIterator();
		while (iterator.hasNext()) {
			Symbol symbol = symbolTable.getPrimarySymbol(iterator.next());
			if (symbol != null) {
				symbols.add(symbol);
			}
		}
		return symbols;
	}

	@Override
	public Icon getIcon(boolean expanded) {
		return expanded ? OPEN_FOLDER : CLOSED_FOLDER;
	}

	@Override
	protected boolean supportsSymbol(Symbol symbol) {
		if (!symbol.isPrimary()) {
			return false;
		}

		if (symbol.isExternalEntryPoint()) {
			return true;
		}

		Symbol parent = symbol.getParentSymbol();
		return parent != null && parent.isExternalEntryPoint();
	}
}
