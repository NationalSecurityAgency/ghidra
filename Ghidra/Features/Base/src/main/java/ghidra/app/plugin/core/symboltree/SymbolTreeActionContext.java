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

import java.util.ArrayList;
import java.util.List;

import javax.swing.tree.TreePath;

import ghidra.app.context.ProgramSymbolActionContext;
import ghidra.app.plugin.core.symboltree.nodes.SymbolNode;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;

public class SymbolTreeActionContext extends ProgramSymbolActionContext {

	private TreePath[] selectionPaths;

	SymbolTreeActionContext(SymbolTreeProvider provider, Program program, SymbolGTree tree,
			TreePath[] selectionPaths) {
		super(provider, program, getSymbols(selectionPaths), tree);
		this.selectionPaths = selectionPaths;
	}

	public SymbolTreeProvider getSymbolTreeProvider() {
		return (SymbolTreeProvider) getComponentProvider();
	}

	public SymbolGTree getSymbolTree() {
		return (SymbolGTree) getContextObject();
	}

	public TreePath[] getSelectedSymbolTreePaths() {
		return selectionPaths;
	}

	public TreePath getSelectedPath() {
		if (selectionPaths.length == 1) {
			return selectionPaths[0];
		}
		return null;
	}

	private static List<Symbol> getSymbols(TreePath[] selectionPaths) {
		if (selectionPaths == null) {
			return null;
		}

		List<Symbol> symbols = new ArrayList<>();
		for (TreePath treePath : selectionPaths) {
			Object object = treePath.getLastPathComponent();
			if (object instanceof SymbolNode) {
				SymbolNode symbolNode = (SymbolNode) object;
				symbols.add(symbolNode.getSymbol());
			}
			else {
				// Do not return symbols if selection contains non-symbolNodes
				return null;
			}
		}
		return symbols;
	}
}
