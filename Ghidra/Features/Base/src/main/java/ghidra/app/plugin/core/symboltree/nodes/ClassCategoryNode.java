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

import docking.widgets.tree.GTreeNode;
import ghidra.app.plugin.core.symboltree.SymbolCategory;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import resources.ResourceManager;

public class ClassCategoryNode extends SymbolCategoryNode {

	public static final Icon OPEN_FOLDER_CLASSES_ICON =
		ResourceManager.loadImage("images/openFolderClasses.png");
	public static final Icon CLOSED_FOLDER_CLASSES_ICON =
		ResourceManager.loadImage("images/closedFolderClasses.png");

	ClassCategoryNode(Program program) {
		super(SymbolCategory.CLASS_CATEGORY, program);
	}

	@Override
	public Icon getIcon(boolean expanded) {
		return expanded ? OPEN_FOLDER_CLASSES_ICON : CLOSED_FOLDER_CLASSES_ICON;
	}

	@Override
	public String getToolTip() {
		return "Symbols for Classes";
	}

	@Override
	public DataFlavor getNodeDataFlavor() {
		return null;
	}

	@Override
	public SymbolNode symbolAdded(Symbol symbol) {
		if (!isLoaded()) {
			return null;
		}

		if (!supportsSymbol(symbol)) {
			return null;
		}

		if (symbol.getSymbolType() == symbolCategory.getSymbolType()) {
			return doAddSymbol(symbol, this); // add new Class symbol
		}

		// see if the symbol is in a class namespace
		Namespace parentNamespace = symbol.getParentNamespace();
		Symbol namespaceSymbol = parentNamespace.getSymbol();
		SymbolNode key = SymbolNode.createNode(namespaceSymbol, program);
		GTreeNode parentNode = findSymbolTreeNode(key, false, TaskMonitorAdapter.DUMMY_MONITOR);
		if (parentNode == null) {
			return null;
		}
		return doAddSymbol(symbol, parentNode);
	}

	@Override
	protected List<GTreeNode> getSymbols(SymbolType type, TaskMonitor monitor)
			throws CancelledException {
		List<GTreeNode> list = new ArrayList<GTreeNode>();

		monitor.initialize(symbolTable.getNumSymbols());
		SymbolType symbolType = symbolCategory.getSymbolType();
		SymbolIterator it = symbolTable.getDefinedSymbols();
		while (it.hasNext()) {
			Symbol s = it.next();
			if (s != null && (s.getSymbolType() == symbolType)) {
				monitor.checkCanceled();
				list.add(SymbolNode.createNode(s, program));
			}
			monitor.incrementProgress(1);
		}
		Collections.sort(list, getChildrenComparator());
		return list;
	}

	@Override
	protected boolean supportsSymbol(Symbol symbol) {
		SymbolType symbolType = symbol.getSymbolType();
		if (symbolType == symbolCategory.getSymbolType()) {
			return true;
		}

		// must be in a class at some level
		Namespace parentNamespace = symbol.getParentNamespace();
		while (parentNamespace != null && parentNamespace != globalNamespace) {
			if (parentNamespace instanceof GhidraClass) {
				return true;
			}
			parentNamespace = parentNamespace.getParentNamespace();
		}

		return false;
	}
}
