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
import java.util.Comparator;
import java.util.List;

import javax.swing.Icon;

import docking.widgets.tree.GTreeNode;
import ghidra.app.plugin.core.symboltree.SymbolCategory;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;
import ghidra.util.task.TaskMonitor;
import resources.ResourceManager;

class FunctionCategoryNode extends SymbolCategoryNode {

	public static final Icon OPEN_FOLDER_FUNCTIONS_ICON =
		ResourceManager.loadImage("images/openFolderFunctions.png");
	public static final Icon CLOSED_FOLDER_FUNCTIONS_ICON =
		ResourceManager.loadImage("images/closedFolderFunctions.png");

	FunctionCategoryNode(Program program) {
		super(SymbolCategory.FUNCTION_CATEGORY, program);
	}

//	
//	This code will allow symbols to appear both in the 'Functions' node *and* in the namespaces
//	node, if they have a namespace.  We have decided that we only want symbols appearing in one
//	or the other node, as does the LabelCategoryNode.  Anywho, if you put this code back in, then
//	you must change supportsSymbol() below to know how to allow symbols to be both in this
//	node and the namespaces node.
//	
//	@Override
//	protected List<GTreeNode> getSymbols(SymbolType type, TaskMonitor monitor) {
//		List<GTreeNode> nodes = new ArrayList<GTreeNode>();
//		SymbolIterator symbols =
//			program.getSymbolTable().getSymbols(program.getMemory(), SymbolType.FUNCTION, true);
//		while (symbols.hasNext()) {
//			Symbol symbol = symbols.next();
//			if (symbol != null) {
//				nodes.add(SymbolNode.createNode(symbol, program));
//			}
//		}
//		Collections.sort(nodes, symbolNodeComparator);
//		return nodes;
//
//	}

	@Override
	public Icon getIcon(boolean expanded) {
		return expanded ? OPEN_FOLDER_FUNCTIONS_ICON : CLOSED_FOLDER_FUNCTIONS_ICON;
	}

	@Override
	public String getToolTip() {
		return "Symbols for Functions";
	}

	@Override
	public boolean supportsDataFlavors(DataFlavor[] dataFlavors) {
		for (DataFlavor flavor : dataFlavors) {
			if (flavor == FunctionSymbolNode.LOCAL_DATA_FLAVOR) {
				return true;
			}
		}
		return false;
	}

	@Override
	public boolean canPaste(List<GTreeNode> pastedNodes) {
		for (GTreeNode treeNode : pastedNodes) {
			if (!(treeNode instanceof FunctionCategoryNode) &&
				!(treeNode instanceof LabelCategoryNode)) {
				return false;
			}
		}

		return true;
	}

	@Override
	public Comparator<GTreeNode> getChildrenComparator() {
		// this category node uses OrganizationNodes
		return OrganizationNode.COMPARATOR;
	}

	@Override
	public SymbolNode symbolAdded(Symbol symbol) {
		if (!isLoaded()) {
			return null;
		}

		if (!supportsSymbol(symbol)) {
			return null;
		}

		// variables and parameters will be beneath function nodes, and our parent method
		// will find them
		if (isVariableParameterOrCodeSymbol(symbol)) {
			return super.symbolAdded(symbol);
		}

		// this namespace will be beneath function nodes, and our parent method will find them
		if (isChildNamespaceOfFunction(symbol)) {
			return super.symbolAdded(symbol);
		}

		// ...otherwise, we have a function and we need to add it as a child of our parent node
		SymbolNode newNode = SymbolNode.createNode(symbol, program);
		doAddNode(this, newNode);
		return newNode;
	}

	private boolean isChildNamespaceOfFunction(Symbol symbol) {
		if (symbol instanceof Function) {
			return false;
		}

		Namespace parentNamespace = symbol.getParentNamespace();
		while (parentNamespace != null && parentNamespace != globalNamespace) {
			if (parentNamespace instanceof Function) {
				return true;
			}
			parentNamespace = parentNamespace.getParentNamespace();
		}
		return false;
	}

	private boolean isVariableParameterOrCodeSymbol(Symbol symbol) {
		SymbolType symbolType = symbol.getSymbolType();
		return symbolType.equals(SymbolType.LOCAL_VAR) || symbolType.equals(SymbolType.PARAMETER) ||
			symbolType.equals(SymbolType.LABEL);
	}

	@Override
	protected boolean supportsSymbol(Symbol symbol) {
		if (super.supportsSymbol(symbol)) {
			return true;
		}

		// the symbol must have a function parent at some level
		Namespace parentNamespace = symbol.getParentNamespace();
		while (parentNamespace != null && parentNamespace != globalNamespace) {
			if (parentNamespace instanceof Function) {
				return true;
			}
			parentNamespace = parentNamespace.getParentNamespace();
		}
		return false;
	}

	@Override
	public GTreeNode findSymbolTreeNode(SymbolNode key, boolean loadChildren, TaskMonitor monitor) {

		// if we don't have to loadChildren and we are not loaded get out.
		if (!loadChildren && !isLoaded()) {
			return null;
		}

		//
		// Special Case: this node uses the OrganizationNode for partitioning child Function
		//               nodes.  Further, some functions may contain Label symbols whose name
		//               is not related to the function name.  In this case, the binary search
		//               for the label will fail because its name will not match the org node
		//               names, which are based on the functions' names.  This call will handle
		//               the case where a non-function symbol has a function as its parent.
		//
		GTreeNode node = maybeSearchForSymbolInsideOfFunction(key, loadChildren, monitor);
		if (node != null) {
			return node;
		}

		return super.findSymbolTreeNode(key, loadChildren, monitor);
	}

	private GTreeNode maybeSearchForSymbolInsideOfFunction(SymbolNode key, boolean loadChildren,
			TaskMonitor monitor) {

		Symbol symbol = key.getSymbol();
		Symbol parentSymbol = symbol.getParentSymbol();
		if (parentSymbol == null) {
			return null; // not sure if this can happen
		}

		SymbolType parentType = parentSymbol.getSymbolType();
		if (parentType != SymbolType.FUNCTION) {
			return null;
		}

		SymbolNode parentKey = SymbolNode.createNode(parentSymbol, program);
		GTreeNode parentNode = super.findSymbolTreeNode(parentKey, loadChildren, monitor);
		if (parentNode == null) {
			return null;
		}

		// At this point we have a function and we have found the node for that function.  
		// Search that node for the symbol.  (This bypasses the OrganizationNode's search 
		// algorithm.)
		return ((FunctionSymbolNode) parentNode).findSymbolTreeNode(key, loadChildren, monitor);
	}
}
