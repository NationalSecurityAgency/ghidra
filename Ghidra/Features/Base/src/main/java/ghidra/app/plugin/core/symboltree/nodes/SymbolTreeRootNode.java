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

import static ghidra.program.model.symbol.SymbolType.*;

import java.util.*;

import javax.swing.Icon;

import docking.widgets.tree.GTreeNode;
import generic.theme.GIcon;
import ghidra.app.plugin.core.symboltree.SymbolCategory;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;
import ghidra.util.task.TaskMonitor;

public class SymbolTreeRootNode extends GTreeNode {
	private static Icon GLOBAL_ICON = new GIcon("icon.plugin.symboltree.node.root");
	private final String name;

	protected SymbolCategory symbolCategory;
	protected Program program;
	private int groupThreshold;

	public SymbolTreeRootNode(Program program, int groupThreshold) {
		this.groupThreshold = groupThreshold;
		this.symbolCategory = SymbolCategory.ROOT_CATEGORY;
		this.program = program;

		if (program == null) {
			name = "No Symbol Tree";
		}
		else {
			name = "Global";
		}
	}

	public int getNodeGroupThreshold() {
		return groupThreshold;
	}

	public int getReorganizeLimit() {
		// Arbitrary number to prevent bulk updates from triggering repeated node organization.
		// The higher the value, the longer the delay between the tree collapsing nodes to signal
		// that a re-organzation is needed.
		return groupThreshold * 2;
	}

	public Program getProgram() {
		return program;
	}

	@Override
	public List<GTreeNode> generateChildren() {
		if (program == null) {
			return Collections.emptyList();
		}

		List<GTreeNode> list = new ArrayList<>();

		list.add(new ImportsCategoryNode(program));
		list.add(new ExportsCategoryNode(program));
		list.add(new FunctionCategoryNode(program));
		list.add(new LabelCategoryNode(program));
		list.add(new ClassCategoryNode(program));
		list.add(new NamespaceCategoryNode(program));

		return list;
	}

	public GTreeNode findSymbolTreeNode(SymbolNode key, boolean loadChildren, TaskMonitor monitor) {

		//
		// The finding of nodes starts here, at the root.  Optimize searching by using the 
		// implicit knowledge of how the tree builds/stores symbols by their type:
		// -Function - search only the function nodes, no recursive searching		
		// -External function - search only the imports node, no recursive searching
		// -Params/Locals - find the function node, then search that node
		// -Classes - search the classes node, need recursive searching
		// -Namespaces - search the namespaces node, need recursive searching
		//

		Symbol searchSymbol = key.getSymbol();
		SymbolType type = searchSymbol.getSymbolType();
		if (type == FUNCTION) {
			return findFunctionSymbolNode(key, loadChildren, monitor);
		}
		else if (type == PARAMETER || type == LOCAL_VAR) {
			return findVariableSymbolNode(key, loadChildren, monitor);
		}
		else if (type == CLASS) {
			return findClassSymbol(key, loadChildren, monitor);
		}
		else if (type == LIBRARY || type == NAMESPACE) {
			return findNamespaceSymbol(key, loadChildren, monitor);
		}
		else if (type == LABEL) {
			return findCodeSymbol(key, loadChildren, monitor);
		}
		//else { GLOBAL, GLOBAL_VAR } // not sure where these end up

		return null;
	}

	private GTreeNode findCodeSymbol(SymbolNode key, boolean loadChildren, TaskMonitor monitor) {

		//@formatter:off
		List<SymbolCategoryNode> categories = Arrays.asList(
			getLabelsNode(),					
			getNamespacesNode(),
			getClassesNode(),	
			getFunctionsNode()
		);
		//@formatter:on
		GTreeNode node = searchCategories(categories, key, loadChildren, monitor);
		return node;
	}

	private GTreeNode findNamespaceSymbol(SymbolNode key, boolean loadChildren,
			TaskMonitor monitor) {

		SymbolCategoryNode category = getNamespacesNode();
		return category.findSymbolTreeNode(key, loadChildren, monitor);
	}

	private GTreeNode findClassSymbol(SymbolNode key, boolean loadChildren, TaskMonitor monitor) {
		SymbolCategoryNode category = getClassesNode();
		return category.findSymbolTreeNode(key, loadChildren, monitor);
	}

	private GTreeNode findVariableSymbolNode(SymbolNode key, boolean loadChildren,
			TaskMonitor monitor) {

		Symbol searchSymbol = key.getSymbol();
		Symbol functionSymbol = searchSymbol.getParentSymbol();
		SymbolNode parentKey = SymbolNode.createNode(functionSymbol, program);
		GTreeNode functionNode = findFunctionSymbolNode(parentKey, loadChildren, monitor);
		if (functionNode != null) {
			return ((SymbolTreeNode) functionNode).findSymbolTreeNode(key, loadChildren, monitor);
		}
		return null;
	}

	private GTreeNode findFunctionSymbolNode(SymbolNode key, boolean loadChildren,
			TaskMonitor monitor) {

		Symbol searchSymbol = key.getSymbol();
		if (searchSymbol.isExternal()) {
			// assumption: externals will always be in the Externals category
			return searchCategory(getExternalsNode(), key, loadChildren, monitor);
		}

		//@formatter:off
		List<SymbolCategoryNode> categories = Arrays.asList(
			getFunctionsNode(),
			getClassesNode(),
			getNamespacesNode()
		);
		//@formatter:on
		GTreeNode node = searchCategories(categories, key, loadChildren, monitor);
		return node;
	}

	private GTreeNode searchCategories(List<SymbolCategoryNode> categories, SymbolNode key,
			boolean loadChildren, TaskMonitor monitor) {

		for (SymbolCategoryNode category : categories) {
			GTreeNode node = searchCategory(category, key, loadChildren, monitor);
			if (node != null) {
				return node;
			}
		}

		return null;
	}

	private GTreeNode searchCategory(SymbolCategoryNode category, SymbolNode key,
			boolean loadChildren, TaskMonitor monitor) {

		if (category == null) {
			return null; // assume category is filtered out
		}

		GTreeNode node = category.findSymbolTreeNode(key, loadChildren, monitor);
		return node;
	}

	private SymbolCategoryNode getLabelsNode() {
		List<GTreeNode> children = getChildren();
		for (GTreeNode child : children) {
			if (child instanceof LabelCategoryNode) {
				return (SymbolCategoryNode) child;
			}
		}
		return null; // must be filtered out
	}

	private SymbolCategoryNode getFunctionsNode() {
		List<GTreeNode> children = getChildren();
		for (GTreeNode child : children) {
			if (child instanceof FunctionCategoryNode) {
				return (SymbolCategoryNode) child;
			}
		}
		return null; // must be filtered out
	}

	private SymbolCategoryNode getExternalsNode() {
		List<GTreeNode> children = getChildren();
		for (GTreeNode child : children) {
			if (child instanceof FunctionCategoryNode) {
				return (SymbolCategoryNode) child;
			}
		}
		return null; // must be filtered out
	}

	private SymbolCategoryNode getClassesNode() {
		List<GTreeNode> children = getChildren();
		for (GTreeNode child : children) {
			if (child instanceof ClassCategoryNode) {
				return (SymbolCategoryNode) child;
			}
		}
		return null; // must be filtered out
	}

	private SymbolCategoryNode getNamespacesNode() {
		List<GTreeNode> children = getChildren();
		for (GTreeNode child : children) {
			if (child instanceof NamespaceCategoryNode) {
				return (SymbolCategoryNode) child;
			}
		}
		return null; // must be filtered out
	}

	public SymbolNode symbolAdded(Symbol symbol, TaskMonitor monitor) {
		SymbolNode returnNode = null;
		List<GTreeNode> allChildren = getChildren();
		for (GTreeNode gNode : allChildren) {
			SymbolCategoryNode symbolNode = (SymbolCategoryNode) gNode;
			SymbolNode newNode = symbolNode.symbolAdded(symbol, monitor);
			if (newNode != null) {
				returnNode = newNode;  // doesn't matter which one we return
			}
		}
		return returnNode;
	}

	public void symbolRemoved(Symbol symbol, String oldName, TaskMonitor monitor) {

		// we have to loop--the symbol may exist in more than one category
		List<GTreeNode> allChildren = getChildren();
		for (GTreeNode gNode : allChildren) {
			SymbolCategoryNode symbolNode = (SymbolCategoryNode) gNode;
			symbolNode.symbolRemoved(symbol, oldName, monitor);
		}
	}

	public void symbolRemoved(Symbol symbol, Namespace oldNamespace, TaskMonitor monitor) {

		// we have to loop--the symbol may exist in more than one category
		List<GTreeNode> allChildren = getChildren();
		for (GTreeNode gNode : allChildren) {
			SymbolCategoryNode symbolNode = (SymbolCategoryNode) gNode;
			symbolNode.symbolRemoved(symbol, oldNamespace, monitor);
		}
	}

	public void rebuild() {
		setChildren(null);
	}

	@Override
	public Icon getIcon(boolean expanded) {
		return GLOBAL_ICON;
	}

	@Override
	public String getName() {
		return name;
	}

	@Override
	public String getToolTip() {
		return null;
	}

	@Override
	public boolean isLeaf() {
		return program == null;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) {
			return true;
		}
		if (!(o instanceof SymbolTreeRootNode)) {
			return false;
		}
		SymbolTreeRootNode node = (SymbolTreeRootNode) o;
		return getName().equals(node.getName());
	}
}
