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
import java.util.Map.Entry;

import javax.swing.Icon;

import docking.widgets.tree.GTreeNode;
import generic.theme.GIcon;
import ghidra.app.plugin.core.symboltree.SymbolCategory;
import ghidra.app.util.NamespaceUtils;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class ClassCategoryNode extends SymbolCategoryNode {

	public static final Icon OPEN_FOLDER_CLASSES_ICON =
		new GIcon("icon.plugin.symboltree.node.category.classes.open");
	public static final Icon CLOSED_FOLDER_CLASSES_ICON =
		new GIcon("icon.plugin.symboltree.node.category.classes.closed");

	public ClassCategoryNode(Program program) {
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

	@Override
	public GTreeNode findSymbolTreeNode(SymbolNode key, boolean loadChildren, TaskMonitor monitor) {

		if ((!isLoaded() && !loadChildren) || monitor.isCancelled()) {
			return null;
		}

		Symbol symbol = key.getSymbol();
		Namespace parentNs = symbol.getParentNamespace();
		if (parentNs == globalNamespace) {
			// no need to search for the class in the tree; the class only lives at the top
			return findNode(this, key, loadChildren, monitor);
		}

		// set getAllClassNodes() for a description of the map
		Map<GTreeNode, List<Namespace>> classNodes =
			getAllClassNodes(symbol, parentNs, loadChildren, monitor);
		if (classNodes.isEmpty()) {
			return null;
		}

		// since the symbol lives in all of these paths, just pick one in a consistent way
		List<GTreeNode> keys = new ArrayList<>(classNodes.keySet());
		Collections.sort(keys);
		GTreeNode classNode = keys.get(0);
		List<Namespace> parentPath = classNodes.get(classNode);
		GTreeNode symbolParent =
			getNamespaceNode(classNode, parentPath, loadChildren, monitor);
		return findNode(symbolParent, key, loadChildren, monitor);
	}

	@Override
	public void symbolRemoved(Symbol symbol, Namespace oldNamespace, TaskMonitor monitor) {

		if (!isLoaded()) {
			return;
		}

		if (!supportsSymbol(symbol)) {
			return;
		}

		SymbolNode key = SymbolNode.createKeyNode(symbol, symbol.getName(), program);
		Namespace parentNs = symbol.getParentNamespace();
		if (parentNs == globalNamespace) {
			// no need to search for the class in the tree; the class only lives at the top
			GTreeNode symbolNode = findNode(this, key, false, monitor);
			if (symbolNode != null) {
				removeNode(symbolNode);
			}
			return;
		}

		// set getAllClassNodes() for a description of the map		
		Map<GTreeNode, List<Namespace>> classNodes =
			getAllClassNodes(symbol, oldNamespace, monitor);
		removeSymbol(key, classNodes, monitor);
	}

	@Override
	public void symbolRemoved(Symbol symbol, String oldName, TaskMonitor monitor) {
		if (!isLoaded()) {
			return;
		}

		if (!supportsSymbol(symbol)) {
			return;
		}

		SymbolNode key = SymbolNode.createKeyNode(symbol, oldName, program);
		Namespace parentNs = symbol.getParentNamespace();
		if (parentNs == globalNamespace) {
			// no need to search for the class in the tree; the class only lives at the top
			GTreeNode symbolNode = findNode(this, key, false, monitor);
			if (symbolNode != null) {
				removeNode(symbolNode);
			}
			return;
		}

		// set getAllClassNodes() for a description of the map
		Map<GTreeNode, List<Namespace>> classNodes = getAllClassNodes(symbol, parentNs, monitor);
		removeSymbol(key, classNodes, monitor);
	}

	private void removeSymbol(SymbolNode key, Map<GTreeNode, List<Namespace>> classNodes,
			TaskMonitor monitor) {

		Set<Entry<GTreeNode, List<Namespace>>> entries = classNodes.entrySet();
		for (Entry<GTreeNode, List<Namespace>> entry : entries) {

			if (monitor.isCancelled()) {
				return;
			}

			// start with the the top-level class node and walk the namespace path to find the 
			// parent for the given symbol
			GTreeNode classNode = entry.getKey();
			List<Namespace> parentPath = entry.getValue();
			GTreeNode symbolParent =
				getNamespaceNode(classNode, parentPath, false, monitor);
			GTreeNode symbolNode = findNode(symbolParent, key, false, monitor);
			if (symbolParent != null) {
				symbolParent.removeNode(symbolNode);
			}
		}
	}

	@Override
	public SymbolNode symbolAdded(Symbol symbol, TaskMonitor monitor) {
		if (!isLoaded()) {
			return null;
		}

		if (!supportsSymbol(symbol)) {
			return null;
		}

		if (symbol.getSymbolType() == symbolCategory.getSymbolType()) {
			doAddSymbol(symbol, this); // add new flat Class symbol
		}

		// set getAllClassNodes() for a description of the map
		SymbolNode lastNode = null;
		Namespace parentNs = symbol.getParentNamespace();
		Map<GTreeNode, List<Namespace>> classNodes = getAllClassNodes(symbol, parentNs, monitor);
		Set<Entry<GTreeNode, List<Namespace>>> entries = classNodes.entrySet();
		for (Entry<GTreeNode, List<Namespace>> entry : entries) {

			// start with the the top-level class node and walk the namespace path to find the 
			// parent for the given symbol
			GTreeNode classNode = entry.getKey();
			List<Namespace> parentPath = entry.getValue();
			GTreeNode symbolParent =
				getNamespaceNode(classNode, parentPath, false, monitor);
			if (symbolParent != null) {
				lastNode = doAddSymbol(symbol, symbolParent);
			}

		}

		return lastNode;
	}

	/*
	 	Uses the namespace path of the given symbol to create a mapping from this Classes category
	 	node's top-level child classes to the path from that child node to the given symbol node.
	 	
	 	This mapping allows us to find the symbol in multiple tree paths, such as in this example:
	 	
	 	Classes
	 		Class1		 			
	 			Label1
	 			BarNs
	 				Class2
	 					Label2
	 		Class2
	 			Label2
	 		
	 			
	 	In this tree, the Label2 symbol is in the tree twice.  The mapping created by this method
	 	will have have as keys both Class1 and Class2.  Class1 will be mapped to Class1/BarNs/Class2
	 	and Class2 will be mapped to Class2 (since it only has one namespace element). 
	 	
	 	This code is needed because this Classes category node will duplicate class nodes.  It puts
	 	each class at the top-level (as a flattened view) and then also includes each class under 
	 	any other parent class nodes. 
	 	
	 */
	private Map<GTreeNode, List<Namespace>> getAllClassNodes(Symbol symbol, Namespace parentNs,
			TaskMonitor monitor) {
		return getAllClassNodes(symbol, parentNs, false, monitor);
	}

	private Map<GTreeNode, List<Namespace>> getAllClassNodes(Symbol symbol, Namespace parentNs,
			boolean loadChildren, TaskMonitor monitor) {
		List<Namespace> parents = NamespaceUtils.getNamespaceParts(parentNs);
		Map<GTreeNode, List<Namespace>> classByPath = new HashMap<>();
		findAllClassNodes(this, parents, classByPath, loadChildren, monitor);
		return classByPath;
	}

	private void findAllClassNodes(GTreeNode searchNode, List<Namespace> namespaces,
			Map<GTreeNode, List<Namespace>> results, boolean loadChildren, TaskMonitor monitor) {

		if ((!searchNode.isLoaded() && !loadChildren) || monitor.isCancelled()) {
			return;
		}

		if (namespaces.isEmpty()) {
			return;
		}

		Namespace namespace = getNextClass(namespaces);
		if (namespace == null) {
			return;
		}

		Symbol nsSymbol = namespace.getSymbol();
		SymbolNode key = SymbolNode.createKeyNode(nsSymbol, nsSymbol.getName(), program);
		GTreeNode namespaceNode = findNode(searchNode, key, loadChildren, monitor);
		if (namespaceNode == null) {
			return; // we hit the last namespace
		}

		if (namespaceNode instanceof ClassSymbolNode) {
			List<Namespace> currentPath = new ArrayList<>(namespaces);
			currentPath.add(0, namespace);
			results.put(namespaceNode, currentPath);
		}

		// move to the next namespace
		findAllClassNodes(searchNode, namespaces, results, loadChildren, monitor);
	}

	private GhidraClass getNextClass(List<Namespace> namespaces) {
		while (namespaces.size() > 0) {
			Namespace ns = namespaces.remove(0);
			if (ns instanceof GhidraClass) {
				return (GhidraClass) ns;
			}
		}
		return null;
	}

	@Override
	protected List<GTreeNode> getSymbols(SymbolType type, TaskMonitor monitor)
			throws CancelledException {
		List<GTreeNode> list = new ArrayList<>();

		monitor.initialize(symbolTable.getNumSymbols());
		SymbolType symbolType = symbolCategory.getSymbolType();
		SymbolIterator it = symbolTable.getDefinedSymbols();
		while (it.hasNext()) {
			Symbol s = it.next();
			if (s != null && (s.getSymbolType() == symbolType)) {
				monitor.checkCancelled();
				list.add(SymbolNode.createNode(s, program));
			}
			monitor.incrementProgress(1);
		}
		Collections.sort(list, getChildrenComparator());
		return list;
	}
}
