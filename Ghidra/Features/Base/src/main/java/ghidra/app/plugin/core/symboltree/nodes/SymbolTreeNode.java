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

import docking.widgets.tree.GTreeNode;
import docking.widgets.tree.GTreeSlowLoadingNode;
import ghidra.app.plugin.core.symboltree.SymbolTreeFilterState;
import ghidra.app.plugin.core.symboltree.SymbolTreeProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.task.TaskMonitor;

/**
 * Base class for all nodes that live in the {@link SymbolTreeProvider Symbol Tree}.  
 * 
 * <p>All nodes will provide a way to search for the node that represents a given symbol.  The
 * 'find' logic lives in this class so all nodes have this capability.  Some subclasses
 * of this interface, those with the potential for thousands of children, will break their 
 * children up into subgroups by name.  The search algorithm in this class will uses each 
 * node's {@link #getChildrenComparator()} method in order to be able to find the correct
 * symbol node whether or not the grouping nodes are used.   This allows each {@link GTreeNode}
 * to keep its default {@link GTreeNode#compareTo(GTreeNode)} method, while allow each 
 * parent node to sort its children differently.
 */
public abstract class SymbolTreeNode extends GTreeSlowLoadingNode {
	//@formatter:off
	static final DataFlavor LABEL_DATA_FLAVOR = new SymbolTreeDataFlavor("Symbol Tree Data Flavor - Labels");
	static final DataFlavor FUNCTION_DATA_FLAVOR = new SymbolTreeDataFlavor("Symbol Tree Data Flavor - Functions");
	static final DataFlavor CLASS_DATA_FLAVOR = new SymbolTreeDataFlavor("Symbol Tree Data Flavor - Classes");
	static final DataFlavor NAMESPACE_DATA_FLAVOR = new SymbolTreeDataFlavor("Symbol Tree Data Flavor - Namespaces");
	//@formatter:on

	public static final Comparator<Symbol> SYMBOL_COMPARATOR = (s1, s2) -> {
		// note: not really sure if we care about the cases where 'symbol' is null, as that 
		//       implies the symbol was deleted and the node will go away.  Just be consistent.

		if (s1 == null) {
			if (s2 != null) {
				return 1;
			}
		}

		if (s2 == null) {
			return -1;
		}

		int idCompare = (int) (s1.getID() - s2.getID());
		if (idCompare == 0) {
			// the exact same symbol
			return idCompare;
		}

		// different symbol objects; compare by address
		Address a1 = s1.getAddress();
		Address a2 = s2.getAddress();
		int result = a1.compareTo(a2);
		if (result != 0) {
			// different location; different symbol
			return result;
		}

		// same address, try the namespaces
		Namespace ns1 = s1.getParentNamespace();
		Namespace ns2 = s2.getParentNamespace();
		String path1 = ns1.getName(true);
		String path2 = ns2.getName(true);
		result = path1.compareTo(path2);
		if (result != 0) {
			// different namespaces
			return result;
		}

		// At this point we assume: same address, same name, same namespaces--use ID as a 
		// consistent way to sort
		return idCompare;
	};

	static final Comparator<GTreeNode> DEFAULT_NODE_COMPARATOR =
		(node1, node2) -> node1.compareTo(node2);

	/**
	 * Returns true if this node can be cut and moved to a different location.
	 * @return true if this node can be cut and moved to a different location.
	 */
	public abstract boolean canCut();

	/**
	 * Signals to this node that it has been cut during a cut operation, for example, like during
	 * a cut/paste operation.
	 * @param isCut true signals that the node has been cut; false that it is not cut.
	 */
	public abstract void setNodeCut(boolean isCut);

	/**
	 * Return true if the node has been cut.
	 * @return true if the node has been cut.
	 */
	public abstract boolean isCut();

	/**
	 * Gets the data flavor that this node supports for dragging.
	 * @return the data flavor that this node supports for dragging.
	 */
	public abstract DataFlavor getNodeDataFlavor();

	/**
	 * Returns true if this node can accept any of the given data flavors for dropping.
	 * @param dataFlavors the data flavors of an object being dragged.
	 * @return true if this node can accept any of the given data flavors for dropping.
	 */
	public abstract boolean supportsDataFlavors(DataFlavor[] dataFlavors);

	/**
	 * Returns the namespace for this symbol tree node.  Not all implementations contain symbols,
	 * but all category implementations represent a namespace and some symbol nodes represent a
	 * namespace.
	 * @return the namespace for this symbol tree node.
	 */
	public abstract Namespace getNamespace();

	/**
	 * Returns the comparator used to sort the children of this node.  This node will still 
	 * be sorted according to its own <code>compareTo</code> method, unless its parent has
	 * overridden this method.
	 * 
	 * @return the comparator used to sort this node's children
	 */
	public Comparator<GTreeNode> getChildrenComparator() {
		return DEFAULT_NODE_COMPARATOR;
	}

	/**
	 * Returns the symbol for this node, if it has one.
	 * 
	 * @return the symbol for this node; null if it not associated with a symbol
	 */
	public Symbol getSymbol() {
		// We use an odd inheritance hierarchy, where all nodes share this interface.  Not all
		// nodes have symbols, like a category node.  Stub this method out here and allow 
		// symbol nodes to return their value.
		return null;
	}

	protected SymbolTreeFilterState getFilterState() {
		SymbolTreeRootNode root = (SymbolTreeRootNode) getRoot();
		return root.getSymbolTreeFilterState();
	}

	/**
	 * Last resort method to find a symbol in the tree when the more direct approaches have failed.
	 * This method will visit each node in a depth first traversal, looking for the given symbol.
	 * Note that this method only searches the nodes that are currently loaded, it will not trigger
	 * any lazy node loading.
	 * The main use of this method is to find a node whose symbol was removed and the corresponding
	 * tree node needs to be deleted. The direct approach will fail if both the name and namespace
	 * where changed at same time since the event system sends two events and neither have the 
	 * all the necessary information to find the symbol efficiently.
	 * 
	 * @param symbol the symbol to search for
	 * @param monitor the TaskMonitor that can be used to cancel the operation
	 * @return the GTreeNode containing the symbol or null if not found
	 */
	protected final GTreeNode findNodeBruteForce(Symbol symbol, TaskMonitor monitor) {

		if (getSymbol() == symbol) {
			return this;
		}

		if (!isLoaded() || monitor.isCancelled()) {
			return null;
		}

		for (GTreeNode childNode : getChildren()) {
			if (monitor.isCancelled()) {
				return null;
			}
			if (!(childNode instanceof SymbolTreeNode)) {
				continue; // InProgressNode
			}

			SymbolTreeNode symbolNode = (SymbolTreeNode) childNode;
			GTreeNode foundNode = symbolNode.findNodeBruteForce(symbol, monitor);
			if (foundNode != null) {
				return foundNode;
			}
		}

		return null;
	}

	/**
	 * Finds the child node in this node that matches the given search key. The search key node
	 * will contain the symbol being searched for, but the name may not be the current symbol's
	 * name. This is to facilitate finding symbols in the tree whose name has been changed, but
	 * we know the old name.
	 * <P>
	 * This method normally just searches the immediate children of a node. However, if the node
	 * is an organization node, it will recursively descend into organization nodes to find the
	 * target symbol. It will never recurse into non-organization nodes.
	 * 
	 * @param key a special node used to search for a symbol. It allows for a different name than
	 * the actual symbol name.
	 * @param loadChildren if true, the node will load its children before searching. Otherwise, 
	 * if loadChildren is false and the node is not currently loaded, it will just return null.
	 * @return returns the node containing the searched for symbol if it is found; otherwise it
	 * returns null
	 */
	public SymbolTreeNode getMatchingChild(SymbolNode key, boolean loadChildren) {
		if (!loadChildren && !isLoaded()) {
			return null;
		}
		List<GTreeNode> children = getChildren();

		Comparator<GTreeNode> comparator = getChildrenComparator();
		int index = Collections.binarySearch(children, key, comparator);
		if (index < 0) {
			return null;
		}

		// We may have duplicate symbols, so our binary search may have resulted in the middle
		// of a run of duplicate names, so we must search around the found index.
		//
		// However, if the node at the index is an organization node, then we know that any 
		// duplicates will also be in the organization node. 
		// Normally, this search is only one level, but organization nodes have to be handled
		// specially. Since organization nodes add artificial layers to break up what would have
		// been a very large list of child nodes, the algorithm needs to recurse down through all
		// organization nodes to find the node that conceptually lives at this level.

		SymbolTreeNode node = (SymbolTreeNode) children.get(index);
		if (node instanceof OrganizationNode orgNode) {
			return orgNode.getMatchingChild(key, loadChildren);
		}

		int start = getStart(index, key, children, comparator);
		int end = getEnd(index, key, children, comparator);
		for (int i = start; i < end; i++) {
			node = (SymbolNode) children.get(i);
			if (node.getSymbol() == key.getSymbol()) {
				return node;
			}
		}
		return null;
	}

	private static int getStart(int index, SymbolNode key, List<GTreeNode> children,
			Comparator<GTreeNode> comparator) {
		for (int i = index - 1; i >= 0; i--) {
			GTreeNode node = children.get(i);
			int result = comparator.compare(key, node);
			if (result != 0) {
				return i + 1;
			}
		}
		return 0;
	}

	private static int getEnd(int index, SymbolNode key, List<GTreeNode> children,
			Comparator<GTreeNode> comparator) {
		for (int i = index + 1; i < children.size(); i++) {
			GTreeNode node = children.get(i);
			int result = comparator.compare(key, node);
			if (result != 0) {
				return i;	// the end is exclusive so don't subtract 1
			}
		}
		return children.size();
	}
}
