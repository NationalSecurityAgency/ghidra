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
import ghidra.app.plugin.core.symboltree.SymbolTreeProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
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
	 * Returns true if this nodes handles paste operations
	 * @return true if this nodes handles paste operations
	 */
	public abstract boolean canPaste(List<GTreeNode> pastedNodes);

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

	/**
	 * Locates the node that contains the given symbol.
	 * 
	 * <p><b>Note: </b>This can degenerate into a brute-force search algorithm, but works in 
	 * all normal cases using a binary search.
	 *  
	 * @param key the node used to find an existing node.  This node is a node created that is
	 *        used by the Comparators to perform binary searches.  These can be fabricated 
	 *        by using {@link SymbolNode#createNode(Symbol, Program)}
	 * @param loadChildren if true then children should be loaded, else quit early if 
	 *        children are not loaded.
	 * @param monitor the task monitor
	 * @return the node that contains the given symbol.
	 */
	public GTreeNode findSymbolTreeNode(SymbolNode key, boolean loadChildren,
			TaskMonitor monitor) {

		// if we don't have to loadChildren and we are not loaded get out.
		if (!loadChildren && !isLoaded()) {
			return null;
		}

		List<GTreeNode> children = getChildren();
		int index = Collections.binarySearch(children, key, getChildrenComparator());
		if (index >= 0) {
			GTreeNode node = children.get(index);
			SymbolTreeNode symbolNode = (SymbolTreeNode) node;
			Symbol searchSymbol = key.getSymbol();
			if (symbolNode.getSymbol() == searchSymbol) {
				return node;
			}

			// At this point we know that the given child is not itself a symbol node, but it 
			// may contain a child that contains the symbol node (some symbol nodes will
			// themselves contain more symbol nodes).  
			// Ask that child to search.  Leave this method regardless, as if this child does
			// not have it, then none of the others will.
			node = symbolNode.findSymbolTreeNode(key, loadChildren, monitor);
			return node;
		}

		// Brute-force lookup in each child.  This will not typically be called.
		for (GTreeNode childNode : children) {
			if (monitor.isCancelled()) {
				return null;
			}
			if (!(childNode instanceof SymbolTreeNode)) {
				continue; // InProgressNode
			}

			SymbolTreeNode symbolNode = (SymbolTreeNode) childNode;
			GTreeNode foundNode = symbolNode.findSymbolTreeNode(key, loadChildren, monitor);
			if (foundNode != null) {
				return foundNode;
			}
		}

		return null;
	}
}
