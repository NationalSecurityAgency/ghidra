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
package ghidra.app.plugin.core.calltree;

import java.util.*;

import javax.swing.Icon;
import javax.swing.tree.TreePath;

import org.apache.commons.collections4.map.LazyMap;

import docking.widgets.tree.GTreeNode;
import docking.widgets.tree.GTreeSlowLoadingNode;
import generic.theme.GIcon;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.util.ProgramLocation;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import resources.MultiIcon;
import resources.icons.TranslateIcon;

/**
 * In general, a CallNode represents a function and its relationship (either a call reference or
 * a data reference) to the function of its parent node 
 */
public abstract class CallNode extends GTreeSlowLoadingNode {

	static final Icon FUNCTION_ICON = new GIcon("icon.plugin.calltree.function");
	static final Icon REFERENCE_ICON = new GIcon("icon.plugin.calltree.reference");
	static final Icon RECURSIVE_ICON = new GIcon("icon.plugin.calltree.recursive");

	protected CallTreeOptions callTreeOptions;
	private int depth = -1;

	/** Used to signal that this node has been marked for replacement */
	protected boolean invalid = false;

	/** Indicates whether the associated reference is a call reference **/
	protected boolean isCallReference = false;

	protected static Icon createIcon(Icon baseIcon, boolean isCallReference) {

		MultiIcon multiIcon = new MultiIcon(baseIcon, false, 32, 16);
		//@formatter:off
		TranslateIcon translateIcon = isCallReference ? 
				new TranslateIcon(FUNCTION_ICON, 16, 0) :
				new TranslateIcon(REFERENCE_ICON, 16, 0);
		//@formatter:on
		multiIcon.addIcon(translateIcon);
		return multiIcon;
	}

	public CallNode(CallTreeOptions callTreeOptions) {
		this.callTreeOptions = Objects.requireNonNull(callTreeOptions);
	}

	/**
	 * Returns this node's remote function, where remote is the source function for
	 * an incoming call or a destination function for an outgoing call.   May return
	 * null for nodes that do not have functions.
	 * @return the function or null
	 */
	public abstract Function getRemoteFunction();

	/**
	 * Returns a location that represents the caller of the callee.
	 * @return the location
	 */
	public abstract ProgramLocation getLocation();

	/**
	 * Returns the address that for the caller of the callee.
	 * @return the address
	 */
	public abstract Address getSourceAddress();

	/**
	 * Called when this node needs to be reconstructed due to external changes, such as when
	 * functions are renamed.
	 * 
	 * @return a new node that is the same type as 'this' node.
	 */
	abstract CallNode recreate();

	/**
	 * Returns true if the reference associated with this node is a call reference type.
	 * @return true if the reference associated with this node is a call reference type.
	 */
	public boolean isCallReference() {
		return isCallReference;
	}

	@Override
	public String getToolTip() {
		String refString = isCallReference ? "Called from " : "Referenced from ";
		return refString + getSourceAddress();
	}

	protected void addNode(LazyMap<Function, List<GTreeNode>> nodesByFunction, CallNode nodeToAdd) {

		if (ignoreNonCallReference(nodeToAdd)) {
			return;
		}

		Function function = nodeToAdd.getRemoteFunction();
		List<GTreeNode> nodes = nodesByFunction.get(function);
		if (nodes.isEmpty()) {
			nodes.add(nodeToAdd); // can can always add new nodes when the list is empty
			return;
		}

		for (GTreeNode node : nodes) {

			if (node.equals(nodeToAdd)) {
				return; // never add equal() nodes
			}

			// Don't allow a call reference and a non-call reference to the same remote function
			// at the same address.  One call node in the tree is sufficient to show the user that
			// the references exist.
			CallNode existingNode = (CallNode) node;
			if (resovleConflictingReferenceTypes(nodes, existingNode, nodeToAdd)) {
				return;
			}
		}

		// At this point we have verified that the node being added is not the same as an existing
		// node and has not replaced a similar node with a different type of reference.  We also
		// know that there are multiple child nodes for the given remote function.  Since we have
		// multiples, only add the new node if the user is allowing duplicate nodes.
		if (callTreeOptions.allowsDuplicates()) {
			nodes.add(nodeToAdd); // ok to add multiple nodes for this function with different addresses
			return;
		}

	}

	private boolean ignoreNonCallReference(CallNode nodeToAdd) {
		if (nodeToAdd.isCallReference()) {
			return false; // is a call reference; do not ignore node
		}

		// a non-call reference; check options
		return !callTreeOptions.allowsNonCallReferences();
	}

	private boolean resovleConflictingReferenceTypes(List<GTreeNode> nodes, CallNode existingNode,
			CallNode nodeToAdd) {

		//
		// This code is looking for a special case where the two nodes passed in both come from the
		// same address, point to the same function, but one is a call reference and the other is
		// not.  In this case, we prefer the call reference.
		//
		Address newAddress = nodeToAdd.getSourceAddress();
		Address exitingAddress = existingNode.getSourceAddress();
		if (!newAddress.equals(exitingAddress)) {
			return false; // different source addresses; nothing to do
		}

		if (nodeToAdd.isCallReference() == existingNode.isCallReference()) {
			return false; // same reference type; nothing to do
		}

		// The 2 given nodes point to the same function and from the same address. Remove the 
		// existing node if it is not a call reference.   Otherwise, if the new node is not a call
		// reference, then the existing node is and we should just throw away the new node.
		if (!existingNode.isCallReference()) {
			// swap the old node for the new one
			nodes.remove(existingNode);
			nodes.add(nodeToAdd);
		}
		// else {  // ignore the new node by returning true
		return true; // return true to signal we have handled the new node
	}

	protected class CallNodeComparator implements Comparator<GTreeNode> {
		@Override
		public int compare(GTreeNode o1, GTreeNode o2) {
			CallNode node1 = (CallNode) o1;
			CallNode node2 = (CallNode) o2;
			int addrCompare = node1.getSourceAddress().compareTo(node2.getSourceAddress());
			if (addrCompare != 0) {
				return addrCompare;
			}
			return Boolean.compare(node1.isCallReference, node2.isCallReference);

		}

	}

	@Override
	public int loadAll(TaskMonitor monitor) throws CancelledException {
		if (depth() > callTreeOptions.getRecurseDepth()) {
			return 1;
		}
		return super.loadAll(monitor);
	}

	private int depth() {
		if (depth < 0) {
			TreePath treePath = getTreePath();
			Object[] path = treePath.getPath();
			depth = path.length;
		}
		return depth;
	}

	boolean functionIsInPath() {
		TreePath path = getTreePath();
		Object[] pathComponents = path.getPath();
		for (Object pathComponent : pathComponents) {
			CallNode node = (CallNode) pathComponent;
			Function nodeFunction = node.getRemoteFunction();
			Function myFunction = getRemoteFunction();
			if (node != this && nodeFunction.equals(myFunction)) {
				return true;
			}
		}
		return false;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (!super.equals(obj)) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}

		CallNode other = (CallNode) obj;
		if (!Objects.equals(getSourceAddress(), other.getSourceAddress())) {
			return false;
		}
		if (other.isCallReference != isCallReference) {
			return false;
		}
		return Objects.equals(getRemoteFunction(), other.getRemoteFunction());
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = super.hashCode();
		result = prime * result + Boolean.hashCode(isCallReference);
		Function function = getRemoteFunction();
		result = prime * result + ((function == null) ? 0 : function.hashCode());
		Address sourceAddress = getSourceAddress();
		result = prime * result + ((sourceAddress == null) ? 0 : sourceAddress.hashCode());
		return result;
	}

}
