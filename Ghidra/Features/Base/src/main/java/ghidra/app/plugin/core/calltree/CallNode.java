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

import javax.swing.tree.TreePath;

import org.apache.commons.collections4.map.LazyMap;

import docking.widgets.tree.GTreeNode;
import docking.widgets.tree.GTreeSlowLoadingNode;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.util.ProgramLocation;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * In general, a CallNode represents a function and its relationship (either a call reference or
 * a data reference) to the function of its parent node 
 */
public abstract class CallNode extends GTreeSlowLoadingNode {

	protected CallTreeOptions callTreeOptions;
	private int depth = -1;

	/** Used to signal that this node has been marked for replacement */
	protected boolean invalid = false;

	/** Indicates whether the associated reference is a call reference **/
	protected boolean isCallRef = false;

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


	@Override
	public String getToolTip() {
		String refString = isCallRef ? "Called from " : "Referenced from ";
		return refString + getSourceAddress();
	}

	protected void addNode(LazyMap<Function, List<GTreeNode>> nodesByFunction, CallNode nodeToAdd) {

		Function function = nodeToAdd.getRemoteFunction();
		List<GTreeNode> nodes = nodesByFunction.get(function);

		GTreeNode nodeToRemove = null;
		for (GTreeNode node : nodes) {
			if (node.equals(nodeToAdd)) {
				return; // never add equal() nodes
			}
			// don't allow a call reference and a non-call node to the same remote function
			// at the same address 
			CallNode callNode = (CallNode) node;
			if (nodeToAdd.isCallRef != callNode.isCallRef) {
				if (Objects.equals(nodeToAdd.getSourceAddress(), callNode.getSourceAddress())) {
					if (Objects.equals(nodeToAdd.getRemoteFunction(),
						callNode.getRemoteFunction())) {
						if (nodeToAdd.isCallRef) {
							return;  // don't replace a call node with a non-call node
						}
						// add the call node and remove the non-call node
						nodeToRemove = callNode;
						break;
					}
				}
			}
		}
		if (nodeToRemove != null) {
			nodes.remove(nodeToRemove);
			nodes.add(nodeToAdd);
			return;
		}

		if (callTreeOptions.allowsDuplicates()) {
			nodes.add(nodeToAdd); // ok to add multiple nodes for this function with different addresses
			return;
		}

		if (nodes.isEmpty()) {
			nodes.add(nodeToAdd); // no duplicates allowed; only add if this is the only node
			return;
		}

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
			return Boolean.compare(node1.isCallRef, node2.isCallRef);

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
		if (other.isCallRef != isCallRef) {
			return false;
		}
		return Objects.equals(getRemoteFunction(), other.getRemoteFunction());
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = super.hashCode();
		result = prime * result + Boolean.hashCode(isCallRef);
		Function function = getRemoteFunction();
		result = prime * result + ((function == null) ? 0 : function.hashCode());
		Address sourceAddress = getSourceAddress();
		result = prime * result + ((sourceAddress == null) ? 0 : sourceAddress.hashCode());
		return result;
	}

}
