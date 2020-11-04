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
import java.util.concurrent.atomic.AtomicInteger;

import javax.swing.tree.TreePath;

import org.apache.commons.collections4.map.LazyMap;

import docking.widgets.tree.GTreeNode;
import docking.widgets.tree.GTreeSlowLoadingNode;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.util.ProgramLocation;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public abstract class CallNode extends GTreeSlowLoadingNode {

	private boolean allowDuplicates;
	protected AtomicInteger filterDepth;
	private int depth = -1;

	/** Used to signal that this node has been marked for replacement */
	protected boolean invalid = false;

	public CallNode(AtomicInteger filterDepth) {
		this.filterDepth = filterDepth;
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

	protected Set<Reference> getReferencesFrom(Program program, AddressSetView addresses,
			TaskMonitor monitor) throws CancelledException {
		Set<Reference> set = new HashSet<>();
		ReferenceManager referenceManager = program.getReferenceManager();
		AddressIterator addressIterator = addresses.getAddresses(true);
		while (addressIterator.hasNext()) {
			monitor.checkCanceled();
			Address address = addressIterator.next();
			Reference[] referencesFrom = referenceManager.getReferencesFrom(address);
			if (referencesFrom != null) {
				for (Reference reference : referencesFrom) {
					set.add(reference);
				}
			}
		}
		return set;
	}

	/**
	 * True allows this node to contains children with the same name
	 * 
	 * @param allowDuplicates true to allow duplicate nodes
	 */
	protected void setAllowsDuplicates(boolean allowDuplicates) {
		this.allowDuplicates = allowDuplicates;
	}

	protected void addNode(LazyMap<Function, List<GTreeNode>> nodesByFunction,
			CallNode node) {

		Function function = node.getRemoteFunction();
		List<GTreeNode> nodes = nodesByFunction.get(function);
		if (nodes.contains(node)) {
			return; // never add equal() nodes
		}

		if (allowDuplicates) {
			nodes.add(node); // ok to add multiple nodes for this function with different addresses
		}

		if (nodes.isEmpty()) {
			nodes.add(node); // no duplicates allow; only add if this is the only node
			return;
		}

	}

	protected class CallNodeComparator implements Comparator<GTreeNode> {
		@Override
		public int compare(GTreeNode o1, GTreeNode o2) {
			return ((CallNode) o1).getSourceAddress().compareTo(((CallNode) o2).getSourceAddress());
		}
	}

	@Override
	public int loadAll(TaskMonitor monitor) throws CancelledException {
		if (depth() > filterDepth.get()) {
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
		return Objects.equals(getRemoteFunction(), other.getRemoteFunction());
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = super.hashCode();
		Function function = getRemoteFunction();
		result = prime * result + ((function == null) ? 0 : function.hashCode());
		Address sourceAddress = getSourceAddress();
		result = prime * result + ((sourceAddress == null) ? 0 : sourceAddress.hashCode());
		return result;
	}

}
