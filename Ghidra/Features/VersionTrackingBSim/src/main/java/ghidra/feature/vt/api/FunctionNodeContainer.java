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
package ghidra.feature.vt.api;

import java.util.*;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;

/**
 * Container of FunctionNodes corresponding to functions in a single Program
 */
public class FunctionNodeContainer {
	private Program program;						// Program containing all the functions
	private Map<Address, FunctionNode> addrToNode;	// Map from Address to FunctionNode representing the function

	public FunctionNodeContainer(Program program, List<FunctionNode> nodeList) {
		this.program = program;
		addrToNode = new TreeMap<Address, FunctionNode>();
		for (FunctionNode node : nodeList) {
			addrToNode.put(node.getAddress(), node);
		}
		generateCallGraph();
	}

	public Program getProgram() {
		return program;
	}

	/**
	 * Get the FunctionNode associated with a specific address
	 * @param addr the Address to search for
	 * @return the corresponding FunctionNode (or null if addr maps to nothing)
	 */
	public FunctionNode get(Address addr) {
		return addrToNode.get(addr);
	}

	/**
	 * @return the number of FunctionNodes held in this container
	 */
	public int size() {
		return addrToNode.size();
	}

	/**
	 * @return an iterator over all FunctionNodes in this container, in address order
	 */
	public Iterator<FunctionNode> iterator() {
		return addrToNode.values().iterator();
	}

	/**
	 * Generate program call-graph in terms of FunctionNodes
	 * Uses the call address attached to each raw FunctionNode
	 * Once the xrefs are built, the original call address arrays are released
	 */
	private void generateCallGraph() {
		FunctionManager mgr = program.getFunctionManager();
		for (FunctionNode node : addrToNode.values()) {								//Addresses are associated to nodes.
			if (node != null) {
				List<Address> callAddresses = node.releaseCallAddresses();
				for (Address addr : callAddresses) {
					FunctionNode kid;
					for (;;) {
						kid = addrToNode.get(addr);							//These nodes are the vertices in the call graph.
						if (kid != null) {
							break;
						}
						Function f = mgr.getFunctionAt(addr);	// If addr does not link to a node, it is most likely a thunk
						if (f == null) {
							break;
						}
						if (!f.isThunk()) {
							break;
						}
						addr = f.getThunkedFunction(false).getEntryPoint();	// Replace with address of thunked function
					}
					if (kid != null) {
						node.getChildren().add(kid);
						kid.getParents().add(node);
					}
				}
			}
		}
		return;
	}
}
