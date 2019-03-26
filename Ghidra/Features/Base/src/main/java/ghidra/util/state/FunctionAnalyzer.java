/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.util.state;

import ghidra.program.model.address.Address;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.RefType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import java.util.List;

public interface FunctionAnalyzer {

	/**
	 * Callback indicating that an absolute stack reference was encountered.  A non-load/store
	 * operation will have a -1 for both storageSpaceId and size.
	 * @param op pcode operation
	 * @param instrOpIndex opIndex associated with reference or -1 if it could not be determined
	 * @param stackOffset stack offset
	 * @param size access size or -1 if not applicable
	 * @param storageSpaceID storage space ID or -1 if not applicable
	 * @param refType read/write/data reference type
	 * @param monitor task monitor
	 * @throws CancelledException if callback canceled by monitor
	 */
	void stackReference(PcodeOp op, int instrOpIndex, int stackOffset, int size, int storageSpaceID, RefType refType, TaskMonitor monitor) throws CancelledException;
	
	/**
	 * Callback indicating that a computed stack reference was encountered.  A non-load/store
	 * operation will have a -1 for both storageSpaceId and size.
	 * @param op pcode operation
	 * @param instrOpIndex opIndex associated with reference or -1 if it could not be determined
	 * @param computedStackOffset stack offset computation (i.e., VarnodeOperation w/ stack pointer)
	 * @param size access size or -1 if not applicable
	 * @param storageSpaceID storage space ID or -1 if not applicable
	 * @param refType read/write/data reference type
	 * @param monitor task monitor
	 * @throws CancelledException if callback canceled by monitor
	 */
	void stackReference(PcodeOp op, int instrOpIndex, VarnodeOperation computedStackOffset, int size, int storageSpaceID, RefType refType, TaskMonitor monitor) throws CancelledException;
	
	/**
	 * Callback indicating that an absolute memory reference was encountered
	 * @param op pcode operation
	 * @param instrOpIndex opIndex associated with reference or -1 if it could not be determined
	 * @param storageVarnode absolute storage Varnode
	 * @param refType read/write/data reference type
	 * @param monitor task monitor
	 * @throws CancelledException if callback canceled by monitor
	 */
	void dataReference(PcodeOp op, int instrOpIndex, Varnode storageVarnode, RefType refType, TaskMonitor monitor) throws CancelledException;

	/**
	 * Callback indicating that an indirect/computed memory reference was encountered using an indirect/computed offset
	 * @param op pcode operation
	 * @param instrOpIndex opIndex associated with reference or -1 if it could not be determined
	 * @param offsetVarnode indirect/computed offset
	 * @param size access size or -1 if not applicable
	 * @param storageSpaceID storage space ID
	 * @param refType read/write/data reference type
	 * @param monitor task monitor
	 * @throws CancelledException if callback canceled by monitor
	 */
	void indirectDataReference(PcodeOp op, int instrOpIndex, Varnode offsetVarnode, int size, int storageSpaceID, RefType refType, TaskMonitor monitor) throws CancelledException;

	/**
	 * Callback indicating that a call/branch destination was identified.  
	 * Analyzer should create reference if appropriate
	 * Keep in mind that there could be other unidentified destinations.
	 * @param op branch or call flow operation
	 * @param instrOpIndex opIndex associated with reference or -1 if it could not be determined
	 * @param destAddr destination address
	 * @param results contains previous states leading upto the currentState
	 * @param currentState current state at the branch/call
	 * @param monitor task monitor
	 * @return true if destination should be disassembled if not already
	 * @throws CancelledException if callback canceled by monitor
	 */
	boolean resolvedFlow(PcodeOp op, int instrOpIndex, Address destAddr, ContextState currentState, ResultsState results, TaskMonitor monitor) throws CancelledException;

	/**
	 * Callback indicating that a computed call/branch destination was not resolved.
	 * @param op indirect branch or call flow operation
	 * @param instrOpIndex opIndex associated with reference or -1 if it could not be determined
	 * @param destination destination identified as a Varnode (may be an expression represented by
	 * a {@link VarnodeOperation}
	 * @param results contains previous states leading upto the currentState
	 * @param currentState current state at the branch/call
	 * @param monitor task monitor
	 * @return list of resolved destinations which should be used or null.  List of destination
	 * addresses will trigger disassembly where necessary.
	 * @throws CancelledException if callback cancelled by monitor
	 */
	List<Address> unresolvedIndirectFlow(PcodeOp op, int instrOpIndex, Varnode destination, ContextState currentState, ResultsState results, TaskMonitor monitor) throws CancelledException;
	
}
