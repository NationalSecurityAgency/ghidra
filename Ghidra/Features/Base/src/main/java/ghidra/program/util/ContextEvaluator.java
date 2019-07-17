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
package ghidra.program.util;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.RefType;

/**
 * ContextEvaluator provides a callback mechanism for the SymbolicPropogator as code is evaluated.
 * 
 */
public interface ContextEvaluator {

	/**
	 * Evaluate the current instruction given the context before the instruction is evaluated
	 * 
	 * @param context describes current state of registers
	 * @param instr instruction whose context has not yet been applied
	 * 
	 * @return true if evaluation should stop
	 */
	public boolean evaluateContextBefore(VarnodeContext context, Instruction instr);

	/**
	 * Evaluate the current instruction given the final context for the instruction
	 * 
	 * @param context describes current state of registers
	 * @param instr instruction whose context has been applied
	 * 
	 * @return true if evaluation should stop, false to continue evaluation
	 */
	boolean evaluateContext(VarnodeContext context, Instruction instr);

	/**
	 * Evaluate the reference that has been found on this instruction. Computed values that are used as an
	 * address will be passed to this function.  For example a value passed to a function, or a stored
	 * constant value.
	 * 
	 * @param context current program context
	 * @param instr instruction on which this reference was detected
	 * @param pcodeop the PcodeOp operation that is causing this reference
	 * @param address address being referenced
	 * @param size size of the item being referenced (only non-zero if load or store of data)
	 * @param refType reference type (flow, data/read/write)
	 * 
	 * @return false if the reference should be ignored (or has been taken care of by this routine)
	 */
	boolean evaluateReference(VarnodeContext context, Instruction instr, int pcodeop, Address address, int size,
			RefType refType);

	/**
	 * Evaluate a potential constant to be used as an address or an interesting constant that
	 * should have a reference created for it.  Computed values that are not know to be used as an address will
	 * be passed to this function.  For example a value passed to a function, or a stored constant value.
	 * 
	 * @param context current program context
	 * @param instr instruction on which this reference was detected
	 * @param pcodeop the PcodeOp operation that is causing this potential constant
	 * @param constant constant value (in constant.getOffset() )
	 * @param size size of constant value in bytes
	 * @param refType reference type (flow, data/read/write)
	 * 
	 * @return the original address unchanged if it should be a reference
	 *         null if the constant reference should not be created
	 *         a new address if the value should be a different address or address space
	 *             Using something like instr.getProgram().getAddressFactory().getDefaultAddressSpace();
	 */
	Address evaluateConstant(VarnodeContext context, Instruction instr, int pcodeop, Address constant, int size, RefType refType);
	
	/**
	 * Evaluate the instruction for an unknown destination
	 * 
	 * @param context current register context
	 * @param instruction instruction that has an unknown destination
	 * 
	 * @return true if the evaluation should stop, false to continue evaluation
	 */
	boolean evaluateDestination(VarnodeContext context, Instruction instruction);

	/**
	 * Called when a value is needed for a register that is unknown
	 * 
	 * @param context current register context
	 * @param instruction instruction that has an unknown destination
	 * @param node varnode for the register being accessed to obtain a value
	 * 
	 * @return null if the varnode should not have an assumed value.
	 *         a long value if the varnode such as a Global Register should have an assumed constant
	 */
	Long unknownValue(VarnodeContext context, Instruction instruction, Varnode node);

	/**
	 * Follow all branches, even if the condition evaluates to false, indicating it shouldn't be followed.
	 * 
	 * @return true if false evaluated conditional branches should be followed.
	 */
	boolean followFalseConditionalBranches();

	/**
	 * Evaluate the reference that has been found on this instruction that points into an unknown space that
	 * has been designated as tracked.
	 * 
	 * @param context current program context
	 * @param instr instruction on which this reference was detected
	 * @param address address being referenced
	 * 
	 * @return false if the reference should be ignored (or has been taken care of by this routine)
	 *         true to allow the reference to be created
	 */
	boolean evaluateSymbolicReference(VarnodeContext context, Instruction instr, Address address);

	/**
	 * Evaluate the address and check if the access to the value in the memory location to be read
	 * The address is read-only and is not close to this address.
	 *
	 * @param context current program context
	 * @param addr Address of memory where location is attempting to be read
	 * 
	 * @return true if the access should be allowed
	 */
	boolean allowAccess(VarnodeContext context, Address addr);
}
