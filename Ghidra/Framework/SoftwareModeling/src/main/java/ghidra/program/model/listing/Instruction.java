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
package ghidra.program.model.listing;

import java.util.List;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.UniqueAddressFactory;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.RefType;

/**
 * Interface to define an instruction for a processor.
 */
public interface Instruction extends CodeUnit, ProcessorContext {

	public static final int INVALID_DEPTH_CHANGE = InstructionPrototype.INVALID_DEPTH_CHANGE; // 2^24

	/**
	 * Get the prototype for this instruction.
	 */
	public InstructionPrototype getPrototype();

	/**
	 * If operand is a pure Register, return the register.
	 * @param opIndex index of the operand.
	 * @return A register if the operand represents a register.
	 */
	public Register getRegister(int opIndex);

	/**
	 * Get objects used by this operand (Address, Scalar, Register ...)
	 * @param opIndex index of the operand.
	 */
	public Object[] getOpObjects(int opIndex);

	/**
	 * Get the Input objects used by this instruction.
	 * These could be Scalars, Registers, Addresses
	 * 
	 * @return an array of objects that are used by this instruction
	 */
	public Object[] getInputObjects();

	/**
	 * Get the Result objects produced/affected by this instruction
	 * These would probably only be Register or Address
	 * 
	 * @return an array of objects that are affected by this instruction
	 */
	public Object[] getResultObjects();

	/**
	 * Get the operand representation for the given operand index without markup.
	 *
	 * @param opIndex operand index
	 * 
	 * @return operand represented as a string.
	 */
	public String getDefaultOperandRepresentation(int opIndex);

	/**
	 * Get the operand representation for the given operand index.
	 * A list of Register, Address, Scalar, Character and String objects is returned - without markup!
	 *
	 * @param opIndex operand index
	 * 
	 * @return ArrayList of pieces of the operand representation.  Unsupported languages may return null.
	 */
	public List<Object> getDefaultOperandRepresentationList(int opIndex);

	/**
	 * Get the separator strings between an operand.
	 * 
	 * The separator string for 0 are the characters before the first operand.
	 * The separator string for numOperands+1 are the characters after the last operand.
	 * 
	 * @param opIndex valid values are 0 thru numOperands+1
	 * @return separator string, or null if there is no string
	 */
	public String getSeparator(int opIndex);

	/**
	 * Get the type of a specific operand.
	 *
	 * @param opIndex the index of the operand. (zero based)
	 * @return the type of the operand.
	 *
	 * @see OperandType
	 */
	public int getOperandType(int opIndex);

	/**
	 * Get the operand reference type for the given operand index.
	 * @param index operand index
	 */
	public RefType getOperandRefType(int index);

	/**
	 * Get default fall-through offset in bytes from start of instruction to the
	 * fallthrough instruction.  This accounts for any
	 * instructions contained with delay slots.
	 * @return default fall-through offset or zero (0) if instruction has no fallthrough
	 */
	public int getDefaultFallThroughOffset();

	/**
	 * Get the default fallthrough for this instruction.
	 * This accounts for any instructions contained with delay slots.
	 * @return fall-through address or null if instruction has no default fallthrough
	 */
	public Address getDefaultFallThrough();

	/**
	 * Get the fallthrough for this instruction, factoring in
	 * any fallthrough override and delay slotted instructions.
	 * @return fall-through address or null if instruction has no fallthrough
	 */
	public Address getFallThrough();

	/**
	 * Get the Address for the instruction that fell through to
	 * this instruction.
	 * This is useful for handling instructions that are found
	 * in a delay slot.
	 */
	public Address getFallFrom();

	/**
	 * Get an array of Address objects for all flows other than
	 * a fall-through.  This will include any flow references which
	 * have been added to the instruction.
	 * @return flow addresses or null if there are no flows
	 * 
	 */
	public Address[] getFlows();

	/**
	 * Get an array of Address objects for all default flows established
	 * by the underlying instruction prototype.  References are ignored.
	 * @return flow addresses or null if there are no flows
	 * 
	 */
	public Address[] getDefaultFlows();

	/**
	 * Get the flow type of this instruction (how this
	 * instruction flows to the next instruction).
	 */
	public FlowType getFlowType();

	/**
	 * Returns true if this instruction has no execution flow other than fall-through.
	 */
	public boolean isFallthrough();

	/**
	 * Returns true if this instruction has a fall-through flow.
	 */
	public boolean hasFallthrough();

	/**
	 * Returns the flow override which may have been set on this instruction.
	 */
	public FlowOverride getFlowOverride();

	/**
	 * Set the flow override for this instruction.
	 * @param flowOverride
	 */
	public void setFlowOverride(FlowOverride flowOverride);

	/**
	 * Get an array of PCode operations (micro code) that this instruction
	 * performs.  Flow overrides are not factored into pcode.
	 * 
	 * @return an array of Pcode operations,
	 *         a zero length array if the language does not support PCode
	 */
	public PcodeOp[] getPcode();

	/**
	 * Get an array of PCode operations (micro code) that this instruction
	 * performs.  NOTE: If includeOverrides is true, unique temporary varnodes
	 * may be produced which vary in size to those produced for other instructions.
	 * If your analysis is sensitive to this you should consider using 
	 * {@link InstructionPrototype#getPcode(InstructionContext, PcodeOverride, UniqueAddressFactory)}
	 * instead with your own {@link UniqueAddressFactory} to prevent duplication within 
	 * your scope of analysis.
	 * by this method may not be suitable for use with certain analysis
	 * @param includeOverrides if true any flow overrides will be factored
	 * into generated pcode.  
	 * @return an array of Pcode operations,
	 *         a zero length array if the language does not support PCode
	 */
	public PcodeOp[] getPcode(boolean includeOverrides);

	/**
	 * Get an array of PCode operations (micro code) that a particular operand
	 * performs to compute its value.
	 *
	 * @param opIndex index of the operand to retrieve PCode
	 * 
	 * @return an array of PCode operations,
	 *         a zero length array if the language does not support PCode
	 */
	public PcodeOp[] getPcode(int opIndex);

	/**
	 * Get the number of delay slot instructions for this
	 * argument. This should be 0 for instructions which don't have a
	 * delay slot.  This is used to support the delay slots found on
	 * some RISC processors such as SPARC and the PA-RISC. This
	 * returns an integer instead of a boolean in case some other
	 * processor executes more than one instruction from a delay slot.
	 */
	public int getDelaySlotDepth();

	/**
	 * Return true if this instruction was disassembled in a delay slot
	 */
	public boolean isInDelaySlot();

	/**
	 * Get the instruction following this one in address order.
	 */
	public Instruction getNext();

	/**
	 * Get the instruction before this one in address order.
	 */
	public Instruction getPrevious();

	/**
	 * Overrides the instruction's default fallthrough address to the given address.
	 * The given address may be null to indicate that the instruction has no fallthrough.
	 * @param addr the address to be used as this instructions fallthrough address.  May be null.
	 */
	public void setFallThrough(Address addr);

	/**
	 * Restores this instruction's fallthrough address back to the default fallthrough
	 * for this instruction.
	 *
	 */
	public void clearFallThroughOverride();

	/**
	 * Returns true if this instructions fallthrough has been overriden.
	 */
	public boolean isFallThroughOverridden();

	/**
	 * @return the instruction context for this instruction
	 */
	public InstructionContext getInstructionContext();

}
