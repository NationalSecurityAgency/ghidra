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
import ghidra.program.model.lang.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.util.CodeUnitInsertionException;

/**
 * Interface to define an instruction for a processor.
 */
public interface Instruction extends CodeUnit, ProcessorContext {

	public static final int INVALID_DEPTH_CHANGE = InstructionPrototype.INVALID_DEPTH_CHANGE; // 2^24
	public static final int MAX_LENGTH_OVERRIDE = 7;

	/**
	 * {@return the prototype for this instruction}
	 */
	public InstructionPrototype getPrototype();

	/**
	 * If a specific operand is a pure {@link Register}, return it
	 * 
	 * @param operandIndex the 0-up index of the operand.
	 * @return the register or null
	 */
	public Register getRegister(int operandIndex);

	/**
	 * Get objects used by this operand (Address, Scalar, Register ...)
	 * 
	 * @param operandIndex index of the operand.
	 * @return objects used by this operand (Address, Scalar, Register ...)
	 */
	public Object[] getOpObjects(int operandIndex);

	/**
	 * Get the Input objects used by this instruction.
	 * <p>
	 * These could be Scalars, Registers, Addresses
	 * 
	 * @return an array of objects that are used by this instruction
	 */
	public Object[] getInputObjects();

	/**
	 * Get the Result objects produced/affected by this instruction
	 * <p>
	 * These would probably only be Register or Address
	 * 
	 * @return an array of objects that are affected by this instruction
	 */
	public Object[] getResultObjects();

	/**
	 * Get the operand representation for the given operand index without markup.
	 *
	 * @param operandIndex operand index
	 * @return operand represented as a string.
	 */
	public String getDefaultOperandRepresentation(int operandIndex);

	/**
	 * Get the operand representation for the given operand index.
	 * <p>
	 * A list of Register, Address, Scalar, Character and String objects is returned - without
	 * markup!
	 *
	 * @param operandIndex operand index
	 * @return ArrayList of pieces of the operand representation. Unsupported languages may return
	 *         null.
	 */
	public List<Object> getDefaultOperandRepresentationList(int operandIndex);

	/**
	 * Get the separator strings between an operand.
	 * <p>
	 * The separator string for 0 are the characters before the first operand. The separator string
	 * for numOperands+1 are the characters after the last operand.
	 * 
	 * @param operandIndex valid values are 0 thru numOperands+1
	 * @return separator string, or null if there is no string
	 */
	public String getSeparator(int operandIndex);

	/**
	 * Get the type of a specific operand.
	 *
	 * @param operandIndex the index of the operand. (zero based)
	 * @return the type of the operand.
	 * @see OperandType
	 */
	public int getOperandType(int operandIndex);

	/**
	 * Get the operand reference type for the given operand index.
	 * 
	 * @param operandIndex operand index
	 * @return the operand reference type for the given operand index.
	 */
	public RefType getOperandRefType(int operandIndex);

	/**
	 * Get default fall-through offset in bytes from start of instruction to the fall-through
	 * instruction.
	 * <p>
	 * This accounts for any instructions contained with delay slots.
	 * 
	 * @return default fall-through offset or zero (0) if instruction has no fall through
	 */
	public int getDefaultFallThroughOffset();

	/**
	 * Get the default fall through for this instruction.
	 * <p>
	 * This accounts for any instructions contained with delay slots.
	 * 
	 * @return fall-through address or null if instruction has no default fall through
	 */
	public Address getDefaultFallThrough();

	/**
	 * Get the fall through for this instruction, factoring in any fall-through override and delay
	 * slotted instructions.
	 * 
	 * @return fall-through address or null if instruction has no fall through
	 */
	public Address getFallThrough();

	/**
	 * {@return the {@link Address} for the instruction that fell through to this instruction}
	 * <p>
	 * This is useful for handling instructions that are found in a delay slot.
	 * <p>
	 * Note: if an instruction is in a delay slot, then it may have a branch into the delay slot,
	 * which is handled as follows
	 * 
	 * <pre>
	 * JMPIF Y, X
	 *   lab:
	 *     _ADD         getFallFrom() = JMPIF
	 * MOV              getFallFrom() = _ADD
	 * 
	 * JMP Y, X
	 *   lab:
	 *     _ADD         getFallFrom() = null
	 * MOV              getFallFrom() = _ADD
	 *
	 * JMPIF Y, X
	 *     _ADD         getFallFrom() = JMPIF
	 * MOV              getFallFrom() = JMPIF
	 *   
	 * JMP Y, X
	 *     _ADD         getFallFrom() = JMP
	 * MOV              getFallFrom() = null
	 * </pre>
	 */
	public Address getFallFrom();

	/**
	 * Get an array of {@link Address}es for all flows other than a fall-through.
	 * <p>
	 * This will include any flow references which have been added to the instruction. Note the
	 * result may include {@link Address#NO_ADDRESS} to indicate flow to an address that could not
	 * be evaluated, e.g., to {@code inst_next2} when the skipped instruction could not be parsed.
	 * 
	 * @return flow addresses or null if there are no flows
	 */
	public Address[] getFlows();

	/**
	 * Get an array of {@link Address}es for all default flows established by the underlying
	 * instruction prototype.
	 * <p>
	 * References are ignored. Note the result may include {@link Address#NO_ADDRESS} to indicate
	 * flow to an address that could not be evaluated, e.g., to {@code inst_next2} when the skipped
	 * instruction could not be parsed.
	 * 
	 * @return flow addresses or null if there are no flows
	 */
	public Address[] getDefaultFlows();

	/**
	 * {@return the flow type of this instruction (how this instruction flows to the next
	 * instruction)}
	 */
	public FlowType getFlowType();

	/**
	 * {@return true if this instruction has no execution flow other than fall-through}
	 */
	public boolean isFallthrough();

	/**
	 * {@return true if this instruction has a fall-through flow}
	 */
	public boolean hasFallthrough();

	/**
	 * {@return the flow override which may have been set on this instruction}
	 */
	public FlowOverride getFlowOverride();

	/**
	 * Set the flow override for this instruction.
	 * 
	 * @param flowOverride flow override setting or {@link FlowOverride#NONE} to clear.
	 */
	public void setFlowOverride(FlowOverride flowOverride);

	/**
	 * Set instruction length override.
	 * <p>
	 * Specified length must be in the range 0..7 where 0 clears the setting and adopts the default
	 * length. The specified length must be less than the actual number of bytes consumed by the
	 * prototype and be a multiple of the language specified instruction alignment.
	 * <p>
	 * NOTE: Use of the feature with a delay slot instruction is discouraged.
	 * 
	 * @param length effective instruction code unit length.
	 * @throws CodeUnitInsertionException if expanding instruction length conflicts with another
	 *             instruction or length is not a multiple of the language specified instruction
	 *             alignment.
	 */
	public void setLengthOverride(int length) throws CodeUnitInsertionException;

	/**
	 * Determine if an instruction length override has been set.
	 * 
	 * @return true if length override has been set else false.
	 */
	public boolean isLengthOverridden();

	/**
	 * Get the actual number of bytes parsed when forming this instruction.
	 * <p>
	 * While this method will generally return the same value as {@link #getLength()}, its value
	 * will differ when {@link #setLengthOverride(int)} has been used. In addition, it is important
	 * to note that {@link #getMaxAddress()} will always reflect a non-overlapping address which
	 * reflects {@link #getLength()}.
	 * <p>
	 * This method is equivalent to the following code for a given instruction:
	 * 
	 * <pre>
	 * {@link InstructionPrototype} proto = instruction.{@link #getPrototype()};
	 * int length = proto.{@link InstructionPrototype#getLength() getLength()};
	 * </pre>
	 * 
	 * @return the actual number of bytes parsed when forming this instruction
	 */
	public int getParsedLength();

	/**
	 * Get the actual bytes parsed when forming this instruction.
	 * <p>
	 * While this method will generally return the same value as {@link #getBytes()}, it will return
	 * more bytes when {@link #setLengthOverride(int)} has been used. In this override situation,
	 * the bytes returned will generally duplicate some of the parsed bytes associated with the next
	 * instruction that this instruction overlaps.
	 * <p>
	 * This method is equivalent to the following code for a given instruction:
	 * 
	 * <pre>
	 * {@link InstructionPrototype} proto = instruction.{@link #getPrototype()};
	 * {@link Memory} mem = instruction.{@link #getMemory()};
	 * byte[] bytes = mem.getBytes(instruction.{@link #getAddress()}, proto.getLength());
	 * int length = proto.{@link InstructionPrototype#getLength() getLength()};
	 * </pre>
	 * 
	 * @return the actual number of bytes parsed when forming this instruction
	 * @throws MemoryAccessException if the full number of bytes could not be read
	 */
	public byte[] getParsedBytes() throws MemoryAccessException;

	/**
	 * Get an array of p-code operations (micro code) that this instruction performs.
	 * <p>
	 * Flow overrides are not factored into p-code.
	 * 
	 * @return an array of p-code operations, a zero length array if the language does not support
	 *         p-code
	 */
	public PcodeOp[] getPcode();

	/**
	 * Get an array of p-code operations (micro code) that this instruction performs.
	 * <p>
	 * NOTE: If includeOverrides is true, unique temporary varnodes may be produced which vary in
	 * size to those produced for other instructions.
	 * 
	 * @param includeOverrides if true any flow overrides will be factored into generated p-code.
	 * @return an array of p-code operations, a zero length array if the language does not support
	 *         p-code
	 */
	public PcodeOp[] getPcode(boolean includeOverrides);

	/**
	 * Get an array of p-code operations (micro code) that a particular operand performs to compute
	 * its value.
	 *
	 * @param operandIndex index of the operand to retrieve p-code
	 * 
	 * @return an array of p-code operations, a zero length array if the language does not support
	 *         p-code
	 */
	public PcodeOp[] getPcode(int operandIndex);

	/**
	 * Get the number of delay slot instructions for this argument.
	 * <p>
	 * This should be 0 for instructions which don't have a delay slot. This is used to support the
	 * delay slots found on some RISC processors such as SPARC and the PA-RISC. This returns an
	 * integer instead of a boolean in case some other processor executes more than one instruction
	 * from a delay slot.
	 * 
	 * @return delay slot depth (number of instructions)
	 */
	public int getDelaySlotDepth();

	/**
	 * {@return true if this instruction was disassembled in a delay slot}
	 */
	public boolean isInDelaySlot();

	/**
	 * {@return the instruction following this one in address order or null if none found}
	 */
	public Instruction getNext();

	/**
	 * {@return the instruction before this one in address order or null if none found}
	 */
	public Instruction getPrevious();

	/**
	 * Override the instruction's default fall-through address to the given address.
	 * <p>
	 * The given address may be null to indicate that the instruction has no fall through.
	 * 
	 * @param addr the address to be used as this instructions fall-through address. May be null.
	 */
	public void setFallThrough(Address addr);

	/**
	 * Restores this instruction's fall-through address back to the default fall through for this
	 * instruction.
	 */
	public void clearFallThroughOverride();

	/**
	 * {@return true if this instruction's fall through has been overridden}
	 */
	public boolean isFallThroughOverridden();

	/**
	 * {@return the instruction context for this instruction}
	 */
	public InstructionContext getInstructionContext();
}
