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
package ghidra.program.model.lang;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.UniqueAddressFactory;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOverride;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.RefType;

import java.util.ArrayList;

/**
 * InstructionPrototype is designed to describe one machine level instruction.
 * A language parser can return the same InstructionProtoype object for the 
 * same type node. Prototypes for instructions will normally be fixed for a node.
 */
public interface InstructionPrototype {
	public static final int INVALID_DEPTH_CHANGE = 16777216; // 2^24

	/**
	 * Get a new instance of a ParserContext.
	 * @param buf
	 * @param processorContext
	 * @return instruction ParserContext
	 * @throws MemoryAccessException
	 */
	public ParserContext getParserContext(MemBuffer buf, ProcessorContextView processorContext)
			throws MemoryAccessException;

	/**
	 * Get a ParserContext by parsing bytes outside of the normal disassembly process
	 * @param addr where the ParserContext is needed
	 * @param buffer of actual bytes
	 * @param processorContext
	 * @return
	 * @throws InsufficientBytesException
	 * @throws UnknownInstructionException
	 * @throws UnknownContextException
	 * @throws MemoryAccessException
	 */
	public ParserContext getPseudoParserContext(Address addr, MemBuffer buffer,
			ProcessorContextView processorContext) throws InsufficientBytesException,
			UnknownInstructionException, UnknownContextException, MemoryAccessException;

	/**
	 * @return true if instruction prototype expects one or more delay slotted
	 * instructions to exist.
	 */
	public boolean hasDelaySlots();

	/**
	 * @return true if instruction semantics have a CrossBuild instruction
	 * dependency which may require a robust InstructionContext with access
	 * to preceding instructions  
	 */
	public boolean hasCrossBuildDependency();

	/**
	 * Get the mnemonic for this CodeProtype.  Examples: "MOV" and
	 * "CALL" for instructions and "DB" and "DA" for data.
	 * @param context the instruction context
	 * @return the mnemonic for this CodePrototype.
	 */
	public String getMnemonic(InstructionContext context);

	/**
	 * Get the length of this CodeProtoype. 
	 *
	 * @return the length of this CodeProtoype.
	 */
	public int getLength();

	/**
	 * Get a Mask that describe which bits of this instruction determine
	 * the opcode.
	 *
	 * @return a Mask for the opcode bits or null if unknown.
	 */
	public Mask getInstructionMask();

	/**
	 * Get a Mask that describe which bits of this instruction determine
	 * the operand value.
	 *
	 * @return a Mask for the operand bits or null if unknown.
	 */
	public Mask getOperandValueMask(int operandIndex);

	/**
	 * Get the flow type of this instruction. Used
	 * for analysis purposes. i.e., how this
	 * instruction flows to the next instruction.
	 *
	 * @param context the instruction context
	 * @return flow type.
	 */
	public FlowType getFlowType(InstructionContext context);

	/**
	 * Get the number of delay slot instructions for this
	 * argument. This should be 0 for instructions which don't have a
	 * delay slot.  This is used to support the delay slots found on
	 * some RISC processors such as SPARC and the PA-RISC. This
	 * returns an integer instead of a boolean in case some other
	 * processor executes more than one instruction from a delay slot.
	 *
	 * @param context the instruction context
	 * 
	 * @return the number of delay slot instructions for this instruction.
	 */
	public int getDelaySlotDepth(InstructionContext context);

	/**
	 * @return the number of delay-slot instruction bytes which correspond
	 * to this prototype.
	 */
	public int getDelaySlotByteCount();

	/**
	 * Return true if this prototype was disassembled in a delay slot.
	 */
	boolean isInDelaySlot();

	/**
	 *  Return the number of operands in this instruction.
	 *
	 */
	public int getNumOperands();

	/**
	 * Get the type of a specific operand.
	 *
	 * @param opIndex the index of the operand. (zero based)
	 * @param context the instruction context.
	 * @return the type of the operand.
	 */
	public int getOpType(int opIndex, InstructionContext context);

	/**
	 * Get the Address for default flow after instruction.
	 *
	 * @param context the instruction context
	 *
	 * @return Address of fall through flow or null if flow
	 * does not fall through this instruction.
	 */
	public Address getFallThrough(InstructionContext context);

	/**
	 * Get the byte offset to the default flow after instruction.
	 * If this instruction does not have a fall-through due to flow
	 * behavior, this method will still return an offset which accounts for 
	 * the instruction length including delay slotted instructions if 
	 * applicable.
	 * 
	 * @param context the instruction context
	 * 
	 * @return int how much to add to the current address to get
	 * the fall through address.
	 */
	public int getFallThroughOffset(InstructionContext context);

	/**
	 * Get an array of Address objects for all flows other than
	 * a fall-through, null if no flows.
	 *
	 * @param context the instruction context.
	 * @return an array of Address objects for all flows other than
	 *  a fall-through, null if no flows.
	 */
	public Address[] getFlows(InstructionContext context);

	/**
	 * Get the separator strings between an operand.
	 * 
	 * The separator string for 0 are the characters before the first operand.
	 * The separator string for numOperands+1 are the characters after the last operand.
	 * 
	 * @param opIndex valid values are 0 thru numOperands+1
	 * @param context the instruction context
	 * @return separator string, or null if there is no string
	 */
	public String getSeparator(int opIndex, InstructionContext context);

	/**
	 * Get a List of Objects that can be used to render an operands representation.
	 * 
	 * @param opIndex operand to get the Representation List
	 * @param context the instruction context
	 * 
	 * @return ArrayList of Register, Address, Scalar, VariableOffset and Character objects
	 *         of null if the operation isn't supported
	 */
	public ArrayList<Object> getOpRepresentationList(int opIndex, InstructionContext context);

	/**
	 * If the indicated operand is an address, this gets the address value for 
	 * that operand
	 * @param opIndex index of the operand.
	 * @param context the instruction context.
	 * @return the address indicated by the operand
	 */
	public Address getAddress(int opIndex, InstructionContext context);

	/**
	 * If the indicated operand is a scalar, this gets the scalar value for 
	 * that operand
	 * @param opIndex index of the operand.
	 * @param context the instruction context
	 * @return the scalar for the indicated operand
	 */
	public Scalar getScalar(int opIndex, InstructionContext context);

	/**
	 * If the indicated operand is a register, this gets the register value 
	 * for that operand
	 * @param opIndex index of the operand.
	 * @param context the instruction context
	 * @return a register description for the indicated operand
	 */
	public Register getRegister(int opIndex, InstructionContext context);

	/**
	 * Get objects used by this operand (Address, Scalar, Register ...)
	 * @param opIndex the index of the operand. (zero based)
	 * @param context the instruction context
	 * @return an array of objects found at this operand.
	 */
	public Object[] getOpObjects(int opIndex, InstructionContext context);

	/**
	 * Get the suggested operand reference type.
	 * @param opIndex the index of the operand. (zero based)
	 * @param context the instruction context
	 * @param override if not null, steers local overrides of pcode generation
	 * @param uniqueFactory must be specified if flowOverride is not null
	 * @return reference type.
	 */
	public RefType getOperandRefType(int opIndex, InstructionContext context,
			PcodeOverride override, UniqueAddressFactory uniqueFactory);

	/**
	 * Return true if the operand at opIndex should have a delimiter following it.
	 * @param opIndex the index of the operand to test for having a delimiter.
	 */
	public boolean hasDelimeter(int opIndex);

	/**
	 * Get the Result objects produced/affected by this instruction
	 * These would probably only be Register or Address
	 * 
	 * @param context the instruction context
	 * 
	 * @return an array of objects that are used by this instruction
	 */
	public Object[] getInputObjects(InstructionContext context);

	/**
	 * Get the Result objects produced/affected by this instruction
	 * These would probably only be Register or Address
	 * 
	 * @param context the instruction context
	 * 
	 * @return an array of objects that are affected by this instruction
	 */
	public Object[] getResultObjects(InstructionContext context);

	/**
	 * Get an array of PCode operations (micro code) that this instruction
	 * performs.
	 * 
	 * @param context the instruction context
	 * @param override if not null, may indicate that different elements of the pcode generation are overridden
	 * @param uniqueFactory must be specified if flowOverride is not null
	 * @return array of PCODE,
	 *         zero length array if language doesn't support PCODE for this instruction
	 */
	public PcodeOp[] getPcode(InstructionContext context, PcodeOverride override,
			UniqueAddressFactory uniqueFactory);

	/**
	 * Same as getPcode but returns the operations in a packed format to optimize transfer to other processes
	 * @param context the instruction context
	 * @param override if not null, may indicate that different elements of the pcode generation are overridden
	 * @param uniqueFactory must be specified if flowOverride is not null
	 * @return
	 */
	public PackedBytes getPcodePacked(InstructionContext context, PcodeOverride override,
			UniqueAddressFactory uniqueFactory);

	/**
	 * Get an array of PCode operations (micro code) that a particular operand
	 * performs to compute its value.
	 *
	 * @param context the instruction context
	 * @param opIndex the index of the operand for which to get PCode.
	 * 
	 * @return array of PCODE,
	 *         zero length array if language doesn't support PCODE for this instruction
	 */
	public PcodeOp[] getPcode(InstructionContext context, int opIndex);

	/**
	 * Get processor language module associated with this prototype.
	 * @return language module
	 */
	public Language getLanguage();
}
