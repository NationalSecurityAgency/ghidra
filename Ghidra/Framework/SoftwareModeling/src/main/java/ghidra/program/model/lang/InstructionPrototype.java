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
package ghidra.program.model.lang;

import java.io.IOException;
import java.util.ArrayList;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.VariableOffset;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.pcode.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.RefType;

/**
 * InstructionPrototype is designed to describe one machine level instruction. A language parser can
 * return the same InstructionProtoype object for the same type node. Prototypes for instructions
 * will normally be fixed for a node.
 */
public interface InstructionPrototype {
	/** Sentinel value to indicate an invalid depth change */
	public static final int INVALID_DEPTH_CHANGE = 1 << 24;

	/**
	 * {@return a new instance of an instruction {@link ParserContext}}
	 * 
	 * @param buf the memory from which this prototype was parsed, or an equivalent cache
	 * @param processorContext the (incoming) processor context during parse
	 * @throws MemoryAccessException if the memory buffer cannot be accessed
	 */
	public ParserContext getParserContext(MemBuffer buf, ProcessorContextView processorContext)
			throws MemoryAccessException;

	/**
	 * {@return a ParserContext by parsing bytes outside of the normal disassembly process}
	 * 
	 * @param address where the ParserContext is needed, i.e., the first address of an instruction
	 *            to be parsed
	 * @param buffer of actual bytes
	 * @param processorContext the (incoming) processor context
	 * @throws InsufficientBytesException if not enough bytes are in the buffer
	 * @throws UnknownInstructionException if the bytes do not constitute a valid instruction
	 * @throws UnknownContextException if contextual dependencies, e.g. {@code crossbuild}
	 *             instructions, are not available
	 * @throws MemoryAccessException if the memory buffer cannot be accessed
	 */
	public ParserContext getPseudoParserContext(Address address, MemBuffer buffer,
			ProcessorContextView processorContext) throws InsufficientBytesException,
			UnknownInstructionException, UnknownContextException, MemoryAccessException;

	/**
	 * {@return true if instruction prototype expects one or more delay slotted instructions to
	 * exist}
	 */
	public boolean hasDelaySlots();

	/**
	 * {@return true if instruction semantics have a {@code crossbuild} instruction dependency which
	 * may require a robust {@link InstructionContext} with access to preceding instructions}
	 */
	public boolean hasCrossBuildDependency();

	/**
	 * {@return true if instruction semantics contain a reference to {@code inst_next2}}.
	 */
	public boolean hasNext2Dependency();

	/**
	 * {@return the mnemonic for this prototype}
	 * <p>
	 * Examples: "{@code MOV}" and "{@code CALL}"
	 * 
	 * @param context the instruction context
	 */
	public String getMnemonic(InstructionContext context);

	/**
	 * {@return the length in bytes of this prototype}
	 */
	public int getLength();

	/**
	 * {@return the {@link Mask} that describe which bits of this instruction determine the opcode,
	 * or null if unknown}
	 */
	public Mask getInstructionMask();

	/**
	 * {@return the {@link Mask} that describe which bits of this instruction determine a specific
	 * operand's value, or null if unknown}
	 * 
	 * @param operandIndex the 0-up index of the operand
	 */
	public Mask getOperandValueMask(int operandIndex);

	/**
	 * {@return the flow type of this instruction}
	 * <p>
	 * This is used for analysis purposes. i.e., how this instruction flows to the next instruction.
	 *
	 * @param context the instruction context
	 */
	public FlowType getFlowType(InstructionContext context);

	/**
	 * {@return the number of delay slot instructions following this instruction}
	 * <p>
	 * This should be 0 for instructions which don't have a delay slot. This is used to support the
	 * delay slots found on some RISC processors such as SPARC and the PA-RISC. This returns an
	 * integer instead of a boolean in case some other processor executes more than one instruction
	 * from a delay slot.
	 *
	 * @param context the instruction context
	 */
	public int getDelaySlotDepth(InstructionContext context);

	/**
	 * {@return the number of delay-slot instruction bytes which correspond to this prototype}
	 */
	public int getDelaySlotByteCount();

	/**
	 * {@return true if this prototype was disassembled in a delay slot}
	 */
	boolean isInDelaySlot();

	/**
	 * {@return the number of operands in this instruction}
	 */
	public int getNumOperands();

	/**
	 * {@return the type of a specific operand}
	 *
	 * @param operandIndex the 0-up index of the operand
	 * @param context the instruction context.
	 */
	public int getOpType(int operandIndex, InstructionContext context);

	/**
	 * {@return the {@link Address} for fall-through flow after this instruction, or null if flow
	 * cannot fall through this instruction}
	 *
	 * @param context the instruction context
	 */
	public Address getFallThrough(InstructionContext context);

	/**
	 * {@return the byte offset to the fall-through flow after this instruction}
	 * <p>
	 * Ordinarily, this is just the length (in bytes) of this instruction. However, if this
	 * instruction has delay-slotted instruction(s), their lengths are included. Even if flow cannot
	 * fall through this instruction, this method will still return a the fall-through offset.
	 * 
	 * @param context the instruction context
	 */
	public int getFallThroughOffset(InstructionContext context);

	/**
	 * {@return the {@link Address}es for all flows other than a fall-through, or null if no flows}
	 * <p>
	 * A null return is equivalent to an empty array. Note the result may include
	 * {@link Address#NO_ADDRESS} to indicate flow to an address that could not be evaluated, e.g.,
	 * to {@code inst_next2} when the skipped instruction could not be parsed.
	 *
	 * @param context the instruction context.
	 */
	public Address[] getFlows(InstructionContext context);

	/**
	 * {@return the separator string before a specific operand, or null}
	 * <p>
	 * In particular, the separator string for operand 0 are the characters <em>before</em> the
	 * first operand. The separator string for {@code numOperands} are the characters <em>after</em>
	 * the last operand. A null return value is equivalent to an empty string.
	 * 
	 * @param operandIndex valid values are 0 thru {@code numOperands}, inclusive
	 */
	public String getSeparator(int operandIndex);

	/**
	 * {@return a the objects for rendering an operand's representation}
	 * <p>
	 * Each element is one of {@link Address}, {@link Register}, {@link Scalar},
	 * {@link VariableOffset}, {@link Character}, or null. This method may also return null (as in
	 * no list at all) if the operation is not supported. Nulls should be rendered as empty strings.
	 * 
	 * @param operandIndex the 0-up index of the operand
	 * @param context the instruction context
	 */
	public ArrayList<Object> getOpRepresentationList(int operandIndex, InstructionContext context);

	/**
	 * {@return the {@link Address} value of a specific operand, or null if its value is not an
	 * {@link Address}}
	 * 
	 * @param operandIndex the 0-up index of the operand
	 * @param context the instruction context.
	 */
	public Address getAddress(int operandIndex, InstructionContext context);

	/**
	 * {@return the {@link Register} value of a specific operand, or null if its value is not an
	 * {@link Register}}
	 * 
	 * @param operandIndex the 0-up index of the operand
	 * @param context the instruction context
	 */
	public Register getRegister(int operandIndex, InstructionContext context);

	/**
	 * {@return the {@link Scalar} value of a specific operand, or null if its value is not an
	 * {@link Scalar}}
	 * 
	 * @param operandIndex the 0-up index of the operand
	 * @param context the instruction context
	 */
	public Scalar getScalar(int operandIndex, InstructionContext context);

	/**
	 * {@return the objects used by a specific operand}
	 * <p>
	 * Each element is one of {@link Address}, {@link Register}, {@link Scalar}, or
	 * {@link VariableOffset}.
	 * 
	 * @param operandIndex the 0-up index of the operand
	 * @param context the instruction context
	 */
	public Object[] getOpObjects(int operandIndex, InstructionContext context);

	/**
	 * {@return the suggested reference type for a specific operand}
	 * 
	 * @param operandIndex the 0-up index of the operand
	 * @param context the instruction context
	 * @param override if not null, steers local overrides of p-code generation
	 */
	public RefType getOperandRefType(int operandIndex, InstructionContext context,
			PcodeOverride override);

	/**
	 * {@return true if a specific operand ought to have a delimiter following it}
	 * 
	 * @param operandIndex the 0-up index of the operand
	 */
	public boolean hasDelimeter(int operandIndex);

	/**
	 * {@return the objects used as input by this instruction}
	 * <p>
	 * Each element should probably only be one of {@link Address} or {@link Register}.
	 * 
	 * @param context the instruction context
	 */
	public Object[] getInputObjects(InstructionContext context);

	/**
	 * {@return the objects affected by this instruction}
	 * <p>
	 * Each element should probably only be one of {@link Address} or {@link Register}.
	 * 
	 * @param context the instruction context
	 */
	public Object[] getResultObjects(InstructionContext context);

	/**
	 * {@return the p-code operations (micro code) that this instruction performs}
	 * <p>
	 * This will return an empty array if the language does not support p-code for this instruction.
	 * 
	 * @param context the instruction context
	 * @param override if not null, may indicate that different elements of the pcode generation are
	 *            overridden
	 */
	public PcodeOp[] getPcode(InstructionContext context, PcodeOverride override);

	/**
	 * Does the same as {@link #getPcode(InstructionContext, PcodeOverride)} but emits the
	 * operations directly to an encoder to optimize transfer to other processes}
	 * 
	 * @param encoder is the encoder receiving the operations
	 * @param context the instruction context
	 * @param override if not null, may indicate that different elements of the pcode generation are
	 *            overridden
	 * @throws IOException for errors writing to any stream underlying the encoder
	 */
	public void getPcodePacked(PatchEncoder encoder, InstructionContext context,
			PcodeOverride override) throws IOException;

	/**
	 * {@return the p-code operations (micro code) that perform the computation of a particular
	 * operand's value}
	 *
	 * @param context the instruction context
	 * @param operandIndex the 0-up index of the operand
	 */
	public PcodeOp[] getPcode(InstructionContext context, int operandIndex);

	/**
	 * {@return the processor language module associated with this prototype}
	 */
	public Language getLanguage();
}
