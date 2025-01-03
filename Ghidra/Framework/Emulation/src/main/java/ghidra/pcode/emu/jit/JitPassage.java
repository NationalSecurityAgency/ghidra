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
package ghidra.pcode.emu.jit;

import java.math.BigInteger;
import java.util.*;
import java.util.stream.Collectors;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.app.util.PseudoInstruction;
import ghidra.pcode.emu.PcodeMachine;
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.emu.jit.analysis.JitControlFlowModel.BlockSplitter;
import ghidra.pcode.emu.jit.analysis.JitControlFlowModel.JitBlock;
import ghidra.pcode.emu.jit.analysis.JitDataFlowModel;
import ghidra.pcode.emu.jit.decode.JitPassageDecoder;
import ghidra.pcode.emu.jit.gen.JitCodeGenerator;
import ghidra.pcode.emu.jit.gen.op.OpGen;
import ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage;
import ghidra.pcode.exec.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.ContextChangeException;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.ByteMemBufferImpl;
import ghidra.program.model.pcode.*;
import ghidra.program.util.ProgramContextImpl;

/**
 * A selection of instructions decoded from an emulation target, the generated p-code ops, and
 * associated metadata.
 * 
 * <p>
 * Note that the generated p-code ops include those injected by the emulator's client using
 * {@link PcodeMachine#inject(Address, String)} and {@link PcodeThread#inject(Address, String)},
 * which also includes breakpoints, i.e, {@link PcodeMachine#addBreakpoint(Address, String)}.
 * 
 * @see JitPassageDecoder Passage decoding
 */
public class JitPassage extends PcodeProgram {

	/**
	 * Check if a given p-code op could fall through
	 * 
	 * <p>
	 * Conditional branches and non-branching ops are the only ones that can fall through. Note that
	 * for JIT purposes, a {@link PcodeOp#CALL CALL} op <em>does not</em> fall through! For
	 * decompilation, it hints that it's branching to a subroutine that <em>usually</em> returns
	 * back to the caller, but the JIT compiler does not take that hint. 1) There's no guarantee it
	 * will actually return. 2) Even if it did, it would be via a {@link PcodeOp#RETURN}, which is
	 * an <em>indirect</em> branch. An indirect branch is not sufficient to join two strides in the
	 * same passage. Thus, we have little to gain by falling through a call, and the more likely
	 * outcome is the JIT and/or ASM library will eliminate the code following the call.
	 * 
	 * @param op the op to consider
	 * @return true if the op does or could fall through
	 */
	public static boolean hasFallthrough(PcodeOp op) {
		if (op instanceof NopPcodeOp) {
			return true;
		}
		return switch (op.getOpcode()) {
			case PcodeOp.BRANCH, PcodeOp.BRANCHIND -> false;
			case PcodeOp.CALL, PcodeOp.CALLIND, PcodeOp.RETURN -> false;
			case PcodeOp.UNIMPLEMENTED -> false;
			case PcodeOp.CBRANCH -> true;
			default -> true;
		};
	}

	/**
	 * An address-context pair
	 * 
	 * <p>
	 * Because decode is sensitive to the contextreg value, we have to consider that visiting the
	 * same address with a different context could produce a completely different stride. Thus, we
	 * subsume the context value in a sense as part of the address when seeding the passage decoder,
	 * when referring to the "location" of p-code ops, when exiting a translated passage, etc.
	 */
	public static final class AddrCtx implements Comparable<AddrCtx> {
		/**
		 * An address-context pair for synthetic p-code ops
		 * 
		 * <p>
		 * This is currently used in probing an instruction (possibly instrumented) for fall
		 * through, and in testing.
		 */
		public static final AddrCtx NOWHERE = new AddrCtx(null, Address.NO_ADDRESS);

		/**
		 * Derive the address-context pair from an instruction's context
		 * 
		 * @param insCtx the context
		 * @return the address and input decode context of the instruction whose context was given
		 */
		public static AddrCtx fromInstructionContext(InstructionContext insCtx) {
			return new AddrCtx(getInCtx(insCtx), insCtx.getAddress());
		}

		/**
		 * Derive the address-context pair from an instruction
		 * 
		 * @param instruction the instruction
		 * @return the instruction's address and input decode context
		 */
		public static AddrCtx fromInstruction(Instruction instruction) {
			return fromInstructionContext(instruction.getInstructionContext());
		}

		/**
		 * The contextreg value as a big integer
		 * 
		 * <p>
		 * This is 0 when the language does not have a context register
		 */
		public final BigInteger biCtx;
		/**
		 * The contextreg as a register value
		 * 
		 * <p>
		 * This is {@code null} when the language does not have a context register
		 */
		public final RegisterValue rvCtx;
		/**
		 * The address
		 */
		public final Address address;

		/**
		 * Construct an address-context pair
		 * 
		 * @param ctx the contextreg value
		 * @param address the address
		 */
		public AddrCtx(RegisterValue ctx, Address address) {
			this.biCtx = ctx == null ? BigInteger.ZERO : ctx.getUnsignedValue();
			this.rvCtx = ctx;
			this.address = Objects.requireNonNull(address);
		}

		@Override
		public String toString() {
			return "AddrCtx[ctx=%s,addr=%s]".formatted(rvCtx, address);
		}

		@Override
		public int hashCode() {
			return Objects.hash(biCtx, address);
		}

		@Override
		public boolean equals(Object obj) {
			if (this == obj) {
				return true;
			}
			if (!(obj instanceof AddrCtx that)) {
				return false;
			}
			return this.biCtx.equals(that.biCtx) &&
				this.address.equals(that.address);
		}

		@Override
		public int compareTo(AddrCtx that) {
			int c;
			c = this.biCtx.compareTo(that.biCtx);
			if (c != 0) {
				return c;
			}
			c = this.address.compareTo(that.address);
			if (c != 0) {
				return c;
			}
			return 0;
		}
	}

	/**
	 * Derive the decode context value from the given instruction context
	 * 
	 * @param insCtx the context
	 * @return the input decode context from the instruction whose context was given
	 */
	protected static RegisterValue getInCtx(InstructionContext insCtx) {
		ProcessorContextView procCtx = insCtx.getProcessorContext();
		Register contextreg = procCtx.getBaseContextRegister();
		if (contextreg == Register.NO_CONTEXT) {
			return null;
		}
		return procCtx.getRegisterValue(contextreg);
	}

	/**
	 * Derive the decode context value from the given instruction
	 * 
	 * @param instruction the instruction
	 * @return the input decode context from the instruction
	 */
	protected static RegisterValue getInCtx(Instruction instruction) {
		return getInCtx(instruction.getInstructionContext());
	}

	/**
	 * A branch in the p-code
	 */
	public interface Branch {
		/**
		 * The op performing the branch
		 * 
		 * @return the "from" op
		 */
		PcodeOp from();

		/**
		 * Indicates whether this branch represents a fall-through case.
		 * 
		 * <p>
		 * Note that the {@link #from()} may not be an actual branching p-code op when
		 * {@code isFall} is true. A "fall-through" branch happens in two cases. First, and most
		 * obvious, is to describe the fall-through case of a {@link PcodeOp#CBRANCH conditional
		 * branch}. Second is when for a p-code op the immediately precedes the target of some other
		 * branch. That branch causes a split in basic blocks, and so to encode the fall through
		 * from that op into the basic block immediately after, a fall-through branch is added.
		 * 
		 * @return true if this branch is the fall-through case.
		 */
		default boolean isFall() {
			return false;
		}

		/**
		 * Get a string description of the branch target
		 * 
		 * @return the description
		 */
		default String describeTo() {
			return toString();
		}
	}

	/**
	 * A branch to another p-code op in the same passage
	 * 
	 * <p>
	 * The {@link JitCodeGenerator} translates internal branches into JVM bytecodes for the
	 * equivalent branch to the translation of the target p-code op. Thus, we remain executing
	 * inside the {@link JitCompiledPassage#run(int) run} method. This branch type incurs the least
	 * run-time cost.
	 * 
	 * @param from see {@link #from()}
	 * @param to the target p-code op
	 * @param isFall see {@link #isFall()}
	 */
	public record IntBranch(PcodeOp from, PcodeOp to, boolean isFall) implements Branch {}

	/**
	 * A branch to an address (and context value) not in the same passage
	 * 
	 * <p>
	 * When execution encounters this branch, the {@link JitCompiledPassage#run(int) run} method
	 * sets the emulator's program counter and context to the {@link #to() branch target} and
	 * returns the appropriate entry point for further execution.
	 * 
	 * Note that this branch type is used by the decoder to track queued decode seeds as well.
	 * External branches that get decoded are changed into internal branches.
	 * 
	 * @param from see {@link #from()}
	 * @param to the target address-context pair
	 */
	public record ExtBranch(PcodeOp from, AddrCtx to) implements Branch {}

	/**
	 * A branch to a dynamic address
	 * 
	 * <p>
	 * When execution encounters this branch, the {@link JitCompiledPassage#run(int) run} method
	 * will set the emulator's program counter to the computed address and its context to
	 * {@link #flowCtx()}, then return the appropriate entry point for further execution.
	 * 
	 * <p>
	 * TODO: Some analysis may be possible to narrow the possible addresses to a known few and then
	 * treat this as several {@link IntBranch}es; however, I worry this is too expensive for what it
	 * gets us. This will be necessary if we are to JIT, e.g., a switch table.
	 * 
	 * @param from see {@link #from()}
	 * @param flowCtx the decode context after the branch is taken
	 */
	public record IndBranch(PcodeOp from, RegisterValue flowCtx) implements Branch {}

	/**
	 * A "branch" representing an error
	 * 
	 * <p>
	 * When execution encounters this branch, the {@link JitCompiledPassage#run(int) run} method
	 * throws an exception. This branch is used to encode error conditions that may not actually be
	 * encountered at run time. Some cases are:
	 * 
	 * <ul>
	 * <li>An instruction decode error &mdash; synthesized as a {@link DecodeErrorPcodeOp}</li>
	 * <li>An {@link PcodeOp#UNIMPLEMENTED unimplemented} instruction</li>
	 * <li>A {@link PcodeOp#CALLOTHER call} to an undefined userop</li>
	 * </ul>
	 * 
	 * <p>
	 * The decoder and translator may encounter such an error, but unless execution actually reaches
	 * the error, the emulator need not crash. Thus, we note the error and generate code that will
	 * actually throw it in the translation, only if it's actually encountered.
	 * 
	 * <p>
	 * Note that the {@link OpGen} for the specific p-code op generating the error will decide what
	 * exception type to throw.
	 * 
	 * @param from see {@link #from()}
	 * @param message the error message for the exception
	 */
	public record ErrBranch(PcodeOp from, String message) implements Branch {}

	/**
	 * An extension of {@link PcodeOp} that carries along with it the address and decode context
	 * where it occurred.
	 * 
	 * <p>
	 * There is a difference between {@link #at}'s {@link AddrCtx#address address} vs.
	 * {@link #getSeqnum() seqnum}'s {@link SequenceNumber#getTarget() target}. The former is
	 * determined by the {@link JitPassageDecoder} and applied to all p-code ops generated at that
	 * address (and context value), including those from injected Sleigh. The latter is determined
	 * by the {@link Instruction} (or injected {@link PcodeProgram}), which have less information
	 * about their origins. There are also {@link DecodeErrorPcodeOp} and {@link NopPcodeOp}, which
	 * are synthesized by the {@link JitPassageDecoder} without an instruction or inject. This
	 * information is required for bookkeeping, esp., when updating the emulator's program counter
	 * and decode context when a p-code op produces an unexpected run-time error.
	 */
	public static class DecodedPcodeOp extends PcodeOp {
		private final AddrCtx at;

		/**
		 * Construct a new p-code op, decoded by the {@link JitPassageDecoder}
		 * 
		 * @param at the address and context value where the op was produced
		 * @param seqnum the p-code op sequence number
		 * @param opcode the p-code opcode
		 * @param inputs the input varnodes
		 * @param output the output varnode, or {@link null} if none or not applicable
		 */
		DecodedPcodeOp(AddrCtx at, SequenceNumber seqnum, int opcode, Varnode[] inputs,
				Varnode output) {
			super(seqnum, opcode, inputs, output);
			this.at = at;
		}

		/**
		 * Re-write a p-code op including its address and context value
		 * 
		 * <p>
		 * Aside from {@link #at}, everything is copied from the given original p-code op.
		 * 
		 * @param at the address and context value where the op was produced
		 * @param original the original p-code op
		 */
		public DecodedPcodeOp(AddrCtx at, PcodeOp original) {
			this(at, original.getSeqnum(), original.getOpcode(), original.getInputs(),
				original.getOutput());
		}

		/**
		 * Get the address and context value where this op was produced
		 * 
		 * @return the address-context pair
		 */
		public AddrCtx getAt() {
			return at;
		}

		/**
		 * Get the address where this op was produced
		 * 
		 * @return the address
		 */
		public Address getCounter() {
			return at.address;
		}

		/**
		 * Get the decode context where this op was produced
		 * 
		 * @return the decode context
		 */
		public RegisterValue getContext() {
			return at.rvCtx;
		}

		/**
		 * Check if this op represents the start of an instruction
		 * 
		 * <p>
		 * If this p-code op was produced by an inject, this will return false! It only returns true
		 * for an op that is genuinely the first op in the result of {@link Instruction#getPcode()}.
		 * <b>WARNING:</b> This should <em>not</em> be used for branching purposes, because branches
		 * to a given address are meant to target any injections there, too. Currently, this is used
		 * only to count the number of instructions actually executed.
		 * 
		 * @see JitBlock#instructionCount()
		 * @see JitCompiledPassage#count(int, int)
		 * @see JitPcodeThread#count(int, int)
		 * @return true if this op is the first of an instruction
		 */
		public boolean isInstructionStart() {
			SequenceNumber seq = getSeqnum();
			return seq.getTime() == 0 && seq.getTarget().equals(at.address);
		}
	}

	/**
	 * A synthetic p-code op that represents a return from the {@link JitCompiledPassage#run(int)}
	 * method.
	 * 
	 * <p>
	 * When execution encounters this op (and the corresponding {@link ExtBranch}), the emulator's
	 * program counter and context values are set to the {@link ExtBranch#to() branch target}, and
	 * the appropriate entry point is returned.
	 * 
	 * <p>
	 * This is used in a few ways: The simplest, though perhaps not obvious, way is when the decoder
	 * encounters an existing entry point. We avoid re-translating the same instructions by forcing
	 * the stride to end. However, the last instruction in that stride would have fall through,
	 * causing dangling control flow. To mitigate that, we append a synthetic exit op to return the
	 * existing entry point. The emulator can then resume execution accordingly.
	 * 
	 * <p>
	 * The next is even less obvious. When the emulation client (or user) injects Sleigh, a common
	 * mistake is to forget control flow. The decoder detects this when "falling through" does not
	 * actually advance the program counter. In this case, we append this synthetic op to exit the
	 * translated passage. While it still results in an endless loop (just like the
	 * interpretation-based emulator), it's easier to interrupt and diagnose when we exit the
	 * translation between each "iteration."
	 * 
	 * <p>
	 * The last is a small hack: The decoder needs to know whether each instruction (possibly
	 * instrumented by an inject) falls through. To do this, it appends an exit op to the very end
	 * of the instruction's (and inject's) ops and performs rudimentary control flow analysis (see
	 * {@link BlockSplitter}). It then seeks a path from start to exit. If one is found, it has fall
	 * through. This "probe" op is <em>not</em> included in the decoded stride.
	 * 
	 */
	public static class ExitPcodeOp extends PcodeOp {
		/**
		 * Construct a synthetic exit op
		 * 
		 * @param at the address and context value to set on the emulator when exiting the
		 *            {@link JitCompiledPassage#run(int)} method
		 */
		public ExitPcodeOp(AddrCtx at) {
			super(new SequenceNumber(at.address, 0), PcodeOp.BRANCH, new Varnode[] {
				new Varnode(at.address, 0) }, null);
		}
	}

	/**
	 * A synthetic op representing the initial seed of a decoded passage.
	 * 
	 * <p>
	 * Because we use a queue of {@link ExtBranch}es as the seed queue, and the initial seed has no
	 * real {@link Branch#from()}, we synthesize a {@link PcodeOp#BRANCH branch op} from the entry
	 * address to itself. This synthetic op is <em>not</em> included in the decoded stride.
	 */
	public static class EntryPcodeOp extends PcodeOp {
		/**
		 * Construct the passage entry p-code op.
		 * 
		 * @param entry the target address and decode context of the passage seed
		 */
		public EntryPcodeOp(AddrCtx entry) {
			super(Address.NO_ADDRESS, 0, PcodeOp.BRANCH, new Varnode[] {
				new Varnode(entry.address, 0) });
		}
	}

	/**
	 * A synthetic p-code op meant to encode "no operation"
	 * 
	 * <p>
	 * P-code does not have a NOP opcode, because there's usually no reason to produce such. A NOP
	 * machine instruction just produces an empty list of p-code ops, denoting "no operation."
	 * However, for bookkeeping purposes in our JIT translator, we occasionally need some op to hold
	 * an important place, but that op needs to do nothing. We use this in two situations:
	 * 
	 * <ul>
	 * <li>An instruction (possibly because of an inject) that does nothing. Yes, essentially a NOP
	 * machine instruction. Because another op may target this instruction, and {@link Branch}es
	 * need to target a p-code op, we synthesize a p-code "nop" to hold that position. The
	 * alternative is to figure out what op immediately follows the branch target, but such an op
	 * may not have been decoded, yet. It's easier just to synthesize the nop.</li>
	 * <li>A p-code branch to the end of an instruction. Most often a slaspec author that means to
	 * skip the remainder of an instruction will use {@code goto inst_next}; however, because of
	 * sub-table structuring and/or personal preferences, sometimes we see {@code goto <end>;} where
	 * {@code <end>} is at the end of the instruction, and thus, no p-code op actually follows it.
	 * We essentially have the same situation and the NOP machine instruction where we can either
	 * synthesize a placeholder nop, or else we have to figure out what op does (or will) actually
	 * follow the label.</li>
	 * </ul>
	 */
	public static class NopPcodeOp extends DecodedPcodeOp {
		/**
		 * Construct a synthetic p-code "nop"
		 * 
		 * @param at the address-context pair where the op was generated
		 * @param seq the sequence where the nop is inserted. For machine-code NOP, this should be
		 *            0. For a branch to the end of an instruction, this should be the next sequence
		 *            number (so that the branch targets this nop)
		 */
		public NopPcodeOp(AddrCtx at, int seq) {
			super(at, new SequenceNumber(at.address, seq), PcodeOp.UNIMPLEMENTED, new Varnode[] {},
				null);
		}
	}

	/**
	 * A synthetic p-code op denoting a decode error
	 * 
	 * <p>
	 * The decoder may encounter several decode errors as it selects and decodes the passage. An
	 * instruction is selected because the JIT believes it <em>may</em> be executed by the emulator.
	 * (Predicting this and making good selections is a matter of further research.) Encounting a
	 * decode error along a possible path is not cause to throw an exception. However; if the
	 * emulator does in fact attempt to execute the bytes which it can't decode, then we do throw
	 * the exception. This p-code op is synthesized where such decode errors occur, and the
	 * translator will generate code that actually throw the exception. Note that the error message
	 * is placed in the corresponding {@link ErrBranch}.
	 */
	public static class DecodeErrorPcodeOp extends DecodedPcodeOp {
		/**
		 * Construct a p-code op representing an instruction decode error.
		 * 
		 * @param at the address and decode context where the error occurred
		 */
		public DecodeErrorPcodeOp(AddrCtx at) {
			super(at, new SequenceNumber(at.address, 0), PcodeOp.UNIMPLEMENTED, new Varnode[] {},
				null);
		}
	}

	/**
	 * An instruction denoting a decode error
	 * 
	 * <p>
	 * The Sleigh disassembler normally denotes this with a {@link PseudoInstruction} having an
	 * {@link InvalidPrototype}. We essentially do the same here, but with custom types that are
	 * simpler to identify. Additionally, the types contain additional information, e.g., the error
	 * message. We also need the prototype to produce a single {@link DecodeErrorPcodeOp}.
	 */
	public static class DecodeErrorInstruction extends PseudoInstruction {

		/**
		 * The prototype for the decode error instruction
		 */
		static class DecodeErrorPrototype extends InvalidPrototype {
			public DecodeErrorPrototype(Language language) {
				super(language);
			}

			@Override
			public PcodeOp[] getPcode(InstructionContext context, PcodeOverride override) {
				return new PcodeOp[] {
					new DecodeErrorPcodeOp(AddrCtx.fromInstructionContext(context)) };
			}
		}

		/**
		 * An implementation of {@link ProcessorContext} to satisfy the requirements of the
		 * {@link PseudoInstruction}.
		 * 
		 * <p>
		 * This need do little more than provide the decode context register value.
		 */
		static class DecodeErrorProcessorContext implements ProcessorContext {
			private final Language language;
			private final RegisterValue ctx;

			public DecodeErrorProcessorContext(Language language, RegisterValue ctx) {
				this.language = language;
				this.ctx = ctx;
			}

			@Override
			public Register getBaseContextRegister() {
				return language.getContextBaseRegister();
			}

			@Override
			public List<Register> getRegisters() {
				return language.getRegisters();
			}

			@Override
			public Register getRegister(String name) {
				return language.getRegister(name);
			}

			@Override
			public BigInteger getValue(Register register, boolean signed) {
				if (register == language.getContextBaseRegister()) {
					return signed ? ctx.getSignedValue() : ctx.getUnsignedValue();
				}
				return null;
			}

			@Override
			public RegisterValue getRegisterValue(Register register) {
				if (register == language.getContextBaseRegister()) {
					return ctx;
				}
				return null;
			}

			@Override
			public boolean hasValue(Register register) {
				return register == language.getContextBaseRegister();
			}

			@Override
			public void setValue(Register register, BigInteger value)
					throws ContextChangeException {
			}

			@Override
			public void setRegisterValue(RegisterValue value)
					throws ContextChangeException {
			}

			@Override
			public void clearRegister(Register register) throws ContextChangeException {
			}
		}

		private final String message;

		/**
		 * Construct an instruction to indicate a decode error
		 * 
		 * @param language the emulation target langauge
		 * @param address the address where decode was attempted
		 * @param ctx the input decode context
		 * @param message a message for the {@link DecodePcodeExecutionException} if the emulator
		 *            attempts to execute this instruction
		 * @throws AddressOverflowException never
		 */
		public DecodeErrorInstruction(Language language, Address address, RegisterValue ctx,
				String message) throws AddressOverflowException {
			super(address, new DecodeErrorPrototype(language),
				new ByteMemBufferImpl(address, new byte[] { 0 }, language.isBigEndian()),
				new DecodeErrorProcessorContext(language, ctx));
			this.message = message;
		}

		/**
		 * Get the message for the exception, should this instruction be "executed"
		 * 
		 * @return the error message
		 */
		public String getMessage() {
			return message;
		}
	}

	/**
	 * Create an instruction to indicate a decode error
	 * 
	 * <p>
	 * The resulting instruction will produce a single {@link DecodeErrorPcodeOp}. The translator
	 * will generate code that throws a {@link DecodePcodeExecutionException} should execution reach
	 * it.
	 * 
	 * @param language the emulation target language
	 * @param address the address where decode was attempted
	 * @param ctx the input decode context
	 * @param message a message for the {@link DecodePcodeExecutionException}
	 * @return the new "instruction"
	 */
	public static DecodeErrorInstruction decodeError(Language language, Address address,
			RegisterValue ctx, String message) {
		try {
			return new DecodeErrorInstruction(language, address, ctx, message);
		}
		catch (AddressOverflowException e) {
			throw new AssertionError(e);
		}
	}

	private final List<Instruction> instructions;
	private final AddrCtx entry;
	private final PcodeUseropLibrary<Object> decodeLibrary;
	private final Map<PcodeOp, Branch> branches;
	private final Map<PcodeOp, AddrCtx> entries;
	private final Register contextreg;
	private final ProgramContextImpl defaultContext;

	/**
	 * Construct a new passage
	 * 
	 * @param language the translation source language, i.e., the emulation target language. See
	 *            {@link #getLanguage()}
	 * @param entry see {@link #getEntry()}
	 * @param code the p-code ops, grouped by stride. Within each stride, they are ordered as
	 *            decoded and produced by their instructions. The strides are sorted by seed, with
	 *            precedence to the decode context value. See {@link #getInstructions()}. See
	 *            {@link #getCode()}.
	 * @param decodeLibrary see {@link #getDecodeLibrary()}
	 * @param instructions see {@link #getInstructions()}
	 * @param branches see {@link #getBranches()}
	 * @param entries see {@link #getOpEntry(PcodeOp)}
	 */
	public JitPassage(SleighLanguage language, AddrCtx entry, List<PcodeOp> code,
			PcodeUseropLibrary<Object> decodeLibrary, List<Instruction> instructions,
			Map<PcodeOp, Branch> branches, Map<PcodeOp, AddrCtx> entries) {
		super(language, code, decodeLibrary.getSymbols(language));
		this.entry = entry;
		this.decodeLibrary = decodeLibrary;
		this.instructions = instructions;
		this.branches = branches;
		this.entries = entries;

		this.contextreg = language.getContextBaseRegister();

		if (contextreg != Register.NO_CONTEXT) {
			defaultContext = new ProgramContextImpl(language);
			language.applyContextSettings(defaultContext);
		}
		else {
			defaultContext = null;
		}
	}

	/**
	 * Get all of the instructions in the passage.
	 * 
	 * <p>
	 * These are grouped by stride. Within each stride, the instructions are listed in decode order.
	 * The strides are ordered by seed address-context pair, with context value taking precedence.
	 * 
	 * @return the list of instructions
	 */
	public List<Instruction> getInstructions() {
		return instructions;
	}

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * Conventionally, the first instruction of the program is the entry. Note this might
	 * <em>not</em> be the initial seed. If the decoded passage contains a branch to an address
	 * preceding the seed, and a stride results from it, then that stride's p-code will occur
	 * earlier in the list. This is not a problem. The code generator will export many entry points,
	 * and the seed must be among them. "Entering" at that seed is achieved using a switch table at
	 * the start of the generated bytecode.
	 */
	@Override
	public List<PcodeOp> getCode() {
		return super.getCode();
	}

	/**
	 * Get the initial seed of this passage.
	 * 
	 * <p>
	 * This is informational only. It should be used in naming things and/or in diagnostics.
	 * 
	 * @return the address-context pair
	 */
	public AddrCtx getEntry() {
		return entry;
	}

	/**
	 * Get the userop library that was used during decode of the passage
	 * 
	 * <p>
	 * This often wraps the emulator's userop library. Downstream components, namely the
	 * {@link JitDataFlowModel}, will need this when translating {@link PcodeOp#CALLOTHER calls} to
	 * userops.
	 * 
	 * @return the library
	 */
	public PcodeUseropLibrary<Object> getDecodeLibrary() {
		return decodeLibrary;
	}

	/**
	 * Get all of the (non-fall-through) branches in the passage
	 * 
	 * @return the branches, keyed by {@link Branch#from()}.
	 */
	public Map<PcodeOp, Branch> getBranches() {
		return branches;
	}

	@Override
	public String toString() {
		return "<" + getClass().getSimpleName() + ":\n  " + instructions.stream().map(i -> {
			return "(" + getInCtx(i) + ") " + i.getAddressString(false, true) + " " + i.toString();
		}).collect(Collectors.joining("\n  ")) + "\n>\n" + format(true);
	}

	/**
	 * Check if a given p-code op is the first of an instruction.
	 * 
	 * <p>
	 * <b>NOTE</b>: If an instruction is at an address with an inject, then the first op produced by
	 * the inject is considered the "entry" to the instruction. This is to ensure that any control
	 * flow to the injected address executes the injected code, not just the instruction's code.
	 * 
	 * @param op the op to check.
	 * @return the address-context pair that generated the op, if it is the first there, or
	 *         {@code null}
	 */
	public AddrCtx getOpEntry(PcodeOp op) {
		return entries.get(op);
	}

	/**
	 * If the given p-code op is known to cause an error, e.g., an unimplemented instruction, get
	 * the error message.
	 * 
	 * @param op the p-code op causing the error
	 * @return the message for the error caused
	 */
	public String getErrorMessage(PcodeOp op) {
		Branch branch = branches.get(op);
		return switch (branch) {
			case null -> throw new AssertionError("No branch record for op: " + op);
			case ErrBranch err -> err.message;
			default -> throw new AssertionError("Wrong branch type " + branch + " for op: " + op);
		};
	}
}
