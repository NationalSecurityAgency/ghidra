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
package ghidra.app.plugin.core.analysis;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.HashSet;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.DataType;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.ContextChangeException;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramContext;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolUtilities;
import ghidra.program.util.SymbolicPropogator;
import ghidra.program.util.VarnodeContext;
import ghidra.util.Msg;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * NDS32 constant-propagation analyzer.  Recovers the global {@code gp} value
 * (from {@code _SDA_BASE_} or by tracing {@code sethi gp / ori gp / movi gp}
 * writes), records it as a {@code _gp_N} symbol, marks sethi+ori dual-instruction
 * pairs as memory references, and delegates the remainder of constant
 * propagation to {@link ConstantPropagationAnalyzer}.  Modeled after
 * {@code MipsAddressAnalyzer}.
 */
public class NDS32Analyzer extends ConstantPropagationAnalyzer {
	private static final int MAX_UNIQUE_GP_SYMBOLS = 50;
	private final static String PROCESSOR_NAME = "NDS32";

	private static final String OPTION_NAME_RECOVER_GP =
		"Recover global GP register writes";
	private static final String OPTION_DESCRIPTION_RECOVER_GP =
		"Discover writes to the global GP register and assume as constant at the " +
			"start of functions if only one value has been discovered.";
	private static final boolean OPTION_DEFAULT_RECOVER_GP = true;

	private static final String OPTION_NAME_MARK_DUAL = "Mark dual-instruction references";
	private static final String OPTION_DESCRIPTION_MARK_DUAL =
		"Turn on to mark all sethi/ori (and similar) dual-instruction pairs as references " +
			"even when not seen actively used as a load/store address.";
	private static final boolean OPTION_DEFAULT_MARK_DUAL = true;

	private boolean recoverGp = OPTION_DEFAULT_RECOVER_GP;
	private boolean markDual = OPTION_DEFAULT_MARK_DUAL;

	private Address gpAssumptionValue = null;

	private Register gp;

	// Mnemonics that compute a target address into Rt and should get a
	// reference annotation when Rt becomes a known address in mapped memory.
	private static final HashSet<String> ADDR_COMPUTING_MNEMONICS = new HashSet<>(Arrays.asList(
		// Core address-computing ALU
		"addi", "addri.gp", "addi.gp", "ori", "sethi", "movi", "addi45", "addi333",
		"addi10.sp", "addri36.sp",
		// Loads (Rt = *(addr in operand))
		"lwi", "lhi", "lhsi", "lbi", "lbsi",
		"lwi.bi", "lhi.bi", "lhsi.bi", "lbi.bi", "lbsi.bi",
		"lw", "lh", "lhs", "lb", "lbs",
		"lw.bi", "lh.bi", "lhs.bi", "lb.bi", "lbs.bi",
		"lwi.gp", "lhi.gp", "lhsi.gp", "lbi.gp", "lbsi.gp",
		// Stores
		"swi", "shi", "sbi", "swi.bi", "shi.bi", "sbi.bi",
		"sw", "sh", "sb", "sw.bi", "sh.bi", "sb.bi",
		"swi.gp", "shi.gp", "sbi.gp"));

	public NDS32Analyzer() {
		super(PROCESSOR_NAME);
	}

	@Override
	public boolean canAnalyze(Program program) {
		boolean canAnalyze = program.getLanguage().getProcessor().equals(
			Processor.findOrPossiblyCreateProcessor(PROCESSOR_NAME));
		if (!canAnalyze) {
			return false;
		}
		gp = program.getRegister("gp");
		return true;
	}

	@Override
	public void registerOptions(Options options, Program program) {
		super.registerOptions(options, program);
		options.registerOption(OPTION_NAME_RECOVER_GP, recoverGp, null,
			OPTION_DESCRIPTION_RECOVER_GP);
		options.registerOption(OPTION_NAME_MARK_DUAL, markDual, null,
			OPTION_DESCRIPTION_MARK_DUAL);
	}

	@Override
	public void optionsChanged(Options options, Program program) {
		super.optionsChanged(options, program);
		recoverGp = options.getBoolean(OPTION_NAME_RECOVER_GP, recoverGp);
		markDual = options.getBoolean(OPTION_NAME_MARK_DUAL, markDual);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor,
			MessageLog log) throws CancelledException {
		gpAssumptionValue = null;
		checkForGlobalGP(program, set, monitor);
		// Run before flowConstants so the gp_assumption is in place for the FIRST
		// function; otherwise functions processed before the gp-setting site miss
		// the inject-at-entry shortcut.
		if (gpAssumptionValue == null && recoverGp) {
			gpAssumptionValue = scanForGpInit(program, monitor);
			if (gpAssumptionValue != null) {
				setGPSymbol(program, gpAssumptionValue);
				program.getBookmarkManager().setBookmark(gpAssumptionValue,
					BookmarkType.WARNING, "GP Global Register Set",
					"Discovered global GP register value");
			}
		}

		// Setting GP across the whole space is heavyweight; skip when the program
		// context already covers the space with the same value.
		if (gpAssumptionValue != null && recoverGp) {
			ProgramContext pc = program.getProgramContext();
			AddressSpace defSpace = program.getAddressFactory().getDefaultAddressSpace();
			Address space0 = defSpace.getMinAddress();
			Address space1 = defSpace.getMaxAddress();
			BigInteger gpVal = BigInteger.valueOf(gpAssumptionValue.getOffset());
			if (!hasGpValueAcrossSpace(pc, space0, space1, gpVal)) {
				RegisterValue rv = new RegisterValue(gp, gpVal);
				try {
					pc.setRegisterValue(space0, space1, rv);
				}
				catch (ContextChangeException e) {
					log.appendException(e);
				}
			}
		}

		boolean ok = super.added(program, set, monitor, log);

		// Constant-prop adds DATA refs at loads/stores that compute an
		// address and dereference it.  `addi.gp` computes a pointer but
		// never dereferences (the result lives in a register), so const-prop
		// has no hook to fire on; this direct walk handles that gap.
		if (markDual && gpAssumptionValue != null) {
			markGpRelativeReferences(program, set, monitor, log);
		}

		// Function-pointer tables in data sections are common on this firmware;
		// Ghidra's stock function-start search doesn't pick them up.
		promoteCodePointerRefs(program, set, monitor, log);

		return ok;
	}

	/**
	 * Promote DATA refs whose target starts with a push25 prologue into Functions.
	 * push25 is a strong NDS32 prologue signal (multi-register save + sp adjust);
	 * the check is kept tight to avoid false positives.
	 *
	 * <p>Iterates only refs whose source is in {@code set}.  Each invocation of
	 * {@code added} receives the addresses that changed since the last pass, so
	 * the cumulative work across invocations equals roughly one full sweep -- vs.
	 * an O(refs<sup>2</sup>) blow-up if every pass re-scanned the whole program.
	 */
	private void promoteCodePointerRefs(Program program, AddressSetView set,
			TaskMonitor monitor, MessageLog log) throws CancelledException {
		Memory mem = program.getMemory();
		Listing listing = program.getListing();
		ReferenceManager refMgr = program.getReferenceManager();
		var fm = program.getFunctionManager();
		HashSet<Address> tried = new HashSet<>();
		int created = 0;
		int disasmed = 0;
		AddressIterator srcAddrs = (set == null || set.isEmpty())
			? refMgr.getReferenceSourceIterator(mem.getMinAddress(), true)
			: refMgr.getReferenceSourceIterator(set, true);
		while (srcAddrs.hasNext()) {
			monitor.checkCancelled();
			Address src = srcAddrs.next();
			for (Reference r : refMgr.getReferencesFrom(src)) {
				if (!r.getReferenceType().isData()) {
					continue;
				}
				Address target = r.getToAddress();
				if (!mem.contains(target)) {
					continue;
				}
				if ((target.getOffset() & 1) != 0) {
					continue;
				}
				if (!tried.add(target)) {
					continue;
				}
				if (fm.getFunctionAt(target) != null) {
					continue;
				}
				if (!looksLikePush25Prologue(mem, target)) {
					continue;
				}
				if (listing.getInstructionAt(target) == null) {
					if (listing.getDefinedDataAt(target) != null) {
						continue;
					}
					DisassembleCommand d = new DisassembleCommand(target, null, true);
					if (!d.applyTo(program, monitor)) {
						continue;
					}
					disasmed++;
				}
				if (listing.getInstructionAt(target) == null) {
					continue;
				}
				CreateFunctionCmd cmd = new CreateFunctionCmd(target);
				if (cmd.applyTo(program, monitor)) {
					created++;
				}
			}
		}
		if (created > 0 || disasmed > 0) {
			Msg.info(this, String.format(
				"NDS32 code pointer markup: promoted %d function pointer target(s); " +
					"disassembled %d new region(s)",
				created, disasmed));
		}
	}

	// push25 encoding: byte 0 = 0xfc, byte 1 bit 7 = 0 (distinguishes from pop25).
	private static boolean looksLikePush25Prologue(Memory mem, Address target) {
		byte[] bs = new byte[2];
		try {
			if (mem.getBytes(target, bs) != 2) {
				return false;
			}
		}
		catch (Exception e) {
			return false;
		}
		int b0 = bs[0] & 0xff;
		int b1 = bs[1] & 0xff;
		return b0 == 0xfc && (b1 & 0x80) == 0;
	}

	/**
	 * Walk every GP-relative instruction and add a memory reference computed as
	 * {@code gpAssumptionValue + imm} when one is missing.
	 */
	private void markGpRelativeReferences(Program program, AddressSetView set,
			TaskMonitor monitor, MessageLog log) throws CancelledException {
		long gpBase = gpAssumptionValue.getOffset() & 0xffffffffL;
		var space = program.getAddressFactory().getDefaultAddressSpace();
		int added = 0;
		Iterable<Instruction> iter = (set != null && !set.isEmpty())
			? () -> program.getListing().getInstructions(set, true)
			: () -> program.getListing().getInstructions(true);
		for (Instruction insn : iter) {
			monitor.checkCancelled();
			String mnem = insn.getMnemonicString();
			if (!mnem.endsWith(".gp")) {
				continue;
			}
			if (insn.getOperandReferences(0).length != 0) {
				continue;
			}
			var sc = insn.getNumOperands() > 0
				? insn.getScalar(insn.getNumOperands() - 1)
				: null;
			if (sc == null) {
				continue;
			}
			long target = (gpBase + sc.getSignedValue()) & 0xffffffffL;
			if ((target >= 0 && target < 4096) || target == 0xffffffffL) {
				continue;
			}
			Address ref;
			try {
				ref = space.getAddress(target);
			}
			catch (AddressOutOfBoundsException e) {
				continue;
			}
			insn.addOperandReference(0, ref, RefType.DATA, SourceType.ANALYSIS);
			added++;
		}
		if (added > 0) {
			Msg.info(this, String.format(
				"NDS32 GP markup: post-pass added %d GP-relative references", added));
		}
	}

	/** Walk all instructions for the canonical GP-init pattern (sethi+ori or movi). */
	private Address scanForGpInit(Program program, TaskMonitor monitor)
			throws CancelledException {
		Instruction prevSethi = null;
		long sethiVal = 0;
		for (Instruction insn : program.getListing().getInstructions(true)) {
			monitor.checkCancelled();
			Register dst = insn.getNumOperands() > 0 ? insn.getRegister(0) : null;
			if (dst == null || !dst.equals(gp)) {
				prevSethi = null;
				continue;
			}
			String mnem = insn.getMnemonicString();
			if (mnem.equals("sethi")) {
				var sc = insn.getScalar(1);
				if (sc != null) {
					prevSethi = insn;
					sethiVal = sc.getUnsignedValue() << 12;
				}
				continue;
			}
			if (mnem.equals("movi")) {
				var sc = insn.getScalar(1);
				if (sc != null) {
					// GP commonly points outside the loaded image (SDRAM/SRAM),
					// so don't require memory.contains.
					return insn.getMinAddress().getNewAddress(sc.getSignedValue());
				}
				prevSethi = null;
				continue;
			}
			if (mnem.equals("ori") && prevSethi != null) {
				var sc = insn.getScalar(2);
				if (sc != null) {
					long full = sethiVal | (sc.getUnsignedValue() & 0xfff);
					return insn.getMinAddress().getNewAddress(full);
				}
			}
			prevSethi = null;
		}
		return null;
	}

	/**
	 * True if every address from {@code lo} to {@code hi} already has
	 * {@code gp = expected}, so the heavyweight setRegisterValue can be skipped.
	 */
	private boolean hasGpValueAcrossSpace(ProgramContext pc, Address lo, Address hi,
			BigInteger expected) {
		var ranges = pc.getRegisterValueAddressRanges(gp);
		AddressSet covered = new AddressSet();
		while (ranges.hasNext()) {
			AddressRange r = ranges.next();
			RegisterValue rv = pc.getRegisterValue(gp, r.getMinAddress());
			if (rv == null || !rv.hasValue()) continue;
			if (!rv.getUnsignedValue().equals(expected)) continue;
			covered.add(r.getMinAddress(), r.getMaxAddress());
		}
		return covered.contains(lo) && covered.contains(hi)
			&& covered.getNumAddresses() >= hi.subtract(lo) + 1;
	}

	private void checkForGlobalGP(Program program, AddressSetView set, TaskMonitor monitor) {
		if (!recoverGp) {
			return;
		}

		// ELF/AndeStar ld script symbol.
		Symbol symbol = SymbolUtilities.getLabelOrFunctionSymbol(program, "_SDA_BASE_",
			err -> Msg.error(this, err));
		if (symbol != null) {
			gpAssumptionValue = symbol.getAddress();
			return;
		}

		// Tracked value in the requested set.
		if (set != null && !set.isEmpty()) {
			var ranges = program.getProgramContext().getRegisterValueAddressRanges(gp);
			while (ranges.hasNext()) {
				var next = ranges.next();
				if (set.contains(next.getMinAddress(), next.getMaxAddress())) {
					RegisterValue rv = program.getProgramContext()
						.getRegisterValue(gp, next.getMinAddress());
					if (rv != null && rv.hasValue()) {
						gpAssumptionValue = next.getMinAddress()
							.getNewAddress(rv.getUnsignedValue().longValue());
						return;
					}
				}
			}
		}

		// Pre-existing _gp / _gp_1 symbol from an earlier pass.
		Symbol s = SymbolUtilities.getLabelOrFunctionSymbol(program, "_gp",
			err -> Msg.error(this, err));
		if (s == null) {
			s = SymbolUtilities.getLabelOrFunctionSymbol(program, "_gp_1",
				err -> Msg.error(this, err));
		}
		if (s != null) {
			gpAssumptionValue = s.getAddress();
		}
	}

	/** Create or reuse a {@code _gp_N} label at the discovered GP value. */
	private Symbol setGPSymbol(Program program, Address toAddr) {
		int index = 1;
		while (index < MAX_UNIQUE_GP_SYMBOLS) {
			try {
				String name = "_gp_" + index++;
				Symbol existing = SymbolUtilities.getLabelOrFunctionSymbol(program, name,
					err -> { /* duplicates ignored */ });
				if (existing != null) {
					if (existing.getAddress().equals(toAddr)) {
						return existing;
					}
					continue;
				}
				return program.getSymbolTable().createLabel(toAddr, name, SourceType.ANALYSIS);
			}
			catch (InvalidInputException e) {
				break;
			}
		}
		return null;
	}

	@Override
	public AddressSetView flowConstants(final Program program, Address flowStart,
			AddressSetView flowSet, final SymbolicPropogator symEval,
			final TaskMonitor monitor) throws CancelledException {

		final Function func = program.getFunctionManager().getFunctionContaining(flowStart);
		final AddressSet coveredSet = new AddressSet();
		final Address currentGPAssumptionValue = gpAssumptionValue;

		// Inject the GP assumption at the function entry so addi.gp / lwi.gp /
		// swi.gp resolve to absolute addresses.
		if (func != null && currentGPAssumptionValue != null) {
			flowStart = func.getEntryPoint();
			ProgramContext programContext = program.getProgramContext();
			RegisterValue gpVal = programContext.getRegisterValue(gp, flowStart);
			if (gpVal == null || !gpVal.hasValue()) {
				gpVal = new RegisterValue(gp,
					BigInteger.valueOf(currentGPAssumptionValue.getOffset()));
				try {
					programContext.setRegisterValue(func.getEntryPoint(),
						func.getEntryPoint(), gpVal);
				}
				catch (ContextChangeException e) {
					throw new AssertException("unexpected", e);
				}
			}
		}

		ConstantPropagationContextEvaluator eval =
			new ConstantPropagationContextEvaluator(monitor, trustWriteMemOption) {

				private Address localGPAssumptionValue = currentGPAssumptionValue;

				@Override
				public boolean evaluateContext(VarnodeContext context, Instruction instr) {
					// On call/terminal boundaries, check whether GP took on a new
					// constant in this flow; if so record it as _gp_N globally.
					FlowType flow = instr.getFlowType();
					if (recoverGp && (flow.isCall() || flow.isTerminal())) {
						RegisterValue rv = context.getRegisterValue(gp);
						if (rv != null) {
							BigInteger value = rv.getUnsignedValue();
							long unsigned = value.longValue();
							if (localGPAssumptionValue == null ||
								unsigned != localGPAssumptionValue.getOffset()) {

								synchronized (gp) {
									Address gpAddr =
										instr.getMinAddress().getNewAddress(unsigned);
									// Use the from-constant variant so a pop25 LOAD that
									// happened to pick up a stale stack-tracking constant
									// isn't attributed as the gp-setting instruction.
									Address lastSetAddr =
										context.getLastSetLocationFromConstant(gp, value);
									if (lastSetAddr != null) {
										Instruction lastSetInstr = instr;
										Instruction other = program.getListing()
											.getInstructionContaining(lastSetAddr);
										if (other != null) {
											lastSetInstr = other;
										}
										setGPSymbol(program, gpAddr);
										symEval.makeReference(context, lastSetInstr, -1,
											instr.getMinAddress().getAddressSpace().getSpaceID(),
											unsigned, 1, null, RefType.DATA,
											PcodeOp.UNIMPLEMENTED, true, false, monitor);
										if (localGPAssumptionValue == null) {
											program.getBookmarkManager().setBookmark(
												lastSetInstr.getMinAddress(),
												BookmarkType.WARNING,
												"GP Global Register Set",
												"Global GP register is set here.");
										}
										// On disagreement, drop the LOCAL assumption (let
										// this function flow without one) but preserve
										// the global -- other functions still rely on it
										// via the markupDualInstruction fallback.
										if (localGPAssumptionValue != null
											&& !localGPAssumptionValue.equals(gpAddr)) {
											localGPAssumptionValue = null;
										}
										else {
											localGPAssumptionValue = gpAddr;
											if (gpAssumptionValue == null) {
												gpAssumptionValue = gpAddr;
											}
										}
									}
								}
							}
						}
					}

					if (markDual) {
						markupDualInstruction(context, instr);
					}
					return false;
				}

				private void markupDualInstruction(VarnodeContext context, Instruction instr) {
					// Hot path: avoid String allocations and re-lookups.
					String mnem = instr.getMnemonicString();
					if (!ADDR_COMPUTING_MNEMONICS.contains(mnem)) {
						return;
					}

					// GP-relative family computes result = gp + imm directly;
					// don't rely on the destination register's tracked value
					// (which evaluateContext sees pre-instruction).
					long addrVal = 0;
					boolean haveAddr = false;
					if (mnem.endsWith(".gp") || mnem.equals("addri.gp") || mnem.equals("addi.gp")) {
						if (gp == null) {
							return;
						}
						BigInteger gpVal = context.getValue(gp, false);
						if (gpVal == null) {
							// Propagator lost GP (e.g. through a push25 store path);
							// fall back to the analyzer-discovered global constant.
							if (gpAssumptionValue == null) {
								return;
							}
							gpVal = BigInteger.valueOf(
								gpAssumptionValue.getOffset() & 0xffffffffL);
						}
						var sc = instr.getScalar(instr.getNumOperands() - 1);
						if (sc == null) {
							return;
						}
						addrVal = gpVal.longValue() + sc.getSignedValue();
						haveAddr = true;
					}

					if (!haveAddr) {
						Register reg = instr.getRegister(0);
						if (reg == null) {
							return;
						}
						BigInteger val = context.getValue(reg, false);
						if (val == null) {
							return;
						}
						addrVal = val.longValue();
					}

					if ((addrVal >= 0 && addrVal < 4096) || addrVal == 0xffff) {
						return;
					}
					Address ref;
					try {
						ref = instr.getMinAddress().getNewAddress(addrVal & 0xffffffffL);
					}
					catch (AddressOutOfBoundsException e) {
						return;
					}
					boolean inMem = program.getMemory().contains(ref);
					boolean isGpRelative = haveAddr;
					if ((inMem || isGpRelative)
						&& instr.getOperandReferences(0).length == 0) {
						instr.addOperandReference(0, ref, RefType.DATA, SourceType.ANALYSIS);
					}
				}

				@Override
				public boolean evaluateDestination(VarnodeContext context, Instruction instr) {
					return false;
				}

				@Override
				public boolean evaluateReference(VarnodeContext context, Instruction instr,
						int pcodeop, Address address, int size,
						DataType dataType, RefType refType) {
					// push25 / pop25 (Smwad/Lmwai) and smw[a].* save gp to the stack;
					// SymbolicPropogator's addStoredReferences then emits a DATA ref
					// pointing at the gp base value.  The store target is the stack
					// slot, not gp -- suppress the ref.
					if (pcodeop == PcodeOp.STORE) {
						String m = instr.getMnemonicString();
						if (m.equals("push25") || m.equals("pop25")
							|| m.startsWith("smw.") || m.startsWith("smwa.")) {
							return false;
						}
					}
					return super.evaluateReference(context, instr, pcodeop, address, size,
						dataType, refType);
				}
			};

		eval.setTrustWritableMemory(trustWriteMemOption)
			.setMinSpeculativeOffset(minSpeculativeRefAddress)
			.setMaxSpeculativeOffset(maxSpeculativeRefAddress)
			.setMinStoreLoadOffset(minStoreLoadRefAddress)
			.setCreateComplexDataFromPointers(createComplexDataFromPointers);

		AddressSet resultSet = symEval.flowConstants(flowStart, null, eval, true, monitor);
		resultSet.add(coveredSet);
		return resultSet;
	}
}
