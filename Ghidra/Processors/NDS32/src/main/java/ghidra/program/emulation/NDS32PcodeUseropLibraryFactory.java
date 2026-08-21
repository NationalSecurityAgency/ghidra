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
package ghidra.program.emulation;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.app.util.PseudoDisassemblerContext;
import ghidra.app.util.PseudoInstruction;
import ghidra.pcode.exec.AnnotatedPcodeUseropLibrary;
import ghidra.pcode.exec.PcodeArithmetic;
import ghidra.pcode.exec.PcodeArithmetic.Purpose;
import ghidra.pcode.exec.PcodeExecutor;
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason;
import ghidra.pcode.exec.PcodeFrame;
import ghidra.pcode.exec.PcodeProgram;
import ghidra.pcode.exec.PcodeUseropLibrary;
import ghidra.pcode.exec.PcodeUseropLibraryFactory;
import ghidra.pcode.exec.PcodeExecutionException;
import ghidra.pcode.emu.DefaultPcodeThread.PcodeThreadExecutor;
import ghidra.pcode.emu.PcodeThread;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.InstructionPrototype;
import ghidra.program.model.lang.Register;
import ghidra.program.model.mem.ByteMemBufferImpl;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.util.ProgramContextImpl;

/**
 * NDS32 userop library for the {@link ghidra.pcode.emu.PcodeEmulator}.
 * Handles the {@code ex9} callother by decoding the IT entry at
 * {@code (itb & ~3) + imm * 4} and executing its pcode in place, plus stub
 * no-ops for system-state operations (TLB, isb/dsb, mfsr/mtsr, etc.) so
 * emulator-based analyses don't choke on boot code.  Hooked up via the
 * {@code useropLibs} property in {@code nds32.pspec}.
 */
@PcodeUseropLibraryFactory.UseropLibrary("nds32")
public class NDS32PcodeUseropLibraryFactory implements PcodeUseropLibraryFactory {

	@Override
	public <T> PcodeUseropLibrary<T> create(SleighLanguage language,
			PcodeArithmetic<T> arithmetic) {
		return new NDS32PcodeUseropLibrary<>(language, arithmetic);
	}

	public static class NDS32PcodeUseropLibrary<T> extends AnnotatedPcodeUseropLibrary<T> {
		private final SleighLanguage language;
		private final PcodeArithmetic<T> arithmetic;
		private final Register itbReg;

		public NDS32PcodeUseropLibrary(SleighLanguage language, PcodeArithmetic<T> arithmetic) {
			this.language = language;
			this.arithmetic = arithmetic;
			this.itbReg = language.getRegister("itb");
		}

		// System-state pcodeops modeled as no-ops so analyzer-driven emulation
		// (e.g. NDS32DataInitAnalyzer) doesn't choke on boot code.  Variadic
		// stubs accept both shapes of the underlying sleigh op (with or
		// without an argument like setgie's enable flag).
		@PcodeUserop(variadic = true) public void isb(T... args) {}
		@PcodeUserop(variadic = true) public void dsb(T... args) {}
		@PcodeUserop(variadic = true) public void msync(T... args) {}
		@PcodeUserop(variadic = true) public void isync(T... args) {}
		@PcodeUserop(variadic = true) public void dpref(T... args) {}
		@PcodeUserop(variadic = true) public void cctl(T... args) {}
		@PcodeUserop(variadic = true) public void setgie(T... args) {}
		@PcodeUserop(variadic = true) public void setend(T... args) {}
		@PcodeUserop(variadic = true) public void standby(T... args) {}

		// TLB ops -- no MMU model.
		@PcodeUserop(variadic = true) public void TLB_TargetRead(T... args) {}
		@PcodeUserop(variadic = true) public void TLB_TargetWrite(T... args) {}
		@PcodeUserop(variadic = true) public void TLB_RWrite(T... args) {}
		@PcodeUserop(variadic = true) public void TLB_RWriteLock(T... args) {}
		@PcodeUserop(variadic = true) public void TLB_Unlock(T... args) {}
		@PcodeUserop(variadic = true) public void TLB_Probe(T... args) {}
		@PcodeUserop(variadic = true) public void TLB_Invalidate(T... args) {}
		@PcodeUserop(variadic = true) public void TLB_FlushAll(T... args) {}

		// Trap / system control.
		@PcodeUserop(variadic = true) public void break_(T... args) {}
		@PcodeUserop(variadic = true) public void syscall(T... args) {}
		@PcodeUserop(variadic = true) public void trap(T... args) {}

		// mfsr / mtsr -- system registers (cpu_ver, msc_cfg, ...) aren't
		// modeled; return 0 so init code's deterministic branches resolve.
		@PcodeUserop(variadic = true) public T mfsr(T... args) {
			return arithmetic.fromConst(0, 4);
		}
		@PcodeUserop(variadic = true) public void mtsr(T... args) {}

		@PcodeUserop
		public void ex9(@OpExecutor PcodeExecutor<T> executor,
				@OpLibrary PcodeUseropLibrary<T> library, T immVal) {
			if (!(executor instanceof PcodeThreadExecutor<T> threadExec)) {
				throw new PcodeExecutionException(
					"ex9 requires a PcodeThreadExecutor (got " + executor.getClass().getName()
						+ "); ex9 only works under PcodeEmulator-style emulation");
			}
			PcodeThread<T> thread = threadExec.getThread();

			long imm = arithmetic.toLong(immVal, Purpose.OTHER);

			if (itbReg == null) {
				throw new PcodeExecutionException("ex9: itb register not defined");
			}
			T itbV = thread.getState().getVar(itbReg, Reason.EXECUTE_READ);
			long itb = arithmetic.toLong(itbV, Purpose.OTHER);

			Address site = thread.getCounter();
			AddressSpace defaultSpace = site.getAddressSpace();
			long memOffset = (itb & ~0b11L) + imm * 4;

			// Raw memory-order bytes; ByteMemBufferImpl in decodeAt() handles endianness.
			byte[] bytes = new byte[4];
			T entryV = thread.getState().getVar(defaultSpace, memOffset, 4, true,
				Reason.EXECUTE_READ);
			byte[] concrete;
			try {
				concrete = arithmetic.toConcrete(entryV, Purpose.OTHER);
			}
			catch (Exception e) {
				throw new PcodeExecutionException(
					"ex9: IT entry @ 0x" + Long.toHexString(memOffset) +
						" not concrete: " + e.getMessage());
			}
			if (concrete == null || concrete.length < 4) {
				throw new PcodeExecutionException(
					"ex9: failed to read IT entry @ 0x" + Long.toHexString(memOffset));
			}
			System.arraycopy(concrete, 0, bytes, 0, 4);

			// Branches/calls re-decode at PC=0 to recover the absolute target
			// (per NDS32 manual); other instructions decode at the ex9.it site
			// so PC-relative loads/stores resolve correctly.
			PseudoInstruction fetched = decodeAt(site, bytes);
			if (fetched == null) {
				throw new PcodeExecutionException("ex9: failed to decode IT entry @ 0x"
					+ Long.toHexString(memOffset));
			}
			if (fetched.getMnemonicString().equalsIgnoreCase("ex9.it")) {
				throw new PcodeExecutionException(
					"ex9: nested ex9.it (would raise Reserved Instruction Exception)");
			}
			if (fetched.getFlowType().isJump() || fetched.getFlowType().isCall()) {
				PseudoInstruction relAtZero =
					decodeAt(defaultSpace.getAddress(0), bytes);
				if (relAtZero == null) {
					throw new PcodeExecutionException("ex9: failed to re-decode IT entry @ 0");
				}
				fetched = relAtZero;
			}

			PcodeProgram inner = PcodeProgram.fromInstruction(fetched);
			PcodeFrame frame = executor.execute(inner, library);

			// Calls must save the ex9.it return address, not the inner inst_next.
			// Because the inner was decoded at addr=0, sleigh's `link = inst_next`
			// wrote the inner instruction's length (2 or 4) into the link register;
			// patch it to the address after the ex9.it.
			if (fetched.getFlowType().isCall()) {
				Register linkReg = findLinkRegister(fetched);
				if (linkReg != null) {
					long correctLp = site.getOffset()
							+ thread.getInstruction().getLength();
					T newVal = arithmetic.fromConst(correctLp,
							linkReg.getMinimumByteSize());
					thread.getState().setVar(linkReg, newVal);
				}
			}

			// Emulator will advance the counter by ex9.it's length after return.
			// If the IT entry branched, executor.execute already moved the counter
			// to the target -- pre-compensate by subtracting the ex9.it length.
			if (!frame.isFallThrough()) {
				thread.overrideCounter(
					thread.getCounter().subtractWrap(thread.getInstruction().getLength()));
			}
		}

		// Sleigh emits `link = inst_next` as `COPY register, const(innerLen)` when
		// we decoded at inst_start=0; the matching output varnode is the link
		// register (lp for jal/jral5/bgezal/bltzal, Rt for jral).
		private Register findLinkRegister(PseudoInstruction inst) {
			long innerLen = inst.getLength();
			for (PcodeOp op : inst.getPcode()) {
				if (op.getOpcode() != PcodeOp.COPY) {
					continue;
				}
				Varnode in = op.getInput(0);
				Varnode out = op.getOutput();
				if (in == null || out == null || !in.isConstant()) {
					continue;
				}
				if (in.getOffset() != innerLen) {
					continue;
				}
				Register reg =
					language.getRegister(out.getAddress(), out.getSize());
				if (reg != null) {
					return reg;
				}
			}
			return null;
		}

		private PseudoInstruction decodeAt(Address addr, byte[] bytes) {
			try {
				ProgramContextImpl ctx = new ProgramContextImpl(language);
				PseudoDisassemblerContext disCtx = new PseudoDisassemblerContext(ctx);
				MemBuffer buf = new ByteMemBufferImpl(addr, bytes, language.isBigEndian());
				disCtx.flowStart(addr);
				InstructionPrototype proto = language.parse(buf, disCtx, false);
				if (proto == null) {
					return null;
				}
				AddressFactory factory = language.getAddressFactory();
				return new PseudoInstruction(factory, addr, proto, buf, disCtx);
			}
			catch (Exception e) {
				return null;
			}
		}
	}
}
