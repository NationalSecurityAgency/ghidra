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
package ghidra.pcode.exec;

import static org.junit.Assert.assertEquals;

import java.math.BigInteger;
import java.util.*;

import org.junit.AssumptionViolatedException;
import org.junit.Before;

import generic.test.AbstractGenericTest;
import ghidra.app.plugin.assembler.*;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.pcode.emu.*;
import ghidra.pcode.emulate.BreakTableCallBack;
import ghidra.pcode.emulate.Emulate;
import ghidra.pcode.exec.PcodeArithmetic.Purpose;
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason;
import ghidra.pcode.memstate.*;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.util.Msg;
import ghidra.util.NumericUtilities;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.exception.MultipleCauses;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.util.task.TaskMonitor;

public class AbstractEmulationEquivalenceTest extends AbstractGenericTest {
	protected static final TaskMonitor MONITOR = new ConsoleTaskMonitor();

	protected static class TestMemoryFaultHandler implements MemoryFaultHandler {
		@Override
		public boolean uninitializedRead(Address address, int size, byte[] buf, int bufOffset) {
			return false;
		}

		@Override
		public boolean unknownAddress(Address address, boolean write) {
			return false;
		}
	}

	protected interface DoAsm {
		void accept(AssemblyBuffer buf) throws Exception;
	}

	@Before
	public void setupSearch() throws Exception {
		ClassSearcher.search(MONITOR);
	}

	protected long getEntryOffset() {
		return 0x00400000;
	}

	protected void doTestEquivOld(SleighLanguage language, Map<String, String> init,
			AssemblyBuffer buf, int count, Map<String, String> expected) throws Exception {
		Address entry = buf.getEntry();

		MemoryState state = new DefaultMemoryState(language);
		Emulate emu = new Emulate(language, state, new BreakTableCallBack(language));
		AddressSet regsUnchecked = new AddressSet();
		state.setMemoryBank(new MemoryPageBank(language.getAddressFactory().getRegisterSpace(),
			language.isBigEndian(), 0x1000, new TestMemoryFaultHandler()) {

			@Override
			public void setChunk(long offset, int size, byte[] val) {
				super.setChunk(offset, size, val);
				try {
					regsUnchecked.add(new AddressRangeImpl(getSpace().getAddress(offset), size));
				}
				catch (AddressOverflowException | AddressOutOfBoundsException e) {
					throw new AssertionError(e);
				}
			}
		});
		state.setMemoryBank(new MemoryPageBank(language.getDefaultSpace(),
			language.isBigEndian(), 0x1000, new TestMemoryFaultHandler()) {
			@Override
			public void setChunk(long offset, int size, byte[] val) {
				/*Msg.info(this, "Old set ram[0x%x]:%d = %s".formatted(offset, size,
					NumericUtilities.convertBytesToString(val)));*/
				super.setChunk(offset, size, val);
			}
		});
		byte[] bytes = buf.getBytes();
		state.setChunk(bytes, language.getDefaultSpace(), entry.getOffset(), bytes.length);

		for (Map.Entry<String, String> ent : init.entrySet()) {
			state.setValue(ent.getKey(), new BigInteger(ent.getValue(), 16));
		}

		emu.setExecuteAddress(entry);
		for (int i = 0; i < count; i++) {
			emu.executeInstruction(false, MONITOR);
		}

		for (Map.Entry<String, String> ent : expected.entrySet()) {
			assertEquals("Old register value mismatch on " + ent.getKey(), ent.getValue(),
				state.getBigInteger(ent.getKey()).toString(16));
			Register reg = language.getRegister(ent.getKey());
			if (!reg.getAddressSpace().isRegisterSpace()) {
				continue;
			}
			regsUnchecked.delete(new AddressRangeImpl(reg.getAddress(), reg.getNumBytes()));
		}

		if (!regsUnchecked.isEmpty()) {
			Set<String> regs = new TreeSet<>();
			nextAddr: while (!regsUnchecked.isEmpty()) {
				Address min = regsUnchecked.getMinAddress();
				List<Register> found = Arrays.asList(language.getRegisters(min));
				found.sort((r1, r2) -> r1.getBitLength() - r2.getBitLength());
				for (Register r : found) {
					AddressRange rng = new AddressRangeImpl(r.getAddress(), r.getNumBytes());
					if (!regsUnchecked.contains(rng.getMinAddress(), rng.getMaxAddress())) {
						continue;
					}
					regs.add(r.getName());
					regsUnchecked.delete(rng);
					continue nextAddr;
				}
				regsUnchecked.delete(min, min);
			}
			if (!regs.isEmpty()) {
				throw new AssertionError("Some written registers were not asserted: " + regs);
			}
		}
	}

	protected void doTestEquivNew(SleighLanguage language, Map<String, String> init,
			AssemblyBuffer buf, int count, Map<String, String> expected) throws Exception {
		Address entry = buf.getEntry();

		@SuppressWarnings("unused") // uncomment arg to PcodeEmulator to enable
		PcodeEmulationCallbacks<byte[]> cb = new PcodeEmulationCallbacks<>() {
			public <A, U> void dataWritten(PcodeThread<byte[]> thread,
					PcodeExecutorStatePiece<A, U> piece, Address address, int length, U value) {
				if (!address.isMemoryAddress()) {
					return;
				}
				if (!(value instanceof byte[] v)) {
					return;
				}
				Msg.info(this, "New set ram[0x%x]:%d = %s".formatted(address.getOffset(), length,
					NumericUtilities.convertBytesToString(v)));
			};
		};
		PcodeEmulator emu = new PcodeEmulator(language/*, cb*/) {
			@Override
			protected BytesPcodeThread createThread(String name) {
				/**
				 * TODO: There's a branch somewhere that will make this not work.
				 */
				return new BytesPcodeThread(name, this) {
					@Override
					protected boolean onMissingUseropDef(PcodeOp op, String opName) {
						return false;
					}
				};
			}
		};
		byte[] bytes = buf.getBytes();
		emu.getSharedState().setVar(entry, bytes.length, false, bytes);

		PcodeThread<byte[]> thread = emu.newThread();
		PcodeExecutorState<byte[]> state = thread.getState();
		PcodeArithmetic<byte[]> arithmetic = thread.getArithmetic();

		for (Map.Entry<String, String> ent : init.entrySet()) {
			Register reg = language.getRegister(ent.getKey());
			state.setVar(reg,
				arithmetic.fromConst(new BigInteger(ent.getValue(), 16), reg.getNumBytes()));
		}

		thread.setCounter(entry);
		thread.overrideContextWithDefault();
		thread.stepInstruction(count);

		for (Map.Entry<String, String> ent : expected.entrySet()) {
			Register reg = language.getRegister(ent.getKey());
			assertEquals("New register value mismatch on " + ent.getKey(), ent.getValue(),
				arithmetic.toBigInteger(state.getVar(reg, Reason.INSPECT), Purpose.INSPECT)
						.toString(16));
		}
	}

	protected void doTestEquiv(SleighLanguage language, Map<String, String> init, DoAsm doAsm,
			int count, Map<String, String> expected) throws Exception {
		//Msg.info(this, "Language: " + language.getLanguageID());
		Assembler asm = Assemblers.getAssembler(language);
		Address entry = language.getDefaultSpace().getAddress(getEntryOffset());
		AssemblyBuffer buf = new AssemblyBuffer(asm, entry);

		doAsm.accept(buf);

		AssertionError oldFailure = null;
		AssertionError newFailure = null;
		try {
			doTestEquivOld(language, init, buf, count, expected);
		}
		catch (AssertionError e) {
			oldFailure = e;
			Msg.error("Old failed: " + e, e);
		}
		try {
			doTestEquivNew(language, init, buf, count, expected);
		}
		catch (AssertionError e) {
			newFailure = e;
			Msg.error("New failed: " + e, e);
		}

		if (newFailure != null && oldFailure != null) {
			throw new AssertionError("Both old and new failed",
				new MultipleCauses(List.of(oldFailure, newFailure)));
		}
		if (newFailure != null) {
			throw newFailure;
		}
		if (oldFailure != null) {
			throw new AssumptionViolatedException(
				"Old failed, but new passed: " + oldFailure.getMessage(), oldFailure);
		}
	}
}
