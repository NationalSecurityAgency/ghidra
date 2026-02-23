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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

import java.math.BigInteger;
import java.util.List;
import java.util.Map;

import org.junit.*;

import ghidra.app.plugin.assembler.*;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.pcode.emu.*;
import ghidra.pcode.emulate.BreakTableCallBack;
import ghidra.pcode.emulate.Emulate;
import ghidra.pcode.exec.*;
import ghidra.pcode.exec.PcodeArithmetic.Purpose;
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason;
import ghidra.pcode.memstate.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.lang.Register;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.util.DefaultLanguageService;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.util.exception.MultipleCauses;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.util.task.TaskMonitor;

public class AARCH64PcodeLibraryTest extends AbstractGhidraHeadlessIntegrationTest {
	static final LanguageID LANG_ID_AARCH64 = new LanguageID("AARCH64:LE:64:v8A");

	private SleighLanguage aarch64;
	private TaskMonitor monitor;

	@Before
	public void setup() throws Exception {
		aarch64 = (SleighLanguage) DefaultLanguageService.getLanguageService()
				.getLanguage(LANG_ID_AARCH64);
		monitor = new ConsoleTaskMonitor();
	}

	public Varnode vn(long offset, int size) {
		AddressSpace space = aarch64.getDefaultSpace();
		return new Varnode(space.getAddress(offset), size);
	}

	@Test
	public void testA64_TBL_1_8B() throws Exception {
		PcodeUseropLibrary<byte[]> lib = PcodeUseropLibraryFactory.createUseropLibraryFromId(
			"aarch64", aarch64, BytesPcodeArithmetic.forLanguage(aarch64));

		SleighPcodeUseropDefinition<byte[]> tbl =
			(SleighPcodeUseropDefinition<byte[]>) lib.getUserops().get("a64_TBL");

		Varnode vnDest = vn(0, 8);
		Varnode vnInit = vn(16, 8);
		Varnode vnN1 = vn(32, 16);
		Varnode vnM = vn(96, 8);
		PcodeProgram program = tbl.programFor(
			List.of(vnDest, vnInit, vnN1, vnM),
			lib);

		assertFalse(program.getCode().isEmpty());
	}

	@Test
	public void testA64_TBL_2_8B() throws Exception {
		PcodeUseropLibrary<byte[]> lib = PcodeUseropLibraryFactory.createUseropLibraryFromId(
			"aarch64", aarch64, BytesPcodeArithmetic.forLanguage(aarch64));

		SleighPcodeUseropDefinition<byte[]> tbl =
			(SleighPcodeUseropDefinition<byte[]>) lib.getUserops().get("a64_TBL");

		Varnode vnDest = vn(0, 8);
		Varnode vnInit = vn(16, 8);
		Varnode vnN1 = vn(32, 16);
		Varnode vnN2 = vn(48, 16);
		Varnode vnM = vn(96, 8);
		PcodeProgram program = tbl.programFor(
			List.of(vnDest, vnInit, vnN1, vnN2, vnM),
			lib);

		assertFalse(program.getCode().isEmpty());
	}

	@Test
	public void testA64_TBL_3_8B() throws Exception {
		PcodeUseropLibrary<byte[]> lib = PcodeUseropLibraryFactory.createUseropLibraryFromId(
			"aarch64", aarch64, BytesPcodeArithmetic.forLanguage(aarch64));

		SleighPcodeUseropDefinition<byte[]> tbl =
			(SleighPcodeUseropDefinition<byte[]>) lib.getUserops().get("a64_TBL");

		Varnode vnDest = vn(0, 8);
		Varnode vnInit = vn(16, 8);
		Varnode vnN1 = vn(32, 16);
		Varnode vnN2 = vn(48, 16);
		Varnode vnN3 = vn(64, 16);
		Varnode vnM = vn(96, 8);
		PcodeProgram program = tbl.programFor(
			List.of(vnDest, vnInit, vnN1, vnN2, vnN3, vnM),
			lib);

		assertFalse(program.getCode().isEmpty());
	}

	@Test
	public void testA64_TBL_4_8B() throws Exception {
		PcodeUseropLibrary<byte[]> lib = PcodeUseropLibraryFactory.createUseropLibraryFromId(
			"aarch64", aarch64, BytesPcodeArithmetic.forLanguage(aarch64));

		SleighPcodeUseropDefinition<byte[]> tbl =
			(SleighPcodeUseropDefinition<byte[]>) lib.getUserops().get("a64_TBL");

		Varnode vnDest = vn(0, 8);
		Varnode vnInit = vn(16, 8);
		Varnode vnN1 = vn(32, 16);
		Varnode vnN2 = vn(48, 16);
		Varnode vnN3 = vn(64, 16);
		Varnode vnN4 = vn(80, 16);
		Varnode vnM = vn(96, 8);
		PcodeProgram program = tbl.programFor(
			List.of(vnDest, vnInit, vnN1, vnN2, vnN3, vnN4, vnM),
			lib);

		assertFalse(program.getCode().isEmpty());
	}

	@Test
	public void testA64_TBL_1_16B() throws Exception {
		PcodeUseropLibrary<byte[]> lib = PcodeUseropLibraryFactory.createUseropLibraryFromId(
			"aarch64", aarch64, BytesPcodeArithmetic.forLanguage(aarch64));

		SleighPcodeUseropDefinition<byte[]> tbl =
			(SleighPcodeUseropDefinition<byte[]>) lib.getUserops().get("a64_TBL");

		Varnode vnDest = vn(0, 16);
		Varnode vnInit = vn(16, 16);
		Varnode vnN1 = vn(32, 16);
		Varnode vnM = vn(96, 16);
		PcodeProgram program = tbl.programFor(
			List.of(vnDest, vnInit, vnN1, vnM),
			lib);

		assertFalse(program.getCode().isEmpty());
	}

	@Test
	public void testA64_TBL_2_16B() throws Exception {
		PcodeUseropLibrary<byte[]> lib = PcodeUseropLibraryFactory.createUseropLibraryFromId(
			"aarch64", aarch64, BytesPcodeArithmetic.forLanguage(aarch64));

		SleighPcodeUseropDefinition<byte[]> tbl =
			(SleighPcodeUseropDefinition<byte[]>) lib.getUserops().get("a64_TBL");

		Varnode vnDest = vn(0, 16);
		Varnode vnInit = vn(16, 16);
		Varnode vnN1 = vn(32, 16);
		Varnode vnN2 = vn(48, 16);
		Varnode vnM = vn(96, 16);
		PcodeProgram program = tbl.programFor(
			List.of(vnDest, vnInit, vnN1, vnN2, vnM),
			lib);

		assertFalse(program.getCode().isEmpty());
	}

	@Test
	public void testA64_TBL_3_16B() throws Exception {
		PcodeUseropLibrary<byte[]> lib = PcodeUseropLibraryFactory.createUseropLibraryFromId(
			"aarch64", aarch64, BytesPcodeArithmetic.forLanguage(aarch64));

		SleighPcodeUseropDefinition<byte[]> tbl =
			(SleighPcodeUseropDefinition<byte[]>) lib.getUserops().get("a64_TBL");

		Varnode vnDest = vn(0, 16);
		Varnode vnInit = vn(16, 16);
		Varnode vnN1 = vn(32, 16);
		Varnode vnN2 = vn(48, 16);
		Varnode vnN3 = vn(64, 16);
		Varnode vnM = vn(96, 16);
		PcodeProgram program = tbl.programFor(
			List.of(vnDest, vnInit, vnN1, vnN2, vnN3, vnM),
			lib);

		assertFalse(program.getCode().isEmpty());
	}

	@Test
	public void testA64_TBL_4_16B() throws Exception {
		PcodeUseropLibrary<byte[]> lib = PcodeUseropLibraryFactory.createUseropLibraryFromId(
			"aarch64", aarch64, BytesPcodeArithmetic.forLanguage(aarch64));

		SleighPcodeUseropDefinition<byte[]> tbl =
			(SleighPcodeUseropDefinition<byte[]>) lib.getUserops().get("a64_TBL");

		Varnode vnDest = vn(0, 16);
		Varnode vnInit = vn(16, 16);
		Varnode vnN1 = vn(32, 16);
		Varnode vnN2 = vn(48, 16);
		Varnode vnN3 = vn(64, 16);
		Varnode vnN4 = vn(80, 16);
		Varnode vnM = vn(96, 16);
		PcodeProgram program = tbl.programFor(
			List.of(vnDest, vnInit, vnN1, vnN2, vnN3, vnN4, vnM),
			lib);

		assertFalse(program.getCode().isEmpty());
	}

	static class TestMemoryFaultHandler implements MemoryFaultHandler {
		@Override
		public boolean uninitializedRead(Address address, int size, byte[] buf, int bufOffset) {
			return false;
		}

		@Override
		public boolean unknownAddress(Address address, boolean write) {
			return false;
		}
	}

	interface DoAsm {
		void accept(AssemblyBuffer buf) throws Exception;
	}

	protected void doTestTBL_Equiv_old(Map<String, String> init, AssemblyBuffer buf,
			Map<String, String> expected) throws Exception {
		Address entry = buf.getEntry();

		MemoryState state = new DefaultMemoryState(aarch64);
		Emulate emu = new Emulate(aarch64, state, new BreakTableCallBack(aarch64));
		state.setMemoryBank(new MemoryPageBank(aarch64.getAddressFactory().getRegisterSpace(),
			false, 0x1000, new TestMemoryFaultHandler()));
		state.setMemoryBank(new MemoryPageBank(aarch64.getDefaultSpace(),
			false, 0x1000, new TestMemoryFaultHandler()));
		byte[] bytes = buf.getBytes();
		state.setChunk(bytes, aarch64.getDefaultSpace(), entry.getOffset(), bytes.length);

		for (Map.Entry<String, String> ent : init.entrySet()) {
			state.setValue(ent.getKey(), new BigInteger(ent.getValue(), 16));
		}

		emu.setExecuteAddress(entry);
		emu.executeInstruction(false, monitor);

		for (Map.Entry<String, String> ent : expected.entrySet()) {
			assertEquals(ent.getValue(), state.getBigInteger(ent.getKey()).toString(16));
		}
	}

	protected void doTestTBL_Equiv_new(Map<String, String> init, AssemblyBuffer buf,
			Map<String, String> expected) throws Exception {
		Address entry = buf.getEntry();

		PcodeEmulator emu = new PcodeEmulator(aarch64) {
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
			Register reg = aarch64.getRegister(ent.getKey());
			state.setVar(reg,
				arithmetic.fromConst(new BigInteger(ent.getValue(), 16), reg.getNumBytes()));
		}

		thread.setCounter(entry);
		thread.overrideContextWithDefault();
		thread.stepInstruction();

		for (Map.Entry<String, String> ent : expected.entrySet()) {
			Register reg = aarch64.getRegister(ent.getKey());
			assertEquals(ent.getValue(),
				arithmetic.toBigInteger(state.getVar(reg, Reason.INSPECT), Purpose.INSPECT)
						.toString(16));
		}
	}

	protected void doTestTBL_Equiv(Map<String, String> init, DoAsm doAsm,
			Map<String, String> expected) throws Exception {
		Assembler asm = Assemblers.getAssembler(aarch64);
		Address entry = aarch64.getDefaultSpace().getAddress(0x00400000);
		AssemblyBuffer buf = new AssemblyBuffer(asm, entry);

		doAsm.accept(buf);

		AssertionError oldFailure = null;
		AssertionError newFailure = null;
		try {
			doTestTBL_Equiv_old(init, buf, expected);
		}
		catch (AssertionError e) {
			oldFailure = e;
		}
		try {
			doTestTBL_Equiv_new(init, buf, expected);
		}
		catch (AssertionError e) {
			newFailure = e;
		}

		if (newFailure != null && oldFailure != null) {
			throw new AssertionError("Both old and new failed",
				new MultipleCauses(List.of(oldFailure, newFailure)));
		}
		if (newFailure != null) {
			throw new AssertionError("New failed", newFailure);
		}
		if (oldFailure != null) {
			throw new AssumptionViolatedException(
				"Old failed, but new passed: " + oldFailure.getMessage(), oldFailure);
		}
	}

	@Test
	public void testTBL_1_8B_Instruction() throws Exception {
		doTestTBL_Equiv(
			Map.ofEntries(
				Map.entry("d1", "040308070c0b100f"),
				Map.entry("q2", "0123456789abcdeffedcba9876543210")),
			buf -> buf.assemble("tbl v0.8B, {v2.16B}, v1.8B"),
			Map.ofEntries(
				Map.entry("d0", "9876effe67890001")));
	}

	@Test
	public void testTBL_2_8B_Instruction() throws Exception {
		doTestTBL_Equiv(
			Map.ofEntries(
				Map.entry("d1", "041408180c1c1020"),
				Map.entry("q2", "0123456789abcdeffedcba9876543210"),
				Map.entry("q3", "00112233445566778899aabbccddeeff")),
			buf -> buf.assemble("tbl v0.8B, {v2.16B, v3.16B}, v1.8B"),
			Map.ofEntries(
				Map.entry("d0", "98bbef776733ff00")));
	}

	@Test
	public void testTBL_1_16B_Instruction() throws Exception {
		doTestTBL_Equiv(
			Map.ofEntries(
				Map.entry("q1", "040308070c0b100f020106050a090e0d"),
				Map.entry("q2", "0123456789abcdeffedcba9876543210")),
			buf -> buf.assemble("tbl v0.16B, {v2.16B}, v1.16B"),
			Map.ofEntries(
				Map.entry("q0", "9876effe678900015432dcbaabcd2345")));
	}

	@Test
	public void testTBL_2_16B_Instruction() throws Exception {
		doTestTBL_Equiv(
			Map.ofEntries(
				Map.entry("q1", "041408180c1c1020021206160a1a0e1e"),
				Map.entry("q2", "0123456789abcdeffedcba9876543210"),
				Map.entry("q3", "00112233445566778899aabbccddeeff")),
			buf -> buf.assemble("tbl v0.16B, {v2.16B, v3.16B}, v1.16B"),
			Map.ofEntries(
				Map.entry("q0", "98bbef776733ff0054dddc99ab552311")));
	}
}
