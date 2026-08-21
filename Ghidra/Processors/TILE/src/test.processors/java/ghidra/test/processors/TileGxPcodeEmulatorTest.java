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
package ghidra.test.processors;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import org.junit.Test;

import ghidra.pcode.emu.PcodeEmulator;
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.exec.PcodeArithmetic.Purpose;
import ghidra.pcode.exec.PcodeExecutorState;
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.lang.Register;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.util.NumericUtilities;

public class TileGxPcodeEmulatorTest extends AbstractGhidraHeadlessIntegrationTest {
	@Test
	public void testBundleReadsRegistersBeforeEitherSlotCommits() throws Exception {
		Language language =
			getLanguageService().getLanguage(new LanguageID("TILE:LE:64:default"));
		assertNotNull(language.getCompilerSpecByID(new CompilerSpecID("gcc")));
		PcodeEmulator emulator = new PcodeEmulator(language);
		Address entry = language.getDefaultSpace().getAddress(0x1000);
		emulator.getSharedState()
				.setVar(entry, 8, false, NumericUtilities.convertStringToBytes("1ef307d1c6430818"));

		PcodeThread<byte[]> thread = emulator.newThread();
		PcodeExecutorState<byte[]> state = thread.getState();
		Register r12 = language.getRegister("r12");
		Register r13 = language.getRegister("r13");
		Register r30 = language.getRegister("r30");
		state.setVar(r12, thread.getArithmetic().fromConst(0x1234, 8));
		state.setVar(r30, thread.getArithmetic().fromConst(0x100, 8));

		thread.setCounter(entry);
		thread.overrideContextWithDefault();
		thread.stepInstruction();

		assertEquals(0x1234, value(thread, r30));
		assertEquals(0x108, value(thread, r13));
	}

	@Test
	public void testLastYSlotExecutesBeforeMiddleSlotFlow() throws Exception {
		Language language =
			getLanguageService().getLanguage(new LanguageID("TILE:LE:64:default"));
		PcodeEmulator emulator = new PcodeEmulator(language);
		Address entry = language.getDefaultSpace().getAddress(0x1000);
		emulator.getSharedState()
				.setVar(entry, 8, false, NumericUtilities.convertStringToBytes("00502c3420681ede"));

		PcodeThread<byte[]> thread = emulator.newThread();
		PcodeExecutorState<byte[]> state = thread.getState();
		state.setVar(language.getRegister("r1"), thread.getArithmetic().fromConst(0x2000, 8));
		state.setVar(language.getRegister("r2"), thread.getArithmetic().fromConst(0x3000, 8));
		state.setVar(language.getRegister("r3"), thread.getArithmetic().fromConst(0x1234, 8));

		thread.setCounter(entry);
		thread.overrideContextWithDefault();
		thread.stepInstruction();

		byte[] stored = emulator.getSharedState()
				.getVar(language.getDefaultSpace(), 0x3000, 8, false, Reason.INSPECT);
		assertEquals(0x1234,
			thread.getArithmetic().toLong(stored, Purpose.INSPECT));
	}

	private static long value(PcodeThread<byte[]> thread, Register register) {
		return thread.getArithmetic()
				.toLong(thread.getState().getVar(register, Reason.INSPECT), Purpose.INSPECT);
	}
}
