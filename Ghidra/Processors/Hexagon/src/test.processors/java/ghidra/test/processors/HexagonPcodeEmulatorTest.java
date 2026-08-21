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

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.fail;

import org.junit.Test;

import ghidra.app.util.PseudoInstruction;
import ghidra.pcode.emu.*;
import ghidra.pcode.exec.*;
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.util.NumericUtilities;

public class HexagonPcodeEmulatorTest extends AbstractGhidraHeadlessIntegrationTest {
	@Test
	public void testCunitSample() throws Throwable {
		PcodeEmulator emu = new PcodeEmulator(
			getLanguageService().getLanguage(new LanguageID("Hexagon:LE:32:default"))) {
			@Override
			protected BytesPcodeThread createThread(String name) {
				return new BytesPcodeThread(name, this) {
					@Override
					protected PcodeThreadExecutor<byte[]> createExecutor() {
						return new PcodeThreadExecutor<>(this) {
							@Override
							public void stepOp(PcodeOp op, PcodeFrame frame,
									PcodeUseropLibrary<byte[]> library) {
								//System.err.println("  StepOp: " + op);
								super.stepOp(op, frame, library);
							}
						};
					}

					@Override
					protected SleighInstructionDecoder createInstructionDecoder(
							PcodeExecutorState<byte[]> sharedState) {
						return new SleighInstructionDecoder(language, sharedState) {
							@Override
							public PseudoInstruction decodeInstruction(Address address,
									RegisterValue context) {
								PseudoInstruction instruction =
									super.decodeInstruction(address, context);
								//System.err.println("Decoded " + address + ": " + instruction);
								return instruction;
							}
						};
					}
				};
			}
		};
		PcodeThread<byte[]> thread = emu.newThread();
		AddressSpace as = emu.getLanguage().getDefaultSpace();

		byte[] code_db54 = NumericUtilities.convertStringToBytes("""
				09c09da0284a000042c300782e4a000003c0007841e7007800c06270f9e29ea702c06370f8e39ea784c
				e035a20c0c049ffe0dea742c0c049fee2dea7e2ffde97c4ffde97fbe0dea700c203f502c405f5f8c100
				5afde0dea7a4ffde9702c07d7060ffde9700c0c2a121e8007802c0007820ff9e97f5e29ea7fcc9035a6
				0c0c049f9e0dea722ffde97dcc1005a02c07d7004c1c04900c4c2a142e8007823ff9e97f8e0dea700c0
				637001c06270a2fe9e9704ffde97dec9035a81e8007820ff9e9702ff9e972ace035a1ec01e96"""
				.replaceAll("\\s+", ""));
		emu.getSharedState().setVar(as, 0xdb54, code_db54.length, false, code_db54);

		byte[] code_27a00 = NumericUtilities.convertStringToBytes("""
				00478185004780850440c14326c0c1432e40205c004882754840c1416ac0c1412640005c00448275004
				4c04408c6c04401458275024682758c40c141aec8c1430248c0a103cac0a100527f53204cc04029cec0
				4000478275c440c191e6c0c14300409f520644c0a138c6c0401aefff59"""
				.replaceAll("\\s+", ""));
		emu.getSharedState().setVar(as, 0x27a00, code_27a00.length, false, code_27a00);

		byte[] src = new byte[64];
		for (int i = 0; i < src.length; i++) {
			src[i] = (byte) (31 * i + 5);
		}
		emu.getSharedState().setVar(as, 0x10002000, src.length, false, src);

		emu.addBreakpoint(as.getAddress(0xDEADBEEFL), "1:1");
		//thread.getExecutor().executeSleigh("PC=0xdb54; SP=0x40000000;");
		thread.getExecutor()
				.executeSleigh("PC=0x27a00; SP=0x4000000; R0=0x10001000; R1=0x10002000; R2=" +
					src.length + "; LR=0xDEADBEEF;");
		thread.reInitialize();

		try {
			thread.run();
			fail();
		}
		catch (InterruptPcodeExecutionException e) {
			// We hit the breakpoint. Good.
		}

		byte[] dst = emu.getSharedState().getVar(as, 0x10001000, src.length, false, Reason.INSPECT);
		assertArrayEquals(src, dst);
	}
}
