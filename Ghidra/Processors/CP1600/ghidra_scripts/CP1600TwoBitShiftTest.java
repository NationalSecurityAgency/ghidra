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
// Tests synthetic CP1600 instructions without a ROM image or an open program.
// @category Tests.CP1600

import ghidra.app.script.GhidraScript;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.util.DefaultLanguageService;

public class CP1600TwoBitShiftTest extends GhidraScript {
	@Override
	public void run() throws Exception {
		check("swap2_r0", 0x5620, new int[] { 0x44 },
			new String[] { "R0", "Z", "C", "O" }, new long[] { 0xc0a5, 0x0, 0x1, 0x1 },
			new long[][] { { 0x5621, 0xa5a5, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x1, 0x1 } });
		check("swap2_r1", 0x5628, new int[] { 0x45 },
			new String[] { "R0", "Z", "C", "O", "R1" }, new long[] { 0x0, 0x0, 0x1, 0x1, 0xc0a5 },
			new long[][] { { 0x5629, 0x0, 0xa5a5, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x1, 0x1 } });
		check("sll2_r0", 0x5640, new int[] { 0x4c },
			new String[] { "R0", "Z", "C", "O" }, new long[] { 0xc0a5, 0x0, 0x1, 0x1 },
			new long[][] { { 0x5641, 0x294, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x1 } });
		check("sll2_r1", 0x5648, new int[] { 0x4d },
			new String[] { "R0", "Z", "C", "O", "R1" }, new long[] { 0x0, 0x0, 0x1, 0x1, 0xc0a5 },
			new long[][] { { 0x5649, 0x0, 0x294, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x1 } });
		check("rlc2_r0", 0x5660, new int[] { 0x54 },
			new String[] { "R0", "Z", "C", "O" }, new long[] { 0xc0a5, 0x0, 0x1, 0x1 },
			new long[][] { { 0x5661, 0x297, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x1 } });
		check("rlc2_r1", 0x5668, new int[] { 0x55 },
			new String[] { "R0", "Z", "C", "O", "R1" }, new long[] { 0x0, 0x0, 0x1, 0x1, 0xc0a5 },
			new long[][] { { 0x5669, 0x0, 0x297, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x1 } });
		check("sllc2_r0", 0x5680, new int[] { 0x5c },
			new String[] { "R0", "Z", "C", "O" }, new long[] { 0xc0a5, 0x0, 0x1, 0x1 },
			new long[][] { { 0x5681, 0x294, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x1 } });
		check("sllc2_r1", 0x5688, new int[] { 0x5d },
			new String[] { "R0", "Z", "C", "O", "R1" }, new long[] { 0x0, 0x0, 0x1, 0x1, 0xc0a5 },
			new long[][] { { 0x5689, 0x0, 0x294, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x1 } });
		check("slr2_r0", 0x56a0, new int[] { 0x64 },
			new String[] { "R0", "Z", "C", "O" }, new long[] { 0xc0a5, 0x0, 0x1, 0x1 },
			new long[][] { { 0x56a1, 0x3029, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x1 } });
		check("slr2_r1", 0x56a8, new int[] { 0x65 },
			new String[] { "R0", "Z", "C", "O", "R1" }, new long[] { 0x0, 0x0, 0x1, 0x1, 0xc0a5 },
			new long[][] { { 0x56a9, 0x0, 0x3029, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x1 } });
		check("sar2_r0", 0x56c0, new int[] { 0x6c },
			new String[] { "R0", "Z", "C", "O" }, new long[] { 0xc0a5, 0x0, 0x1, 0x1 },
			new long[][] { { 0x56c1, 0xf029, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x1 } });
		check("sar2_r1", 0x56c8, new int[] { 0x6d },
			new String[] { "R0", "Z", "C", "O", "R1" }, new long[] { 0x0, 0x0, 0x1, 0x1, 0xc0a5 },
			new long[][] { { 0x56c9, 0x0, 0xf029, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x1 } });
		check("rrc2_r0", 0x56e0, new int[] { 0x74 },
			new String[] { "R0", "Z", "C", "O" }, new long[] { 0xc0a5, 0x0, 0x1, 0x1 },
			new long[][] { { 0x56e1, 0xf029, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1 } });
		check("rrc2_r1", 0x56e8, new int[] { 0x75 },
			new String[] { "R0", "Z", "C", "O", "R1" }, new long[] { 0x0, 0x0, 0x1, 0x1, 0xc0a5 },
			new long[][] { { 0x56e9, 0x0, 0xf029, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1 } });
		check("sarc2_r0", 0x5700, new int[] { 0x7c },
			new String[] { "R0", "Z", "C", "O" }, new long[] { 0xc0a5, 0x0, 0x1, 0x1 },
			new long[][] { { 0x5701, 0xf029, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1 } });
		check("sarc2_r1", 0x5708, new int[] { 0x7d },
			new String[] { "R0", "Z", "C", "O", "R1" }, new long[] { 0x0, 0x0, 0x1, 0x1, 0xc0a5 },
			new long[][] { { 0x5709, 0x0, 0xf029, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1 } });
		if (failures != 0) {
			throw new AssertionError(failures + " state mismatches");
		}
		println("PASS: 16 synthetic cases");
	}

	private int failures;

	private void check(String name, int pc, int[] words, String[] registers,
			long[] initial, long[][] expected) throws Exception {
		String languageId = getScriptArgs().length == 0 ? "CP1600:BE:16:default" : getScriptArgs()[0];
		Language language = DefaultLanguageService.getLanguageService()
				.getLanguage(new LanguageID(languageId));
		ProgramDB program = new ProgramDB(name, language, language.getDefaultCompilerSpec(), this);
		try {
			AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
			int transaction = program.startTransaction("Synthetic test");
			try {
				program.getMemory().createInitializedBlock("test", space.getAddress(0),
					0x10000, (byte) 0, monitor, false);
				byte[] bytes = new byte[words.length * 2];
				for (int i = 0; i < words.length; i++) {
					bytes[2 * i] = (byte) (words[i] >> 8);
					bytes[2 * i + 1] = (byte) words[i];
				}
				program.getMemory().setBytes(space.getAddress(pc, true), bytes);
				new DisassembleCommand(space.getAddress(pc, true), null, true)
						.applyTo(program, monitor);
			}
			finally {
				program.endTransaction(transaction, true);
			}
			EmulatorHelper emulator = new EmulatorHelper(program);
			try {
				for (int i = 0; i < 8; i++) {
					emulator.writeRegister("R" + i, 0);
				}
				for (String flag : new String[] { "I", "S", "Z", "O", "C" }) {
					emulator.writeRegister(flag, 0);
				}
				for (int i = 0; i < registers.length; i++) {
					emulator.writeRegister(registers[i], initial[i]);
				}
				emulator.writeMemory(space.getAddress(0x300, true),
					new byte[] { 0x03, 0x01, 0x56, 0x78 });
				emulator.writeRegister("R7", pc);
				String[] observed = { "R0", "R1", "R2", "R3", "R4", "R5", "R6", "S", "Z", "O", "C" };
				for (int step = 0; step < expected.length; step++) {
					if (!emulator.step(monitor)) {
						throw new AssertionError(name + ": " + emulator.getLastError());
					}
					equal(name, step, "PC", expected[step][0],
						emulator.getExecutionAddress().getAddressableWordOffset());
					for (int i = 0; i < observed.length; i++) {
						equal(name, step, observed[i], expected[step][i + 1],
							emulator.readRegister(observed[i]).longValue());
					}
				}
			}
			finally {
				emulator.dispose();
			}
		}
		finally {
			program.release(this);
		}
	}

	private void equal(String name, int step, String register, long expected, long actual) {
		if (expected != actual) {
			failures++;
			printerr(String.format("%s step %d %s: expected 0x%X, got 0x%X",
				name, step + 1, register, expected, actual));
		}
	}
}
