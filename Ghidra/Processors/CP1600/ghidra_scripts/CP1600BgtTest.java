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

public class CP1600BgtTest extends GhidraScript {
	@Override
	public void run() throws Exception {
		check("bgt_zero", 0x5040, new int[] { 0x20e, 0x3 },
			new String[] { "R0", "Z" }, new long[] { 0x0, 0x1 },
			new long[][] { { 0x5042, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0 } });
		check("bgt_s0z0o0c0", 0x5440, new int[] { 0x20e, 0x3 },
			new String[] { "R0", "Z", "S", "O", "C" }, new long[] { 0x0, 0x0, 0x0, 0x0, 0x0 },
			new long[][] { { 0x5445, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 } });
		check("bgt_s0z0o0c1", 0x5444, new int[] { 0x20e, 0x3 },
			new String[] { "R0", "Z", "S", "O", "C" }, new long[] { 0x0, 0x0, 0x0, 0x0, 0x1 },
			new long[][] { { 0x5449, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1 } });
		check("bgt_s0z0o1c0", 0x5448, new int[] { 0x20e, 0x3 },
			new String[] { "R0", "Z", "S", "O", "C" }, new long[] { 0x0, 0x0, 0x0, 0x1, 0x0 },
			new long[][] { { 0x544a, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0 } });
		check("bgt_s0z0o1c1", 0x544c, new int[] { 0x20e, 0x3 },
			new String[] { "R0", "Z", "S", "O", "C" }, new long[] { 0x0, 0x0, 0x0, 0x1, 0x1 },
			new long[][] { { 0x544e, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x1 } });
		check("bgt_s0z1o0c0", 0x5450, new int[] { 0x20e, 0x3 },
			new String[] { "R0", "Z", "S", "O", "C" }, new long[] { 0x0, 0x1, 0x0, 0x0, 0x0 },
			new long[][] { { 0x5452, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0 } });
		check("bgt_s0z1o0c1", 0x5454, new int[] { 0x20e, 0x3 },
			new String[] { "R0", "Z", "S", "O", "C" }, new long[] { 0x0, 0x1, 0x0, 0x0, 0x1 },
			new long[][] { { 0x5456, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x1 } });
		check("bgt_s0z1o1c0", 0x5458, new int[] { 0x20e, 0x3 },
			new String[] { "R0", "Z", "S", "O", "C" }, new long[] { 0x0, 0x1, 0x0, 0x1, 0x0 },
			new long[][] { { 0x545a, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x1, 0x0 } });
		check("bgt_s0z1o1c1", 0x545c, new int[] { 0x20e, 0x3 },
			new String[] { "R0", "Z", "S", "O", "C" }, new long[] { 0x0, 0x1, 0x0, 0x1, 0x1 },
			new long[][] { { 0x545e, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x1, 0x1 } });
		check("bgt_s1z0o0c0", 0x5460, new int[] { 0x20e, 0x3 },
			new String[] { "R0", "Z", "S", "O", "C" }, new long[] { 0x0, 0x0, 0x1, 0x0, 0x0 },
			new long[][] { { 0x5462, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0 } });
		check("bgt_s1z0o0c1", 0x5464, new int[] { 0x20e, 0x3 },
			new String[] { "R0", "Z", "S", "O", "C" }, new long[] { 0x0, 0x0, 0x1, 0x0, 0x1 },
			new long[][] { { 0x5466, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x1 } });
		check("bgt_s1z0o1c0", 0x5468, new int[] { 0x20e, 0x3 },
			new String[] { "R0", "Z", "S", "O", "C" }, new long[] { 0x0, 0x0, 0x1, 0x1, 0x0 },
			new long[][] { { 0x546d, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x1, 0x0 } });
		check("bgt_s1z0o1c1", 0x546c, new int[] { 0x20e, 0x3 },
			new String[] { "R0", "Z", "S", "O", "C" }, new long[] { 0x0, 0x0, 0x1, 0x1, 0x1 },
			new long[][] { { 0x5471, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x1, 0x1 } });
		check("bgt_s1z1o0c0", 0x5470, new int[] { 0x20e, 0x3 },
			new String[] { "R0", "Z", "S", "O", "C" }, new long[] { 0x0, 0x1, 0x1, 0x0, 0x0 },
			new long[][] { { 0x5472, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x1, 0x0, 0x0 } });
		check("bgt_s1z1o0c1", 0x5474, new int[] { 0x20e, 0x3 },
			new String[] { "R0", "Z", "S", "O", "C" }, new long[] { 0x0, 0x1, 0x1, 0x0, 0x1 },
			new long[][] { { 0x5476, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x1, 0x0, 0x1 } });
		check("bgt_s1z1o1c0", 0x5478, new int[] { 0x20e, 0x3 },
			new String[] { "R0", "Z", "S", "O", "C" }, new long[] { 0x0, 0x1, 0x1, 0x1, 0x0 },
			new long[][] { { 0x547a, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x1, 0x1, 0x0 } });
		check("bgt_s1z1o1c1", 0x547c, new int[] { 0x20e, 0x3 },
			new String[] { "R0", "Z", "S", "O", "C" }, new long[] { 0x0, 0x1, 0x1, 0x1, 0x1 },
			new long[][] { { 0x547e, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x1, 0x1, 0x1 } });
		if (failures != 0) {
			throw new AssertionError(failures + " state mismatches");
		}
		println("PASS: 17 synthetic cases");
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
