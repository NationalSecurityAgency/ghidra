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
package ghidra.app.plugin.core.script;

import static org.junit.Assert.*;

import java.io.File;

import org.junit.*;

import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.framework.Application;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.test.*;
import ghidra.util.NumericUtilities;

/**
 * Test the FixOffcutInstructionScript.
 */
public class FixOffcutInstructionScriptTest extends AbstractGhidraHeadedIntegrationTest {

	private TestEnv env;
	private PluginTool tool;
	private Program program;
	private ProgramBuilder programBuilder;
	private CodeBrowserPlugin cb;
	private File script;
	private Address offcutInstructionAddress;

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		program = buildProgram();
		tool = env.launchDefaultTool(program);
		cb = env.getPlugin(CodeBrowserPlugin.class);

		script = Application.getModuleFile("Base", "ghidra_scripts/FixOffcutInstructionScript.java")
				.getFile(true);

		offcutInstructionAddress = addr("1001cea");
	}

	private Program buildProgram() throws Exception {
		programBuilder = new ProgramBuilder("Test", ProgramBuilder._X64);
		programBuilder.createMemory(".text", "0x1001000", 0x4000);

		programBuilder.setBytes("1001cd8", "48 8d 4a 01");
		programBuilder.setBytes("1001cdc", "48 89 d0");
		programBuilder.setBytes("1001cdf", "64 83 3c 25 18 00 00 00 00");
		// JZ with well formed reference into offcut instruction
		programBuilder.setBytes("1001ce8", "74 01");
		// LOCK CMPXCHG example offcut instruction
		programBuilder.setBytes("1001cea", "f0 48 0f b1 0d 75 65 15 00");
		programBuilder.setBytes("1001cf3", "48 39 d0");
		programBuilder.setBytes("1001cf6", "0f 84 bd 00 00 00");
		programBuilder.setBytes("1001cfc", "48 8b 15 65 65 15 00");
		programBuilder.disassemble("1001cd8", 0x100, false);
		return programBuilder.getProgram();
	}

	@After
	public void tearDown() throws Exception {
		env.dispose();
	}

	@Test
	public void testFixOffcutInsruction() throws Exception {
		makeSelection(tool, program, program.getMinAddress(), program.getMaxAddress());
		ScriptTaskListener scriptID = env.runScript(script);
		waitForScript(scriptID);

		assertInstruction(offcutInstructionAddress, 1, "f0", "CMPXCHG.LOCK");
		assertInstruction(offcutInstructionAddress.add(1), 8, "48 0f b1 0d 75 65 15 00", "CMPXCHG");
	}

	private Address addr(String address) {
		return program.getAddressFactory().getAddress(address);
	}

	private void waitForScript(ScriptTaskListener scriptID) {
		waitForScriptCompletion(scriptID, 100000);
		program.flushEvents();
		waitForBusyTool(tool);
	}

	private void assertInstruction(Address addr, int byteCount, String bytes, String mnemonic)
			throws MemoryAccessException {

		assertBytes(addr, byteCount, bytes);
		Instruction instructionAt = program.getListing().getInstructionAt(addr);
		assertEquals(byteCount, instructionAt.getLength());
		assertEquals(mnemonic, instructionAt.getMnemonicString());
	}

	private void assertBytes(Address addr, int count, String bytes) throws MemoryAccessException {

		byte[] x = new byte[count];
		program.getMemory().getBytes(addr, x);
		assertEquals(bytes, NumericUtilities.convertBytesToString(x, " "));
	}
}
