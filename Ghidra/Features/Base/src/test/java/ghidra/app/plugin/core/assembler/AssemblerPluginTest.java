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
package ghidra.app.plugin.core.assembler;

import static org.junit.Assert.*;

import org.junit.*;

import db.Transaction;
import ghidra.app.plugin.assembler.Assembler;
import ghidra.app.plugin.assembler.Assemblers;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.codebrowser.CodeViewerProvider;
import ghidra.app.plugin.core.progmgr.ProgramManagerPlugin;
import ghidra.docking.settings.FormatSettingsDefinition;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.ShortDataType;
import ghidra.program.model.data.TerminatedStringDataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.util.task.TaskMonitor;

public class AssemblerPluginTest extends AbstractGhidraHeadedIntegrationTest {
	protected TestEnv env;
	protected PluginTool tool;

	private ProgramManagerPlugin programManager;
	private AssemblerPlugin assemblerPlugin;

	private CodeViewerProvider codeViewer;

	private AssemblerPluginTestHelper helper;

	private ProgramDB program;
	private AddressSpace space;
	private Memory memory;
	private Listing listing;

	@Before
	public void setUpAssemblerPluginTest() throws Exception {
		env = new TestEnv();
		tool = env.getTool();

		programManager = addPlugin(tool, ProgramManagerPlugin.class);
		addPlugin(tool, CodeBrowserPlugin.class);
		assemblerPlugin = addPlugin(tool, AssemblerPlugin.class);

		codeViewer = waitForComponentProvider(CodeViewerProvider.class);
		program = createDefaultProgram(getName(), "Toy:BE:64:default", this);

		space = program.getAddressFactory().getDefaultAddressSpace();
		memory = program.getMemory();
		listing = program.getListing();

		helper = new AssemblerPluginTestHelper(assemblerPlugin, codeViewer, program);

		try (Transaction tx = program.openTransaction("Setup")) {
			memory.createInitializedBlock(".text", space.getAddress(0x00400000), 0x1000, (byte) 0,
				TaskMonitor.DUMMY, false);
		}

		env.showTool();
		programManager.openProgram(program);
	}

	@After
	public void tearDownAssemblerPluginTest() {
		env.dispose();
	}

	@Test
	public void testActionPatchInstructionNoExisting() throws Exception {
		Address address = space.getAddress(0x00400000);
		Instruction ins = helper.patchInstructionAt(address, "", "imm r0, #911");
		assertEquals("imm r0,#0x38f", ins.toString());
	}

	@Test
	public void testActionPatchInstructionExisting() throws Exception {
		Address address = space.getAddress(0x00400000);
		Assembler asm = Assemblers.getAssembler(program);
		try (Transaction tx = program.openTransaction("Assemble pre-existing")) {
			asm.assemble(address, "imm r0,#0x3d2");
		}

		Instruction ins = helper.patchInstructionAt(address, "imm r0,#0x3d2", "imm r0, #123");
		assertEquals("imm r0,#0x7b", ins.toString());
	}

	// TODO: Test disabled on uninitialized memory
	// TODO: Test disabled on read-only listings

	@Test
	public void testActionPatchDataShortHexValid() throws Exception {
		Address address = space.getAddress(0x00400000);
		try (Transaction tx = program.openTransaction("Place short")) {
			listing.createData(address, ShortDataType.dataType);
		}

		Data data = helper.patchDataAt(address, "0h", "1234h");
		assertEquals("1234h", data.getDefaultValueRepresentation());
	}

	@Test
	public void testActionPatchDataShortDecValid() throws Exception {
		Address address = space.getAddress(0x00400000);
		try (Transaction tx = program.openTransaction("Place short")) {
			Data data = listing.createData(address, ShortDataType.dataType);
			FormatSettingsDefinition.DEF.setChoice(data, FormatSettingsDefinition.DECIMAL);
		}

		Data data = helper.patchDataAt(address, "0", "1234");
		assertEquals("1234", data.getDefaultValueRepresentation());
	}

	@Test
	public void testActionPatchDataUTF8StringSameLength() throws Exception {
		Address address = space.getAddress(0x00400000);
		try (Transaction tx = program.openTransaction("Place string")) {
			memory.setBytes(address, "Hello, World!\0".getBytes("utf-8"));
			listing.createData(address, TerminatedStringDataType.dataType);
		}

		Data data = helper.patchDataAt(address, "\"Hello, World!\"",
			"\"Hello, Patch!\"");
		assertEquals("\"Hello, Patch!\"", data.getDefaultValueRepresentation());
	}

	@Test
	public void testActionPatchDataUTF8StringShorter() throws Exception {
		Address address = space.getAddress(0x00400000);
		try (Transaction tx = program.openTransaction("Place string")) {
			memory.setBytes(address, "Hello, World!\0".getBytes("utf-8"));
			listing.createData(address, TerminatedStringDataType.dataType);
		}

		Data data =
			helper.patchDataAt(address, "\"Hello, World!\"", "\"Hello!\"");
		assertEquals("\"Hello!\"", data.getDefaultValueRepresentation());
		assertEquals(7, data.getLength());
	}

	@Test
	public void testActionPatchDataUTF8StringLonger() throws Exception {
		Address address = space.getAddress(0x00400000);
		try (Transaction tx = program.openTransaction("Place string")) {
			memory.setBytes(address, "Hello, World!\0".getBytes("utf-8"));
			listing.createData(address, TerminatedStringDataType.dataType);
		}

		Data data = helper.patchDataAt(address, "\"Hello, World!\"", "\"Hello to you, too!\"");
		assertEquals("\"Hello to you, too!\"", data.getDefaultValueRepresentation());
		assertEquals(19, data.getLength());
	}
}
