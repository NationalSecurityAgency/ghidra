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

import java.util.List;
import java.util.Objects;

import javax.swing.JTextField;

import org.junit.*;

import ghidra.app.plugin.assembler.Assembler;
import ghidra.app.plugin.assembler.Assemblers;
import ghidra.app.plugin.core.assembler.AssemblyDualTextField.AssemblyCompletion;
import ghidra.app.plugin.core.assembler.AssemblyDualTextField.AssemblyInstruction;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.codebrowser.CodeViewerProvider;
import ghidra.app.plugin.core.progmgr.ProgramManagerPlugin;
import ghidra.docking.settings.FormatSettingsDefinition;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramDB;
import ghidra.program.database.util.ProgramTransaction;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.ShortDataType;
import ghidra.program.model.data.TerminatedStringDataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.util.ProgramLocation;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.util.task.TaskMonitor;

public class AssemblerPluginTest extends AbstractGhidraHeadedIntegrationTest {
	protected TestEnv env;
	protected PluginTool tool;

	private ProgramManagerPlugin programManager;
	private AssemblerPlugin assemblerPlugin;

	private CodeViewerProvider codeViewer;

	private AssemblyDualTextField instructionInput;
	private JTextField dataInput;

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

		instructionInput = assemblerPlugin.patchInstructionAction.input;
		dataInput = assemblerPlugin.patchDataAction.input;

		program = createDefaultProgram(getName(), "Toy:BE:64:default", this);
		space = program.getAddressFactory().getDefaultAddressSpace();
		memory = program.getMemory();
		listing = program.getListing();

		try (ProgramTransaction trans = ProgramTransaction.open(program, "Setup")) {
			memory.createInitializedBlock(".text", space.getAddress(0x00400000), 0x1000, (byte) 0,
				TaskMonitor.DUMMY, false);
			trans.commit();
		}

		// Snuff the assembler's warning prompt
		assemblerPlugin.patchInstructionAction.shownWarning.put(program.getLanguage(), true);

		env.showTool();
		programManager.openProgram(program);
	}

	@After
	public void tearDownAssemblerPluginTest() {
		env.dispose();
	}

	protected void assertDualFields() {
		assertFalse(instructionInput.getAssemblyField().isVisible());
		assertTrue(instructionInput.getMnemonicField().isVisible());
		assertTrue(instructionInput.getOperandsField().isVisible());
	}

	protected List<AssemblyCompletion> inputAndGetCompletions(String text) {
		return runSwing(() -> {
			instructionInput.setText(text);
			instructionInput.auto.startCompletion(instructionInput.getOperandsField());
			instructionInput.auto.flushUpdates();
			return instructionInput.auto.getSuggestions();
		});
	}

	private void goTo(Address address) {
		runSwing(() -> codeViewer.goTo(program, new ProgramLocation(program, address)));
		waitForSwing();
	}

	@Test
	public void testActionPatchInstructionNoExisting() throws Exception {
		Address address = space.getAddress(0x00400000);
		goTo(address);

		performAction(assemblerPlugin.patchInstructionAction, codeViewer, true);
		assertDualFields();
		assertEquals("", instructionInput.getText());
		assertEquals(address, assemblerPlugin.patchInstructionAction.getAddress());

		List<AssemblyCompletion> completions = inputAndGetCompletions("imm r0, #1234");
		AssemblyCompletion first = completions.get(0);
		assertTrue(first instanceof AssemblyInstruction);
		AssemblyInstruction ai = (AssemblyInstruction) first;

		runSwing(() -> assemblerPlugin.patchInstructionAction.accept(ai));
		waitForProgram(program);

		Instruction ins = Objects.requireNonNull(listing.getInstructionAt(address));
		assertEquals("imm r0,#0x4d2", ins.toString());
	}

	@Test
	public void testActionPatchInstructionExisting() throws Exception {
		Address address = space.getAddress(0x00400000);
		Assembler asm = Assemblers.getAssembler(program);
		try (ProgramTransaction trans = ProgramTransaction.open(program, "Assemble pre-existing")) {
			asm.assemble(address, "imm r0,#0x4d2");
			trans.commit();
		}

		goTo(address);

		performAction(assemblerPlugin.patchInstructionAction, codeViewer, true);
		assertDualFields();
		assertEquals("imm r0,#0x4d2", instructionInput.getText());
		assertEquals(address, assemblerPlugin.patchInstructionAction.getAddress());

		List<AssemblyCompletion> completions = inputAndGetCompletions("imm r0, #123");
		AssemblyCompletion first = completions.get(0);
		assertTrue(first instanceof AssemblyInstruction);
		AssemblyInstruction ai = (AssemblyInstruction) first;

		runSwing(() -> assemblerPlugin.patchInstructionAction.accept(ai));
		waitForProgram(program);

		Instruction ins = Objects.requireNonNull(listing.getInstructionAt(address));
		assertEquals("imm r0,#0x7b", ins.toString());
	}

	// TODO: Test disabled on uninitialized memory
	// TODO: Test disabled on read-only listings

	protected Data doPatchAt(Address address, String expText, String newText) {
		goTo(address);

		performAction(assemblerPlugin.patchDataAction, codeViewer, true);
		assertTrue(dataInput.isVisible());
		assertEquals(expText, dataInput.getText());
		assertEquals(address, assemblerPlugin.patchDataAction.getAddress());

		runSwing(() -> {
			dataInput.setText(newText);
			assemblerPlugin.patchDataAction.accept();
		});
		waitForProgram(program);

		return Objects.requireNonNull(listing.getDataAt(address));
	}

	@Test
	public void testActionPatchDataShortHexValid() throws Exception {
		Address address = space.getAddress(0x00400000);
		try (ProgramTransaction trans = ProgramTransaction.open(program, "Place short")) {
			listing.createData(address, ShortDataType.dataType);
			trans.commit();
		}

		Data data = doPatchAt(address, "0h", "1234h");
		assertEquals("1234h", data.getDefaultValueRepresentation());
	}

	@Test
	public void testActionPatchDataShortDecValid() throws Exception {
		Address address = space.getAddress(0x00400000);
		try (ProgramTransaction trans = ProgramTransaction.open(program, "Place short")) {
			Data data = listing.createData(address, ShortDataType.dataType);
			FormatSettingsDefinition.DEF.setChoice(data, FormatSettingsDefinition.DECIMAL);
			trans.commit();
		}

		Data data = doPatchAt(address, "0", "1234");
		assertEquals("1234", data.getDefaultValueRepresentation());
	}

	@Test
	public void testActionPatchDataUTF8StringSameLength() throws Exception {
		Address address = space.getAddress(0x00400000);
		try (ProgramTransaction trans = ProgramTransaction.open(program, "Place string")) {
			memory.setBytes(address, "Hello, World!\0".getBytes("utf-8"));
			listing.createData(address, TerminatedStringDataType.dataType);
			trans.commit();
		}

		Data data = doPatchAt(address, "\"Hello, World!\"", "\"Hello, Patch!\"");
		assertEquals("\"Hello, Patch!\"", data.getDefaultValueRepresentation());
	}

	@Test
	public void testActionPatchDataUTF8StringShorter() throws Exception {
		Address address = space.getAddress(0x00400000);
		try (ProgramTransaction trans = ProgramTransaction.open(program, "Place string")) {
			memory.setBytes(address, "Hello, World!\0".getBytes("utf-8"));
			listing.createData(address, TerminatedStringDataType.dataType);
			trans.commit();
		}

		Data data = doPatchAt(address, "\"Hello, World!\"", "\"Hello!\"");
		assertEquals("\"Hello!\"", data.getDefaultValueRepresentation());
		assertEquals(7, data.getLength());
	}

	@Test
	public void testActionPatchDataUTF8StringLonger() throws Exception {
		Address address = space.getAddress(0x00400000);
		try (ProgramTransaction trans = ProgramTransaction.open(program, "Place string")) {
			memory.setBytes(address, "Hello, World!\0".getBytes("utf-8"));
			listing.createData(address, TerminatedStringDataType.dataType);
			trans.commit();
		}

		Data data = doPatchAt(address, "\"Hello, World!\"", "\"Hello to you, too!\"");
		assertEquals("\"Hello to you, too!\"", data.getDefaultValueRepresentation());
		assertEquals(19, data.getLength());
	}
}
