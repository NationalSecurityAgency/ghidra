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

import javax.swing.JDialog;
import javax.swing.JTextField;

import org.junit.*;

import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.events.ProgramSelectionPluginEvent;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.services.ProgramManager;
import ghidra.framework.Application;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;
import ghidra.program.util.ProgramSelection;
import ghidra.test.*;

/**
 * Test the AutoRenameLabelsPlugin. 
 */
public class AutoRenameLabelsScriptTest extends AbstractGhidraHeadedIntegrationTest {

	private TestEnv env;
	private PluginTool tool;
	private Program program;
	private File script;

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		tool = env.getTool();
		tool.addPlugin(CodeBrowserPlugin.class.getName());

		program = buildProgram();
		ProgramManager pm = tool.getService(ProgramManager.class);
		pm.openProgram(program.getDomainFile());

		env.showTool();
		script =
			Application.getModuleFile("Base", "ghidra_scripts/AutoRenameLabelsScript.java").getFile(
				true);

		env.showTool();
	}

	private Program buildProgram() throws Exception {
		//Default Tree
		ToyProgramBuilder builder = new ToyProgramBuilder("Test", true, this);
		builder.createMemory(".text", "0x1001000", 0x4000);

		program = builder.getProgram();

		builder.addBytesBranch(0x01003a90, 0x01003a94);
		builder.addBytesBranch(0x01003a92, 0x01003a97);
		builder.addBytesNOP(0x01003a94, 0x10);
		builder.disassemble("0x01003a90", 0x14, true);
		builder.disassemble("0x01003a92", 0x14, true);

		builder.addBytesBranch(0x010046c0, 0x010046cc);
		builder.addBytesFallthrough(0x010046cc);
		builder.addBytesReturn(0x010046ce);
		builder.addBytesNOP(0x010046d0, 0x10);
		builder.disassemble("0x010046c0", 0x10, true);
		builder.disassemble("0x010046cc", 0x10, true);
		builder.disassemble("0x010046d0", 0x10, true);

		return builder.getProgram();
	}

	/*
	 * @see TestCase#tearDown()
	 */
	@After
	public void tearDown() throws Exception {
		env.release(program);
		env.dispose();
	}

	@Test
	public void testRename() throws Exception {
		SymbolTable symbolTable = program.getSymbolTable();
		Symbol s1 = symbolTable.getPrimarySymbol(addr(0x01003a94));
		assertNotNull(s1);
		assertTrue(s1.getSource() == SourceType.DEFAULT);

		Symbol s2 = symbolTable.getPrimarySymbol(addr(0x01003a97));
		assertNotNull(s2);
		assertTrue(s2.getSource() == SourceType.DEFAULT);

		ProgramSelection sel = new ProgramSelection(addr(0x01003a94), addr(0x01003a9b));
		tool.firePluginEvent(new ProgramSelectionPluginEvent("test", sel, program));
		waitForPostedSwingRunnables();

		ScriptTaskListener scriptID = env.runScript(script);

		JDialog dialog = waitForJDialog(tool.getToolFrame(), "Auto Rename Labels", 2000);
		final JTextField tf = findComponent(dialog, JTextField.class);
		runSwing(() -> tf.setText("My_Label"));
		pressButtonByText(dialog, "OK");
		waitForScriptCompletion(scriptID, 100000);

		program.flushEvents();
		waitForPostedSwingRunnables();

		s1 = symbolTable.getPrimarySymbol(addr(0x01003a94));
		s2 = symbolTable.getPrimarySymbol(addr(0x01003a97));

		assertEquals("My_Label1", s1.getName());
		assertEquals("My_Label2", s2.getName());
	}

	@Test
	public void testNoRenameOnUserDefined() throws Exception {
		SymbolTable symbolTable = program.getSymbolTable();
		Symbol s1 = symbolTable.getPrimarySymbol(addr(0x010046cc));
		assertTrue(s1.getSource() == SourceType.DEFAULT);

		// create a function at 10046d0 so we don't have a default label
		CreateFunctionCmd cmd =
			new CreateFunctionCmd("My_Function1", addr(0x010046d0), null, SourceType.ANALYSIS);
		tool.execute(cmd, program);
		program.flushEvents();
		waitForPostedSwingRunnables();

		Symbol s2 = symbolTable.getPrimarySymbol(addr(0x010046d0));
		assertNotNull(s2);
		assertTrue(s2.getSource() != SourceType.DEFAULT);
		String s2Name = s2.getName();

		ProgramSelection sel = new ProgramSelection(addr(0x010046cc), addr(0x010046d0));
		tool.firePluginEvent(new ProgramSelectionPluginEvent("test", sel, program));
		waitForPostedSwingRunnables();

		ScriptTaskListener scriptID = env.runScript(script);

		JDialog dialog = waitForJDialog(tool.getToolFrame(), "Auto Rename Labels", 2000);
		final JTextField tf = findComponent(dialog, JTextField.class);
		runSwing(() -> tf.setText("My_Label"));
		pressButtonByText(dialog, "OK");
		waitForScriptCompletion(scriptID, 100000);

		program.flushEvents();
		waitForPostedSwingRunnables();
		s1 = symbolTable.getPrimarySymbol(addr(0x010046cc));
		assertEquals("My_Label1", s1.getName());
		// only dynamic label should get renamed
		s2 = symbolTable.getPrimarySymbol(addr(0x010046d0));
		assertTrue(!s2.getName().equals("My_Label2"));
		assertEquals(s2Name, s2.getName());
	}

	private Address addr(long offset) {
		return program.getMinAddress().getNewAddress(offset);
	}
}
