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
package ghidra.app.plugin.core.debug.gui.interpreters;

import static org.junit.Assert.*;

import java.awt.Robot;
import java.awt.event.KeyEvent;
import java.util.List;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;

import ghidra.app.plugin.core.debug.gui.AbstractGhidraHeadedDebuggerGUITest;
import ghidra.app.plugin.core.interpreter.InterpreterComponentProvider;
import ghidra.dbg.model.TestTargetInterpreter.ExecuteCall;
import ghidra.dbg.target.TargetConsole.Channel;
import ghidra.dbg.testutil.DebuggerModelTestUtils;

public class DebuggerInterpreterPluginTest extends AbstractGhidraHeadedDebuggerGUITest
		implements DebuggerModelTestUtils {
	private DebuggerInterpreterPlugin interpreterPlugin;

	@Before
	public void setUpInterpreterPluginTest() throws Exception {
		interpreterPlugin = addPlugin(tool, DebuggerInterpreterPlugin.class);
	}

	@Test
	public void testShowConsole() throws Exception {
		createTestModel();
		interpreterPlugin.showConsole(mb.testModel.session.interpreter);
		InterpreterComponentProvider interpreter =
			waitForComponentProvider(InterpreterComponentProvider.class);

		assertEquals("Test Debugger", interpreter.getSubTitle());
		assertTrue(interpreter.isVisible());
	}

	@Test
	public void testInputExecutes() throws Exception {
		createTestModel();
		interpreterPlugin.showConsole(mb.testModel.session.interpreter);
		InterpreterComponentProvider interpreter =
			waitForComponentProvider(InterpreterComponentProvider.class);

		interpreter.requestFocus();
		waitForSwing();

		// Can't get at the component, so send keystrokes?
		Robot robot = new Robot();
		ExecuteCall<Void> exe = waitForValue(() -> {
			robot.keyPress(KeyEvent.VK_A);
			robot.keyRelease(KeyEvent.VK_A);
			robot.keyPress(KeyEvent.VK_ENTER);
			robot.keyRelease(KeyEvent.VK_ENTER);
			waitForSwing();
			return mb.testModel.session.interpreter.pollExecute();
		});
		assertEquals("a", exe.cmd);
		exe.complete(null); // Not necessary, but cleaner
	}

	@Test
	public void testOutputDisplaysInConsole() throws Exception {
		createTestModel();
		interpreterPlugin.showConsole(mb.testModel.session.interpreter);
		InterpreterComponentProvider interpreter =
			waitForComponentProvider(InterpreterComponentProvider.class);

		mb.testModel.session.interpreter.output(Channel.STDOUT, "Hello, World!");
		waitForSwing();

		// I/O processing has a dedicated thread
		// FIXME: The trailing space is a hack to fix scrolling....
		waitForPass(() -> assertEquals("Hello, World!\n ", interpreter.getOutputText()));
	}

	@Test
	public void testPromptChangeUpdatesPrompt() throws Exception {
		createTestModel();
		interpreterPlugin.showConsole(mb.testModel.session.interpreter);
		InterpreterComponentProvider interpreter =
			waitForComponentProvider(InterpreterComponentProvider.class);

		mb.testModel.session.interpreter.setPrompt("DEBUG>>");
		waitForSwing();

		assertEquals("DEBUG>>", interpreter.getPrompt());
	}

	@Test
	public void testDisplayChangeUpdatesTitle() throws Throwable {
		createTestModel();
		interpreterPlugin.showConsole(mb.testModel.session.interpreter);
		InterpreterComponentProvider interpreter =
			waitForComponentProvider(InterpreterComponentProvider.class);

		mb.testModel.session.interpreter.setDisplay("Test Debugger X.0");
		waitOn(mb.testModel.flushEvents());
		waitForSwing();

		assertEquals("Test Debugger X.0", interpreter.getSubTitle());
	}

	@Test
	public void testInvalidateInterpreterDestroysConsole() throws Exception {
		createTestModel();
		interpreterPlugin.showConsole(mb.testModel.session.interpreter);
		InterpreterComponentProvider interpreter =
			waitForComponentProvider(InterpreterComponentProvider.class);

		mb.testModel.session.changeAttributes(List.of(
			"Interpreter" //
		), Map.of(), "Invalidate interpreter");
		waitForSwing();

		waitForPass(() -> assertFalse(interpreter.isVisible()));
		assertFalse(interpreter.isInTool());
	}

	@Test
	public void testInvalidatePinnedInterpreterDisablesConsole() throws Exception {
		createTestModel();
		DebuggerInterpreterConnection conn =
			interpreterPlugin.showConsole(mb.testModel.session.interpreter);
		InterpreterComponentProvider interpreter =
			waitForComponentProvider(InterpreterComponentProvider.class);
		conn.setPinned(true);

		mb.testModel.session.changeAttributes(List.of(
			"Interpreter" //
		), Map.of(), "Invalidate interpreter");
		waitForSwing();

		waitForPass(() -> assertFalse(interpreter.isInputPermitted()));
	}
}
