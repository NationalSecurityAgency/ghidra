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
package ghidra.app.plugin.core.debug.gui.console;

import static org.junit.Assert.assertEquals;

import org.junit.Before;
import org.junit.Test;

import docking.ActionContext;
import docking.action.builder.ActionBuilder;
import ghidra.app.plugin.core.debug.gui.AbstractGhidraHeadedDebuggerGUITest;
import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.util.Msg;

public class DebuggerConsoleProviderTest extends AbstractGhidraHeadedDebuggerGUITest {
	DebuggerConsolePlugin consolePlugin;
	DebuggerConsoleProvider consoleProvider;

	@Before
	public void setUpConsoleProviderTest() throws Exception {
		consolePlugin = addPlugin(tool, DebuggerConsolePlugin.class);
		consoleProvider = waitForComponentProvider(DebuggerConsoleProvider.class);
	}

	public static class TestConsoleActionContext extends ActionContext {

	}

	@Test
	public void testActions() throws Exception {
		consolePlugin.addResolutionAction(new ActionBuilder("Add", name.getMethodName())
				.toolBarIcon(DebuggerResources.ICON_ADD)
				.description("Add")
				.withContext(TestConsoleActionContext.class)
				.onAction(ctx -> Msg.info(this, "Add clicked"))
				.build());
		consolePlugin.addResolutionAction(new ActionBuilder("Delete", name.getMethodName())
				.popupMenuIcon(DebuggerResources.ICON_DELETE)
				.popupMenuPath("Delete")
				.description("Delete")
				.withContext(TestConsoleActionContext.class)
				.onAction(ctx -> Msg.info(this, "Delete clicked"))
				.build());

		consolePlugin.log(DebuggerResources.ICON_DEBUGGER, "<html><b>Test message</b></html>",
			new TestConsoleActionContext());
		consolePlugin.log(DebuggerResources.ICON_DEBUGGER, "Test message 2",
			new TestConsoleActionContext());

		waitForPass(() -> assertEquals(2, consoleProvider.logTable.getRowCount()));
	}

	@Test
	public void testHTMLLabel() throws Exception {
		consolePlugin.log(DebuggerResources.ICON_DEBUGGER,
			"<html><b>A rather lengthy test message. " +
				"Here's some more text just to prove it!</b></html>",
			new TestConsoleActionContext());
		consolePlugin.log(DebuggerResources.ICON_DEBUGGER, "Test message 2",
			new TestConsoleActionContext());

		waitForPass(() -> assertEquals(2, consoleProvider.logTable.getRowCount()));
	}
}
