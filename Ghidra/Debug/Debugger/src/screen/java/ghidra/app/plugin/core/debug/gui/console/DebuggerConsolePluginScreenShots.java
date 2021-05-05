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

import org.junit.*;
import org.junit.rules.TestName;

import docking.ActionContext;
import docking.action.builder.ActionBuilder;
import ghidra.app.plugin.core.debug.gui.AbstractGhidraHeadedDebuggerGUITest;
import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.util.Msg;
import help.screenshot.GhidraScreenShotGenerator;

public class DebuggerConsolePluginScreenShots extends GhidraScreenShotGenerator {

	public static class ScreenShotActionContext extends ActionContext {
	}

	DebuggerConsolePlugin consolePlugin;
	DebuggerConsoleProvider consoleProvider;

	@Rule
	public TestName name = new TestName();

	@Before
	public void setUpMine() throws Throwable {
		consolePlugin = addPlugin(tool, DebuggerConsolePlugin.class);
		consoleProvider = waitForComponentProvider(DebuggerConsoleProvider.class);

		consolePlugin.addResolutionAction(new ActionBuilder("Import", name.getMethodName())
				.toolBarIcon(DebuggerResources.ICON_IMPORT)
				.popupMenuIcon(DebuggerResources.ICON_IMPORT)
				.popupMenuPath("Map")
				.description("Import")
				.withContext(ScreenShotActionContext.class)
				.onAction(ctx -> Msg.info(this, "Import clicked"))
				.build());
		consolePlugin.addResolutionAction(new ActionBuilder("Map", name.getMethodName())
				.toolBarIcon(DebuggerResources.ICON_MODULES)
				.popupMenuIcon(DebuggerResources.ICON_MODULES)
				.popupMenuPath("Map")
				.description("Map")
				.withContext(ScreenShotActionContext.class)
				.onAction(ctx -> Msg.info(this, "Map clicked"))
				.build());
	}

	@Test
	public void testCaptureDebuggerConsolePlugin() throws Throwable {
		Msg.warn(this, "This is a warning message");
		Msg.error(this, "This is an error message");
		consolePlugin.log(DebuggerResources.ICON_DEBUGGER,
			"<html>You can take <b>action</b> to resolve this message</html>",
			new ScreenShotActionContext());

		AbstractGhidraHeadedDebuggerGUITest
				.waitForPass(() -> assertEquals(3, consolePlugin.getRowCount(ActionContext.class)));

		captureIsolatedProvider(consoleProvider, 600, 300);
	}
}
