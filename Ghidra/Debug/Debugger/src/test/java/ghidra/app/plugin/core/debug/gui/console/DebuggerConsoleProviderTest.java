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

import docking.DefaultActionContext;
import docking.action.builder.ActionBuilder;
import ghidra.app.plugin.core.debug.gui.AbstractGhidraHeadedDebuggerTest;
import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.app.plugin.core.debug.service.progress.ProgressServicePlugin;
import ghidra.app.services.ProgressService;
import ghidra.debug.api.progress.CloseableTaskMonitor;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

public class DebuggerConsoleProviderTest extends AbstractGhidraHeadedDebuggerTest {
	DebuggerConsolePlugin consolePlugin;
	DebuggerConsoleProvider consoleProvider;

	@Before
	public void setUpConsoleProviderTest() throws Exception {
		consolePlugin = addPlugin(tool, DebuggerConsolePlugin.class);
		consoleProvider = waitForComponentProvider(DebuggerConsoleProvider.class);
	}

	public static class TestConsoleActionContext extends DefaultActionContext {

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

	@Test
	public void testProgress() throws Exception {
		ProgressService progressService = addPlugin(tool, ProgressServicePlugin.class);
		try (CloseableTaskMonitor monitor1 = progressService.publishTask();
				CloseableTaskMonitor monitor2 = progressService.publishTask()) {
			monitor1.initialize(10, "Testing 1");
			monitor2.initialize(10, "Testing 2");
			for (int i = 0; i < 10; i++) {
				Thread.sleep(100);
				monitor1.increment();
				Thread.sleep(100);
				monitor2.increment();
			}
		}
	}

	@Test
	public void testRefTaskMonitor() throws Exception {
		tool.execute(new Task("Test") {
			@Override
			public void run(TaskMonitor monitor) throws CancelledException {
				monitor.initialize(10, "Testing");
				for (int i = 0; i < 10; i++) {
					try {
						Thread.sleep(100);
					}
					catch (InterruptedException e) {
						throw new AssertionError(e);
					}
					monitor.increment();
				}
			}
		});
		Thread.sleep(100);
	}
}
