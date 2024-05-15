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
package ghidra.app.plugin.core.debug.gui.tracermi.connection;

import java.net.InetSocketAddress;

import org.junit.Test;

import ghidra.app.plugin.core.debug.gui.objects.components.DebuggerMethodInvocationDialog;
import ghidra.app.plugin.core.debug.gui.tracermi.connection.TraceRmiConnectionManagerProviderTest.Cx;
import ghidra.app.plugin.core.debug.gui.tracermi.connection.tree.TraceRmiConnectionNode;
import ghidra.app.plugin.core.debug.gui.tracermi.connection.tree.TraceRmiConnectionTreeHelper;
import ghidra.app.plugin.core.debug.service.tracermi.DefaultTraceRmiAcceptor;
import ghidra.app.plugin.core.debug.service.tracermi.TraceRmiPlugin;
import help.screenshot.GhidraScreenShotGenerator;

public class TraceRmiConnectionManagerPluginScreenShots extends GhidraScreenShotGenerator {
	private TraceRmiPlugin servicePlugin;
	private TraceRmiConnectionManagerPlugin managerPlugin;

	@Test
	public void testCaptureTraceRmiConnectionManagerPlugin() throws Throwable {
		servicePlugin = addPlugin(tool, TraceRmiPlugin.class);
		managerPlugin = addPlugin(tool, TraceRmiConnectionManagerPlugin.class);

		TraceRmiConnectionManagerProvider provider =
			waitForComponentProvider(TraceRmiConnectionManagerProvider.class);

		servicePlugin.startServer();
		DefaultTraceRmiAcceptor acceptor =
			servicePlugin.acceptOne(new InetSocketAddress("localhost", 0));
		DefaultTraceRmiAcceptor forCx =
			servicePlugin.acceptOne(new InetSocketAddress("localhost", 0));
		try (Cx cx = Cx.complete(forCx, "demo-dbg")) {
			cx.client().createTrace(0, "bash");

			TraceRmiConnectionNode node =
				TraceRmiConnectionTreeHelper.getConnectionNodeMap(provider.rootNode)
						.get(cx.connection());
			provider.tree.expandTree(node);
			waitForTasks();

			captureIsolatedProvider(provider, 400, 300);
		}
		finally {
			acceptor.cancel();
		}
	}

	@Test
	public void testCaptureConnectDialog() throws Throwable {
		servicePlugin = addPlugin(tool, TraceRmiPlugin.class);
		managerPlugin = addPlugin(tool, TraceRmiConnectionManagerPlugin.class);

		TraceRmiConnectionManagerProvider provider =
			waitForComponentProvider(TraceRmiConnectionManagerProvider.class);

		performAction(provider.actionConnectOutbound, provider, false);

		captureDialog(DebuggerMethodInvocationDialog.class);
	}
}
