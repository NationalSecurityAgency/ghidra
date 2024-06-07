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

import static org.junit.Assert.*;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.util.Map;
import java.util.concurrent.*;

import org.apache.commons.lang3.exception.ExceptionUtils;
import org.junit.Before;
import org.junit.Test;

import generic.Unique;
import ghidra.app.plugin.core.debug.gui.AbstractGhidraHeadedDebuggerTest;
import ghidra.app.plugin.core.debug.gui.objects.components.InvocationDialogHelper;
import ghidra.app.plugin.core.debug.gui.tracermi.connection.tree.*;
import ghidra.app.plugin.core.debug.service.control.DebuggerControlServicePlugin;
import ghidra.app.plugin.core.debug.service.tracermi.TestTraceRmiClient;
import ghidra.app.plugin.core.debug.service.tracermi.TestTraceRmiClient.Tx;
import ghidra.app.plugin.core.debug.service.tracermi.TraceRmiPlugin;
import ghidra.app.services.DebuggerControlService;
import ghidra.app.services.TraceRmiService;
import ghidra.dbg.target.schema.SchemaContext;
import ghidra.dbg.target.schema.TargetObjectSchema.SchemaName;
import ghidra.dbg.target.schema.XmlSchemaContext;
import ghidra.debug.api.control.ControlMode;
import ghidra.debug.api.target.Target;
import ghidra.debug.api.tracermi.TraceRmiAcceptor;
import ghidra.debug.api.tracermi.TraceRmiConnection;
import ghidra.util.exception.CancelledException;

public class TraceRmiConnectionManagerProviderTest extends AbstractGhidraHeadedDebuggerTest {
	TraceRmiConnectionManagerProvider provider;
	TraceRmiService traceRmiService;
	DebuggerControlService controlService;

	@Before
	public void setUpConnectionManager() throws Exception {
		controlService = addPlugin(tool, DebuggerControlServicePlugin.class);
		traceRmiService = addPlugin(tool, TraceRmiPlugin.class);
		addPlugin(tool, TraceRmiConnectionManagerPlugin.class);
		provider = waitForComponentProvider(TraceRmiConnectionManagerProvider.class);
	}

	@Test
	public void testActionAccept() throws Exception {
		performEnabledAction(provider, provider.actionConnectAccept, false);
		InvocationDialogHelper helper = InvocationDialogHelper.waitFor();
		helper.dismissWithArguments(Map.ofEntries(
			Map.entry("address", "localhost"),
			Map.entry("port", 0)));
		waitForPass(() -> Unique.assertOne(traceRmiService.getAllAcceptors()));
	}

	@Test
	public void testActionConnect() throws Exception {
		try (ServerSocketChannel server = ServerSocketChannel.open()) {
			server.bind(new InetSocketAddress("localhost", 0), 1);
			if (!(server.getLocalAddress() instanceof InetSocketAddress sockaddr)) {
				throw new AssertionError();
			}
			performEnabledAction(provider, provider.actionConnectOutbound, false);
			InvocationDialogHelper helper = InvocationDialogHelper.waitFor();
			helper.dismissWithArguments(Map.ofEntries(
				Map.entry("address", sockaddr.getHostString()),
				Map.entry("port", sockaddr.getPort())));
			try (SocketChannel channel = server.accept()) {
				TestTraceRmiClient client = new TestTraceRmiClient(channel);
				client.sendNegotiate("Test client");
				client.recvNegotiate();
				waitForPass(() -> Unique.assertOne(traceRmiService.getAllConnections()));
			}
		}
	}

	@Test
	public void testActionStartServer() throws Exception {
		performEnabledAction(provider, provider.actionStartServer, false);
		InvocationDialogHelper helper = InvocationDialogHelper.waitFor();
		helper.dismissWithArguments(Map.ofEntries(
			Map.entry("address", "localhost"),
			Map.entry("port", 0)));
		waitForPass(() -> assertTrue(traceRmiService.isServerStarted()));
		waitForPass(() -> assertFalse(provider.actionStartServer.isEnabled()));

		traceRmiService.stopServer();
		waitForPass(() -> assertTrue(provider.actionStartServer.isEnabled()));
	}

	@Test
	public void testActionStopServer() throws Exception {
		waitForPass(() -> assertFalse(provider.actionStopServer.isEnabled()));
		traceRmiService.startServer();
		waitForSwing();
		performEnabledAction(provider, provider.actionStopServer, true);
		assertFalse(traceRmiService.isServerStarted());

		waitForPass(() -> assertFalse(provider.actionStopServer.isEnabled()));
	}

	@Test
	public void testActionCloseOnAcceptor() throws Exception {
		TraceRmiAcceptor acceptor =
			traceRmiService.acceptOne(new InetSocketAddress("localhost", 0));
		TraceRmiAcceptorNode node =
			TraceRmiConnectionTreeHelper.getAcceptorNodeMap(provider.rootNode).get(acceptor);
		assertNotNull(node);
		provider.tree.setSelectedNode(node);
		// Tree uses a task queue for selection requests
		waitForPass(() -> assertEquals(node, Unique.assertOne(provider.tree.getSelectedNodes())));

		performEnabledAction(provider, provider.actionCloseConnection, true);
		try {
			acceptor.accept();
			fail();
		}
		catch (CancelledException e) {
			// pass
		}
	}

	@Test
	public void testActionCloseOnConnection() throws Exception {
		try (Cx cx = Cx.connect(traceRmiService, "Test client")) {
			TraceRmiConnectionNode node =
				TraceRmiConnectionTreeHelper.getConnectionNodeMap(provider.rootNode)
						.get(cx.connection);
			assertNotNull(node);
			provider.tree.setSelectedNode(node);
			// Tree uses a task queue for selection requests
			waitForPass(
				() -> assertEquals(node, Unique.assertOne(provider.tree.getSelectedNodes())));

			performEnabledAction(provider, provider.actionCloseConnection, true);
			waitForPass(() -> assertTrue(cx.connection.isClosed()));
		}
	}

	@Test
	public void testActionCloseAll() throws Exception {
		traceRmiService.startServer();
		TraceRmiAcceptor acceptor =
			traceRmiService.acceptOne(new InetSocketAddress("localhost", 0));
		try (Cx cx = Cx.connect(traceRmiService, "Test client")) {
			performEnabledAction(provider, provider.actionCloseAll, true);

			waitForPass(() -> assertFalse(traceRmiService.isServerStarted()));
			waitForPass(() -> assertTrue(cx.connection.isClosed()));
			try {
				acceptor.accept();
				fail();
			}
			catch (CancelledException e) {
				// pass
			}
		}
	}

	@Test
	public void testServerNode() throws Exception {
		TraceRmiServerNode node = TraceRmiConnectionTreeHelper.getServerNode(provider.rootNode);
		assertEquals("Server: CLOSED", node.getDisplayText());
		traceRmiService.startServer();
		waitForPass(() -> assertEquals("Server: LISTENING " + traceRmiService.getServerAddress(),
			node.getDisplayText()));
		traceRmiService.stopServer();
		waitForPass(() -> assertEquals("Server: CLOSED", node.getDisplayText()));
	}

	@Test
	public void testAcceptHasNode() throws Exception {
		TraceRmiAcceptor acceptor =
			traceRmiService.acceptOne(new InetSocketAddress("localhost", 0));
		TraceRmiAcceptorNode node =
			TraceRmiConnectionTreeHelper.getAcceptorNodeMap(provider.rootNode).get(acceptor);
		assertNotNull(node);
		assertEquals("ACCEPTING: " + acceptor.getAddress(), node.getDisplayText());
	}

	@Test
	public void testAcceptThenCancelNoNode() throws Exception {
		TraceRmiAcceptor acceptor =
			traceRmiService.acceptOne(new InetSocketAddress("localhost", 0));
		assertNotNull(
			TraceRmiConnectionTreeHelper.getAcceptorNodeMap(provider.rootNode).get(acceptor));

		acceptor.cancel();
		waitForPass(() -> traceRmiService.getAllAcceptors().isEmpty());
		assertNull(
			TraceRmiConnectionTreeHelper.getAcceptorNodeMap(provider.rootNode).get(acceptor));
	}

	public record Cx(SocketChannel channel, TestTraceRmiClient client,
			TraceRmiConnection connection)
			implements AutoCloseable {
		public static Cx complete(TraceRmiAcceptor acceptor, String description)
				throws IOException, CancelledException {
			SocketChannel channel = null;
			TraceRmiConnection connection = null;
			try {
				channel = SocketChannel.open(acceptor.getAddress());
				TestTraceRmiClient client = new TestTraceRmiClient(channel);
				client.sendNegotiate(description);
				connection = acceptor.accept();
				client.recvNegotiate();
				return new Cx(channel, client, connection);
			}
			catch (Throwable t) {
				if (channel != null) {
					channel.close();
				}
				if (connection != null) {
					connection.close();
				}
				throw t;
			}
		}

		public static Cx toServer(TraceRmiService service, String description) throws IOException {
			SocketChannel channel = null;
			try {
				channel = SocketChannel.open(service.getServerAddress());
				TestTraceRmiClient client = new TestTraceRmiClient(channel);
				client.sendNegotiate(description);
				client.recvNegotiate();
				return new Cx(channel, client,
					waitForPass(() -> Unique.assertOne(service.getAllConnections())));
			}
			catch (Throwable t) {
				if (channel != null) {
					channel.close();
				}
				throw t;
			}
		}

		public static Cx connect(TraceRmiService service, String description)
				throws IOException, InterruptedException, ExecutionException, TimeoutException {
			SocketChannel channel = null;
			CompletableFuture<TraceRmiConnection> future = null;
			try (ServerSocketChannel server = ServerSocketChannel.open()) {
				server.bind(new InetSocketAddress("localhost", 0), 1);
				future = CompletableFuture.supplyAsync(() -> {
					try {
						return service.connect(server.getLocalAddress());
					}
					catch (IOException e) {
						return ExceptionUtils.rethrow(e);
					}
				});
				channel = server.accept();
				TestTraceRmiClient client = new TestTraceRmiClient(channel);
				client.sendNegotiate(description);
				client.recvNegotiate();
				return new Cx(channel, client, future.get(1, TimeUnit.SECONDS));
			}
			catch (Throwable t) {
				if (channel != null) {
					channel.close();
				}
				throw t;
			}
		}

		@Override
		public void close() throws Exception {
			connection.close();
			channel.close();
		}
	}

	@Test
	public void testAcceptThenSuccessNodes() throws Exception {
		TraceRmiAcceptor acceptor =
			traceRmiService.acceptOne(new InetSocketAddress("localhost", 0));
		assertNotNull(
			TraceRmiConnectionTreeHelper.getAcceptorNodeMap(provider.rootNode).get(acceptor));

		try (Cx cx = Cx.complete(acceptor, "Test client")) {
			waitForPass(() -> traceRmiService.getAllAcceptors().isEmpty());
			waitForPass(() -> assertNull(
				TraceRmiConnectionTreeHelper.getAcceptorNodeMap(provider.rootNode)
						.get(acceptor)));
			waitForPass(() -> assertEquals(cx.connection,
				Unique.assertOne(traceRmiService.getAllConnections())));

			TraceRmiConnectionNode node =
				TraceRmiConnectionTreeHelper.getConnectionNodeMap(provider.rootNode)
						.get(cx.connection);
			assertNotNull(node);
			assertEquals("Test client at " + cx.connection.getRemoteAddress(),
				node.getDisplayText());
		}
	}

	@Test
	public void testServerConnectNode() throws Exception {
		traceRmiService.startServer();
		try (Cx cx = Cx.toServer(traceRmiService, "Test client")) {
			waitForPass(() -> traceRmiService.getAllAcceptors().isEmpty());

			TraceRmiConnectionNode node = waitForValue(
				() -> TraceRmiConnectionTreeHelper.getConnectionNodeMap(provider.rootNode)
						.get(cx.connection));
			assertEquals("Test client at " + cx.connection.getRemoteAddress(),
				node.getDisplayText());
		}
	}

	@Test
	public void testConnectThenSuccessNodes() throws Exception {
		try (Cx cx = Cx.connect(traceRmiService, "Test client")) {
			waitForPass(() -> assertEquals(cx.connection,
				Unique.assertOne(traceRmiService.getAllConnections())));

			TraceRmiConnectionNode node =
				TraceRmiConnectionTreeHelper.getConnectionNodeMap(provider.rootNode)
						.get(cx.connection);
			assertNotNull(node);
			assertEquals("Test client at " + cx.connection.getRemoteAddress(),
				node.getDisplayText());
		}
	}

	@Test
	public void testFrontEndCloseNoNodes() throws Exception {
		TraceRmiAcceptor acceptor =
			traceRmiService.acceptOne(new InetSocketAddress("localhost", 0));
		try (Cx cx = Cx.complete(acceptor, "Test client")) {
			assertNotNull(TraceRmiConnectionTreeHelper.getConnectionNodeMap(provider.rootNode)
					.get(cx.connection));

			cx.connection.close();
			waitForPass(() -> assertTrue(traceRmiService.getAllConnections().isEmpty()));
			waitForPass(() -> assertNull(
				TraceRmiConnectionTreeHelper.getConnectionNodeMap(provider.rootNode)
						.get(cx.connection)));
		}
	}

	@Test
	public void testBackEndCloseNoNodes() throws Exception {
		TraceRmiAcceptor acceptor =
			traceRmiService.acceptOne(new InetSocketAddress("localhost", 0));
		try (Cx cx = Cx.complete(acceptor, "Test client")) {
			assertNotNull(TraceRmiConnectionTreeHelper.getConnectionNodeMap(provider.rootNode)
					.get(cx.connection));

			cx.channel.close();
			waitForPass(() -> assertTrue(traceRmiService.getAllConnections().isEmpty()));
			waitForPass(() -> assertNull(
				TraceRmiConnectionTreeHelper.getConnectionNodeMap(provider.rootNode)
						.get(cx.connection)));
		}
	}

	@Test
	public void testActivateTargetNode() throws Exception {
		SchemaContext ctx = XmlSchemaContext.deserialize("""
				<context>
				  <schema name="Root" elementResync="NEVER" attributeResync="NEVER" />
				</context>
				""");
		try (Cx cx = Cx.connect(traceRmiService, "Test client")) {
			cx.client.createTrace(1, "bash");
			try (Tx tx = cx.client.new Tx(1, 1, "Create snapshots")) {
				cx.client.snapshot(1, 0, "First snapshot");
				cx.client.createRootObject(1, ctx.getSchema(new SchemaName("Root")));
				cx.client.snapshot(1, 1, "Stepped");
			}
			cx.client.activate(1, "");
			Target target = waitForValue(() -> traceManager.getCurrent().getTarget());

			TraceRmiTargetNode node =
				TraceRmiConnectionTreeHelper.getTargetNodeMap(provider.rootNode).get(target);
			assertEquals("bash (snap=1)", node.getDisplayText());

			provider.tree.setSelectedNode(node);
			// Tree uses a task queue for selection requests
			waitForPass(
				() -> assertEquals(node, Unique.assertOne(provider.tree.getSelectedNodes())));

			controlService.setCurrentMode(target.getTrace(), ControlMode.RO_TRACE);
			waitForSwing();
			traceManager.activateSnap(0);
			waitForPass(() -> {
				assertEquals(0, traceManager.getCurrentSnap());
				assertEquals(ControlMode.RO_TRACE,
					controlService.getCurrentMode(target.getTrace()));
			});

			triggerEnter(provider.tree);
			waitForPass(() -> {
				assertEquals(1, traceManager.getCurrentSnap());
				assertEquals(ControlMode.RO_TARGET,
					controlService.getCurrentMode(target.getTrace()));
			});
		}
	}
}
