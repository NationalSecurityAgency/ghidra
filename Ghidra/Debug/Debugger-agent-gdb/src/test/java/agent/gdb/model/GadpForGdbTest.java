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
package agent.gdb.model;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.channels.AsynchronousSocketChannel;
import java.util.concurrent.CompletableFuture;

import org.junit.Test;

import agent.gdb.gadp.GdbGadpServer;
import agent.gdb.manager.GdbManager;
import ghidra.async.AsyncUtils;
import ghidra.async.TypeSpec;
import ghidra.dbg.DebuggerObjectModel;
import ghidra.dbg.gadp.client.GadpClient;
import ghidra.dbg.gadp.client.GadpClientTestHelper;
import ghidra.dbg.gadp.protocol.Gadp;
import ghidra.util.Msg;

public class GadpForGdbTest extends AbstractModelForGdbTest {

	class GdbGadpModelHost implements ModelHost {
		final GdbGadpServer server;
		final SocketAddress addr;
		final AsynchronousSocketChannel socket;
		final GadpClient client;

		GdbGadpModelHost(String gdbCmd) throws Exception {
			server = GdbGadpServer.newInstance(new InetSocketAddress("localhost", 0));
			server.startGDB(gdbCmd, new String[] {})
			/*.get(TIMEOUT_MILLISECONDS, TimeUnit.MILLISECONDS)*/;
			addr = server.getLocalAddress();

			socket = AsynchronousSocketChannel.open();
			client = new GadpClient("Test", socket);
		}

		@Override
		public CompletableFuture<Void> init() {
			Msg.debug(this, "Connecting...");
			return AsyncUtils.completable(TypeSpec.VOID, socket::connect, addr).thenCompose(__ -> {
				Msg.debug(this, "Negotiating...");
				return client.connect();
			});
		}

		@Override
		public DebuggerObjectModel getModel() {
			return client;
		}

		@Override
		public void close() throws Exception {
			// Not too eww
			Msg.debug(this, "Disconnecting...");
			try {
				waitOn(client.close());
			}
			catch (Exception e) {
				throw e;
			}
			catch (Throwable e) {
				throw new AssertionError(e);
			}
			server.terminate();
		}
	}

	@Override
	protected GdbGadpModelHost modelHost() throws Exception {
		return modelHost(GdbManager.DEFAULT_GDB_CMD);
	}

	@Override
	protected GdbGadpModelHost modelHost(String gdbCmd) throws Exception {
		return new GdbGadpModelHost(gdbCmd);
	}

	@Test
	public void testBadRequest() throws Throwable {
		try (GdbGadpModelHost m = modelHost()) {
			init(m);
			Msg.debug(this, "Sending bogus message...");
			waitOn(
				GadpClientTestHelper.sendChecked(m.client, Gadp.ErrorRequest.newBuilder(), null));
			fail("Exception expected");
		}
		catch (AssertionError e) {
			assertEquals(
				"Client implementation sent an invalid request: " +
					"BAD_REQUEST: Unrecognized request: ERROR_REQUEST",
				e.getMessage());
		}
	}

	@Test
	public void testPing() throws Throwable {
		try (GdbGadpModelHost m = modelHost()) {
			waitOn(m.init());
			Msg.debug(this, "Pinging...");
			waitOn(m.client.ping("Hello, Ghidra Async Debugging!"));
		}
	}
}
