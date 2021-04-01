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
package agent.dbgeng.model;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.channels.AsynchronousSocketChannel;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import org.junit.Test;

import agent.dbgeng.gadp.DbgEngGadpServer;
import ghidra.async.AsyncUtils;
import ghidra.async.TypeSpec;
import ghidra.dbg.DebuggerObjectModel;
import ghidra.dbg.gadp.client.GadpClient;
import ghidra.dbg.gadp.client.GadpClientTestHelper;
import ghidra.dbg.gadp.protocol.Gadp;
import ghidra.util.Msg;

public class GadpForDbgTest extends AbstractModelForDbgTest {

	static class DbgGadpModelHost implements ModelHost {
		final DbgEngGadpServer server;
		final SocketAddress addr;
		final AsynchronousSocketChannel socket;
		final GadpClient client;

		DbgGadpModelHost() throws Exception {
			server = DbgEngGadpServer.newInstance(new InetSocketAddress("localhost", 0));
			server.startDbgEng(new String[] {})
					.get(TIMEOUT_MILLISECONDS, TimeUnit.MILLISECONDS);
			addr = server.getLocalAddress();

			socket = AsynchronousSocketChannel.open();
			client = new GadpClient("Test", socket);
		}

		@Override
		public CompletableFuture<Void> init() {
			return AsyncUtils.sequence(TypeSpec.VOID).then(seq -> {
				Msg.debug(this, "Connecting...");
				AsyncUtils.completable(TypeSpec.VOID, socket::connect, addr).handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Negotiating...");
				client.connect().handle(seq::next);
			}).finish();
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
	protected DbgGadpModelHost modelHost() throws Exception {
		return new DbgGadpModelHost();
	}

	@Test
	public void testBadRequest() throws Throwable {
		try (DbgGadpModelHost m = modelHost()) {
			waitOn(AsyncUtils.sequence(TypeSpec.VOID).then(seq -> {
				m.init().handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Sending bogus message...");
				GadpClientTestHelper.sendChecked(m.client, Gadp.ErrorRequest.newBuilder(), null)
						.handle(seq::nextIgnore);
			}).finish());
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
		try (DbgGadpModelHost m = modelHost()) {
			waitOn(AsyncUtils.sequence(TypeSpec.VOID).then(seq -> {
				m.init().handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Pinging...");
				m.client.ping("Hello, Ghidra Async Debugging!").handle(seq::next);
			}).finish());
		}
	}
}
