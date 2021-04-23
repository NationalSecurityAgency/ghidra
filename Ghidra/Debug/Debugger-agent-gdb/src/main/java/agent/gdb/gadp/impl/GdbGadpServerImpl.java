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
package agent.gdb.gadp.impl;

import java.io.IOException;
import java.net.SocketAddress;
import java.util.concurrent.CompletableFuture;

import agent.gdb.gadp.GdbGadpServer;
import agent.gdb.model.impl.GdbModelImpl;
import agent.gdb.pty.linux.LinuxPtyFactory;
import ghidra.dbg.gadp.server.AbstractGadpServer;

public class GdbGadpServerImpl implements GdbGadpServer {
	public class GadpSide extends AbstractGadpServer {
		public GadpSide(GdbModelImpl model, SocketAddress addr) throws IOException {
			super(model, addr);
		}
	}

	protected final GdbModelImpl model;
	protected final GadpSide server;

	public GdbGadpServerImpl(SocketAddress addr) throws IOException {
		super();
		// TODO: Select Linux or Windows factory based on host OS
		this.model = new GdbModelImpl(new LinuxPtyFactory());
		this.server = new GadpSide(model, addr);
	}

	@Override
	public CompletableFuture<Void> startGDB(String gdbCmd, String[] args) {
		return model.startGDB(gdbCmd, args).thenCompose(__ -> server.launchAsyncService());
	}

	@Override
	public SocketAddress getLocalAddress() {
		return server.getLocalAddress();
	}

	@Override
	public void consoleLoop() throws IOException {
		model.consoleLoop();
	}

	@Override
	public void terminate() throws IOException {
		model.terminate();
		server.terminate();
	}

	@Override
	public void setExitOnClosed(boolean exitOnClosed) {
		server.setExitOnClosed(exitOnClosed);
	}
}
