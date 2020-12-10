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
package agent.dbgeng.gadp.impl;

import java.io.IOException;
import java.net.SocketAddress;
import java.util.concurrent.CompletableFuture;

import agent.dbgeng.gadp.DbgEngGadpServer;
import agent.dbgeng.model.AbstractDbgModel;
import agent.dbgeng.model.impl.DbgModelImpl;
import ghidra.dbg.gadp.server.AbstractGadpServer;

public class DbgEngGadpServerImpl implements DbgEngGadpServer {
	public class GadpSide extends AbstractGadpServer {
		public GadpSide(AbstractDbgModel model, SocketAddress addr)
				throws IOException {
			super(model, addr);
		}
	}

	protected final AbstractDbgModel model;
	protected final GadpSide server;

	public DbgEngGadpServerImpl(SocketAddress addr) throws IOException {
		super();
		this.model = new DbgModelImpl();
		this.server = new GadpSide(model, addr);
	}

	@Override
	public CompletableFuture<Void> startDbgEng(String[] args) {
		return model.startDbgEng(args).thenCompose(__ -> server.launchAsyncService());
	}

	@Override
	public SocketAddress getLocalAddress() {
		return server.getLocalAddress();
	}

	@Override
	public boolean isRunning() {
		return model.isRunning();
	}

	@Override
	public void terminate() throws IOException {
		model.terminate();
		server.terminate();
	}
}
