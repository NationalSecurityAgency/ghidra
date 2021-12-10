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
package agent.lldb.gadp.impl;

import java.io.IOException;
import java.net.SocketAddress;
import java.util.concurrent.CompletableFuture;

import agent.lldb.gadp.LldbGadpServer;
import agent.lldb.model.AbstractLldbModel;
import agent.lldb.model.impl.LldbModelImpl;
import ghidra.dbg.gadp.server.AbstractGadpServer;

public class LldbGadpServerImpl implements LldbGadpServer {
	public class GadpSide extends AbstractGadpServer {
		public GadpSide(AbstractLldbModel model, SocketAddress addr)
				throws IOException {
			super(model, addr);
		}
	}

	protected final AbstractLldbModel model;
	protected final GadpSide server;

	public LldbGadpServerImpl(SocketAddress addr) throws IOException {
		super();
		this.model = new LldbModelImpl();
		this.server = new GadpSide(model, addr);
	}

	@Override
	public CompletableFuture<Void> startLLDB(String[] args) {
		return model.startLLDB(args).thenCompose(__ -> server.launchAsyncService());
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
