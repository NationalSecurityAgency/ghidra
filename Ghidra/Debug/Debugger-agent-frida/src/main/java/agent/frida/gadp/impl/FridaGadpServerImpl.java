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
package agent.frida.gadp.impl;

import java.io.IOException;
import java.net.SocketAddress;
import java.util.concurrent.CompletableFuture;

import agent.frida.gadp.FridaGadpServer;
import agent.frida.model.AbstractFridaModel;
import agent.frida.model.impl.FridaModelImpl;
import ghidra.dbg.gadp.server.AbstractGadpServer;

public class FridaGadpServerImpl implements FridaGadpServer {
	public class GadpSide extends AbstractGadpServer {
		public GadpSide(AbstractFridaModel model, SocketAddress addr)
				throws IOException {
			super(model, addr);
		}
	}

	protected final AbstractFridaModel model;
	protected final GadpSide server;

	public FridaGadpServerImpl(SocketAddress addr) throws IOException {
		super();
		this.model = new FridaModelImpl();
		this.server = new GadpSide(model, addr);
	}

	@Override
	public CompletableFuture<Void> startFrida(String[] args) {
		return model.startFrida(args).thenCompose(__ -> server.launchAsyncService());
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
