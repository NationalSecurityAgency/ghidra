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
package ghidra.app.plugin.core.debug.service.tracermi;

import java.io.IOException;
import java.net.SocketAddress;

import ghidra.debug.api.tracermi.TraceRmiAcceptor;
import ghidra.debug.api.tracermi.TraceRmiServiceListener.ConnectMode;
import ghidra.util.exception.CancelledException;

public class DefaultTraceRmiAcceptor extends AbstractTraceRmiListener implements TraceRmiAcceptor {
	private boolean cancelled = false;

	public DefaultTraceRmiAcceptor(TraceRmiPlugin plugin, SocketAddress address) {
		super(plugin, address);
	}

	@Override
	protected void startServiceLoop() {
		// Don't. Instead, client calls accept()
	}

	@Override
	protected void bind() throws IOException {
		socket.bind(address, 1);
		plugin.addAcceptor(this);
	}

	@Override
	protected ConnectMode getConnectMode() {
		return ConnectMode.ACCEPT_ONE;
	}

	@Override
	public TraceRmiHandler accept() throws IOException, CancelledException {
		try {
			TraceRmiHandler handler = doAccept(this);
			close();
			return handler;
		}
		catch (Exception e) {
			close();
			if (cancelled) {
				throw new CancelledException();
			}
			plugin.listeners.invoke().acceptFailed(this, e);
			throw e;
		}
	}

	@Override
	public boolean isClosed() {
		return socket.isClosed();
	}

	@Override
	public void close() {
		plugin.removeAcceptor(this);
		super.close();
	}

	@Override
	public void cancel() {
		cancelled = true;
		close();
		plugin.listeners.invoke().acceptCancelled(this);
	}
}
