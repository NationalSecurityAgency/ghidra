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

import ghidra.debug.api.tracermi.TraceRmiServiceListener.ConnectMode;
import ghidra.util.Msg;

public class TraceRmiServer extends AbstractTraceRmiListener {
	public TraceRmiServer(TraceRmiPlugin plugin, SocketAddress address) {
		super(plugin, address);
	}

	@Override
	protected void bind() throws IOException {
		socket.bind(address);
	}

	@Override
	protected void startServiceLoop() {
		new Thread(this::serviceLoop, "trace-rmi server " + socket.getLocalSocketAddress()).start();
	}

	@Override
	protected ConnectMode getConnectMode() {
		return ConnectMode.SERVER;
	}

	@SuppressWarnings("resource")
	protected void serviceLoop() {
		try {
			doAccept(null);
		}
		catch (IOException e) {
			if (socket.isClosed()) {
				return;
			}
			Msg.error("Error accepting TraceRmi client", e);
			return;
		}
		finally {
			try {
				socket.close();
			}
			catch (IOException e) {
				Msg.error("Error closing TraceRmi service", e);
			}
		}
	}
}
