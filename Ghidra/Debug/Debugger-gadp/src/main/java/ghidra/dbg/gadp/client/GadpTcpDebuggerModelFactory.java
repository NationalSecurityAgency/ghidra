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
package ghidra.dbg.gadp.client;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.channels.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executors;

import ghidra.async.AsyncUtils;
import ghidra.async.TypeSpec;
import ghidra.dbg.DebuggerModelFactory;
import ghidra.dbg.util.ConfigurableFactory.FactoryDescription;

@FactoryDescription( //
		brief = "GADP connection over TCP", //
		htmlDetails = "Connect to an optionally remote agent via GADP/TCP." //
)
public class GadpTcpDebuggerModelFactory implements DebuggerModelFactory {

	private String host = "localhost";
	@FactoryOption("Agent network address")
	public final Property<String> agentAddressOption =
		Property.fromAccessors(String.class, this::getAgentAddress, this::setAgentAddress);

	private int port = 15432;
	@FactoryOption("Agent TCP port")
	public final Property<Integer> agentPortOption =
		Property.fromAccessors(Integer.class, this::getAgentPort, this::setAgentPort);

	@Override
	public CompletableFuture<GadpClient> build() {
		try {
			// Note, it looks like the executor knows to shut itself down on GC
			AsynchronousChannelGroup group =
				AsynchronousChannelGroup.withThreadPool(Executors.newSingleThreadExecutor());
			AsynchronousSocketChannel channel = AsynchronousSocketChannel.open(group);
			CompletableFuture<Void> connect = AsyncUtils.completable(TypeSpec.VOID,
				channel::connect, new InetSocketAddress(host, port));
			return connect.thenCompose(__ -> {
				GadpClient client = createClient(host + ":" + port, channel);
				return client.connect().thenApply(___ -> client);
			});
		}
		catch (IOException e) {
			return CompletableFuture.failedFuture(e);
		}
	}

	protected GadpClient createClient(String description, AsynchronousByteChannel channel) {
		return new GadpClient(description, channel);
	}

	public String getAgentAddress() {
		return host;
	}

	public void setAgentAddress(String host) {
		this.host = host;
	}

	public int getAgentPort() {
		return port;
	}

	public void setAgentPort(int port) {
		this.port = port;
	}
}
