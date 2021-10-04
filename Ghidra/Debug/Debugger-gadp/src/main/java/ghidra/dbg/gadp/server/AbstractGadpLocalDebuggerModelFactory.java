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
package ghidra.dbg.gadp.server;

import java.io.*;
import java.nio.channels.AsynchronousByteChannel;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Future;

import generic.concurrent.io.IOResult;
import generic.concurrent.io.ProcessConsumer;
import ghidra.dbg.DebuggerModelFactory;
import ghidra.dbg.gadp.client.GadpClient;
import ghidra.dbg.gadp.client.GadpTcpDebuggerModelFactory;
import ghidra.util.Msg;

public abstract class AbstractGadpLocalDebuggerModelFactory implements DebuggerModelFactory {
	public static final boolean LOG_AGENT_STDOUT = true;

	protected String host = "localhost";
	@FactoryOption("Agent interface address")
	public final Property<String> agentAddressOption =
		Property.fromAccessors(String.class, this::getAgentAddress, this::setAgentAddress);

	protected int port = 0; // Automatic, ephemeral
	@FactoryOption("Agent TCP port")
	public final Property<Integer> agentPortOption =
		Property.fromAccessors(int.class, this::getAgentPort, this::setAgentPort);

	protected int jdwpPort = -1;
	@FactoryOption("Open agent's JDWP port (-1 to disable, 0 for ephemeral)")
	public final Property<Integer> jdwpPortOption =
		Property.fromAccessors(int.class, this::getJdwpPort, this::setJdwpPort);

	protected boolean jdwpSuspend = false;
	@FactoryOption("Suspend for JDWP")
	public final Property<Boolean> jdwpSuspendOption =
		Property.fromAccessors(boolean.class, this::isJdwpSuspend, this::setJdwpSuspend);

	/**
	 * Get the name of the thread which processes the agent's stdout
	 */
	protected abstract String getThreadName();

	/**
	 * Get the command line to launch the agent
	 * 
	 * Note, the given list already contains the java invocation and incorporates the -debugAgent-
	 * option. The implementor must incorporate all other options, including -host- and -port-.
	 * 
	 * @param cmd the command line
	 */
	protected abstract void completeCommandLine(List<String> cmd);

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

	public int getJdwpPort() {
		return jdwpPort;
	}

	public void setJdwpPort(int jdwpPort) {
		this.jdwpPort = jdwpPort;
	}

	public boolean isJdwpSuspend() {
		return jdwpSuspend;
	}

	public void setJdwpSuspend(boolean jdwpSuspend) {
		this.jdwpSuspend = jdwpSuspend;
	}

	class AgentThread extends Thread {
		int port;
		Process process;
		CompletableFuture<Void> ready = new CompletableFuture<>();

		public AgentThread() {
			super(getThreadName());
		}

		@Override
		public void run() {
			try {
				ProcessBuilder builder = new ProcessBuilder();
				List<String> cmd = new ArrayList<>();
				cmd.add("java");
				cmd.addAll(List.of("-cp", System.getProperty("java.class.path")));
				if (jdwpPort >= 0) {
					cmd.add("-agentlib:jdwp=server=y,transport=dt_socket,address=" + jdwpPort +
						",suspend=" + (jdwpSuspend ? "y" : "n"));
				}
				completeCommandLine(cmd);
				builder.command(cmd);
				//builder.redirectError(Redirect.INHERIT);

				process = builder.start();

				InputStream errorStream = process.getErrorStream();
				Future<IOResult> errorFuture = ProcessConsumer.consume(errorStream);

				BufferedReader reader =
					new BufferedReader(new InputStreamReader(process.getInputStream()));
				String line;
				while (null != (line = reader.readLine())) {
					if (LOG_AGENT_STDOUT) {
						Msg.info(this, "AGENT: " + line);
					}
					if (line.startsWith(AbstractGadpServer.LISTENING_ON)) {
						String[] parts = line.split(":"); // Separates address from port
						port = Integer.parseInt(parts[parts.length - 1]);
						ready.complete(null);
					}
				}

				if (!ready.isDone()) {
					IOResult errorResult = errorFuture.get();
					String errorMessage = errorResult.getOutputAsString();
					if (errorMessage != null) {
						ready.completeExceptionally(
							new RuntimeException("Agent terminated with error: " + errorMessage));
					}
					else {
						ready.completeExceptionally(
							new RuntimeException("Agent terminated unexpectedly"));
					}

				}
			}
			catch (Throwable e) {
				ready.completeExceptionally(e);
			}
		}
	}

	static class AgentOwningGadpClient extends GadpClient {
		private final AgentThread agentThread;

		public AgentOwningGadpClient(String description, AsynchronousByteChannel channel,
				AgentThread agentThread) {
			super(description, channel);
			this.agentThread = agentThread;
		}

		@Override
		public CompletableFuture<Void> close() {
			return super.close().whenComplete((v, e) -> {
				agentThread.process.destroy();
				agentThread.interrupt();
			});
		}
	}

	static class AgentOwningGadpTcpDebuggerModelFactory extends GadpTcpDebuggerModelFactory {
		private final AgentThread agentThread;

		public AgentOwningGadpTcpDebuggerModelFactory(AgentThread agentThread) {
			this.agentThread = agentThread;
		}

		@Override
		protected GadpClient createClient(String description, AsynchronousByteChannel channel) {
			return new AgentOwningGadpClient(description, channel, agentThread);
		}
	}

	@Override
	public CompletableFuture<GadpClient> build() {
		AgentThread thread = new AgentThread();
		thread.start();
		return thread.ready.thenCompose(__ -> {
			GadpTcpDebuggerModelFactory factory =
				new AgentOwningGadpTcpDebuggerModelFactory(thread);
			// selectedPort may differ from port option, particularly if port == 0
			factory.setAgentPort(thread.port);
			return factory.build();
		});
	}
}
