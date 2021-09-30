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
package agent.lldb.gadp;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

import agent.lldb.gadp.impl.LldbGadpServerImpl;
import ghidra.dbg.agent.AgentWindow;
import ghidra.util.Msg;

public interface LldbGadpServer extends AutoCloseable {

	/**
	 * The entry point for the LLDB server in stand-alone mode
	 * 
	 * Run it to see help.
	 * 
	 * @param args the command-line arguments
	 * @throws IOException if an I/O error occurs
	 * @throws ExecutionException
	 * @throws InterruptedException
	 */
	public static void main(String[] args) throws Exception {
		new LldbRunner().run(args);
	}

	/**
	 * Create a new instance of the server
	 * 
	 * @param addr the address to bind the SCTL server to
	 * @param busId the client ID the server should use on the bus for synthesized commands
	 * @return the server instance
	 * @throws IOException
	 */
	public static LldbGadpServer newInstance(SocketAddress addr) throws IOException {
		return new LldbGadpServerImpl(addr);
	}

	/**
	 * Runs the server from the command line
	 */
	public class LldbRunner {
		protected InetSocketAddress bindTo;
		protected List<String> lldbArgs = new ArrayList<>();
		protected byte busId = 1;
		protected String remote = null;

		public LldbRunner() {
		}

		public void run(String args[])
				throws IOException, InterruptedException, ExecutionException {
			parseArguments(args);

			try (LldbGadpServer server = newInstance(bindTo)) {
				//TODO: fix/test the debugConnect case when args are passed
				server.startLLDB(lldbArgs.toArray(new String[] {})).exceptionally(e -> {
					Msg.error(this, "Error starting lldb/GADP", e);
					System.exit(-1);
					return null;
				});
				new AgentWindow("LLDB Agent for Ghidra", server.getLocalAddress());
				while (server.isRunning()) {
					Thread.sleep(1000);
				}
				System.exit(0);
			}
		}

		protected void parseArguments(String[] args) {
			String iface = "localhost";
			int port = 12345;
			// NOTE: Maybe commons-cli or Argparse4j?
			Iterator<String> ait = Arrays.asList(args).iterator();
			while (ait.hasNext()) {
				String a = ait.next();
				if ("-h".equals(a) || "--help".equals(a)) {
					printUsage();
					System.exit(0);
				}
				else if ("-p".equals(a) || "--port".equals(a)) {
					if (!ait.hasNext()) {
						System.err.println("Expected PORT");
						printUsage();
						System.exit(-1);
					}
					String portStr = ait.next();
					try {
						port = Integer.parseInt(portStr);
					}
					catch (NumberFormatException e) {
						System.err.println("Integer required. Got " + portStr);
						printUsage();
						System.exit(-1);
					}
				}
				else if ("-H".equals(a) || "--host".equals(a)) {
					if (!ait.hasNext()) {
						System.err.println("Expected HOST/ADDR");
						printUsage();
						System.exit(-1);
					}
					iface = ait.next();
				}
				else {
					System.err.println("Unknown option: " + a);
					printUsage();
					System.exit(-1);
				}
			}

			bindTo = new InetSocketAddress(iface, port);
		}

		protected void printUsage() {
			System.out.println("This is the GADP server for LLVM's lldb.  Usage:");
			System.out.println();
			System.out.println("     [-H HOST/ADDR] [-p PORT] [-i ID] [-t TRANSPORT] [-r REMOTE]");
			System.out.println();
			System.out.println("Options:");
			System.out.println(
				"  --host/-H          The address of the interface on which to listen.");
			System.out.println("                     Default is localhost");
			System.out.println(
				"  --port/-p          The TCP port on which to listen for GADP. Default is 12345");
		}
	}

	/**
	 * Start the debugging server
	 * 
	 * @return a future that completes when the server is ready
	 */
	CompletableFuture<Void> startLLDB(String[] args);

	/**
	 * Get the local address to which the SCTL server is bound.
	 * 
	 * @return the local socket address
	 */
	SocketAddress getLocalAddress();

	/**
	 * Close all connections and ports, GADP and Process Server, and terminate the server
	 * 
	 * @throws IOException if an I/O error occurs
	 */
	public void terminate() throws IOException;

	/**
	 * Check if the server is running
	 * 
	 * This will return false: 1) Before the server has been started, 2) After a call to
	 * {@link #terminate()}, or 3) When an error occurs causing the server to terminate
	 * unexpectedly. Otherwise, it returns true.
	 * 
	 * @returns true if the server is currently running.
	 */
	public boolean isRunning();

	/**
	 * Calls {@link #terminate()}
	 * 
	 * @throws IOException if an I/O error occurs
	 */
	@Override
	default void close() throws IOException {
		terminate();
	}
}
