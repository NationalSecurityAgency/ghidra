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
package agent.gdb.gadp;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

import agent.gdb.gadp.impl.GdbGadpServerImpl;
import ghidra.dbg.agent.AgentWindow;
import ghidra.util.Msg;

public interface GdbGadpServer extends AutoCloseable {
	public static void main(String[] args) throws Exception {
		new Runner().run(args);
	}

	public static GdbGadpServer newInstance(SocketAddress addr) throws IOException {
		return new GdbGadpServerImpl(addr);
	}

	public class Runner {
		private String gdbCmd = "gdb";
		private List<String> gdbArgs = new ArrayList<>();
		private InetSocketAddress bindTo;

		public void run(String args[])
				throws IOException, InterruptedException, ExecutionException {
			parseArguments(args);

			try (GdbGadpServer server = newInstance(bindTo)) {
				server.startGDB(gdbCmd, gdbArgs.toArray(new String[] {})).exceptionally(e -> {
					Msg.error(this, "Error starting GDB/GADP", e);
					System.exit(-1);
					return null;
				});
				new AgentWindow("GDB Agent for Ghidra", server.getLocalAddress());
				server.consoleLoop();
			}
			System.exit(0);
		}

		private void parseArguments(String[] args) {
			String iface = "localhost";
			int port = 12345;
			// NOTE: Maybe we should import commons-cli (Apache 2.0) or Argparse4j (MIT)....
			Iterator<String> ait = Arrays.asList(args).iterator();
			while (ait.hasNext()) {
				String a = ait.next();
				if ("--gadp-args".equals(a)) {
					break;
				}
				else if ("-h".equals(a) || "--help".equals(a)) {
					printUsage();
					System.exit(0);
				}
				else {
					gdbArgs.add(a);
				}
			}
			while (ait.hasNext()) {
				String a = ait.next();
				if ("-p".equals(a) || "--port".equals(a)) {
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
				else if ("-g".equals(a) || "--gdb-cmd".equals(a)) {
					if (!ait.hasNext()) {
						System.err.println("Expected CMD");
						printUsage();
						System.exit(-1);
					}
					gdbCmd = ait.next();
				}
				else if ("-x".equals(a) || "--existing".equals(a)) {
					gdbCmd = null;
				}
				else {
					System.err.println("Unknown option: " + a);
					printUsage();
					System.exit(-1);
				}
			}
			bindTo = new InetSocketAddress(iface, port);
		}

		private void printUsage() {
			System.out.println("This is the GADP wrapper for GDB.  Usage:");
			System.out.println();
			System.out.println(
				"    gadpgdb [GDB options] [--gadp-args [-H HOST/ADDR] [-p PORT] [-g CMD] [-x]]");
			System.out.println();
			System.out.println("Options:");
			System.out.println();
			System.out.println("Use gdb -h for suitable [GDB options]");
			System.out.println();
			System.out.println(
				"  --host/-H          The address of the interface on which to listen. Default is localhost");
			System.out.println(
				"  --port/-p          The TCP port on which to listen. Default is 12345. 0 for automatic.");
			System.out.println(
				"  --gdb-cmd/-g       The command to launch gdb. Default is 'gdb'");
			System.out.println(
				"  --existing/-x      Do not launch gdb. Instead just open a pty");
			System.out.println();
			System.out.println(
				"Starts a GDB-based GADP server \"agent\". In general, it can be invoked in");
			System.out.println(
				"the same manner as standard gdb. Arguments to control the GADP server and");
			System.out.println(
				"GDB invocation are given after the --gadp-args flag. Once the server has");
			System.out.println(
				"started, it will print the interface IP and port. The -g and -x flags are");
			System.out.println(
				"mutually exclusive. The one appearing last get preference. The -x flags");
			System.out.println(
				"causes the agent to refrain from launching its own gdb process. Instead,");
			System.out.println(
				"it prints the file name of a private terminate (pty) where it expects a");
			System.out.println(
				"GDB/MI v2 interpreter from an existing gdb process. Use the new-ui command");
			System.out.println(
				"(available since GDB version 7.12) to join the agent to the existing");
			System.out.println("session:");
			System.out.println();
			System.out.println("(gdb) new-ui mi2 /dev/ptyXX");
		}
	}

	/**
	 * Start the GDB session
	 * 
	 * @param gdbCmd the command to execute GDB
	 * @param args arguments to pass to GDB, except for -i
	 * @return a future that completes when GDB is ready
	 */
	CompletableFuture<Void> startGDB(String gdbCmd, String[] args);

	/**
	 * Get the local address to which the SCTL server is bound.
	 * 
	 * @return the local socket address
	 */
	SocketAddress getLocalAddress();

	/**
	 * Starts the GDB manager's console loop
	 * 
	 * @throws IOException if an I/O error occurs
	 */
	public void consoleLoop() throws IOException;

	/**
	 * Close all SCTL connections and ports, and terminate the GDB session
	 * 
	 * @throws IOException if an I/O error occurs
	 */
	public void terminate() throws IOException;

	/**
	 * Calls {@link #terminate()}
	 * 
	 * @throws IOException if an I/O error occurs
	 */
	@Override
	default void close() throws IOException {
		terminate();
	}

	void setExitOnClosed(boolean exitOnClosed);
}
