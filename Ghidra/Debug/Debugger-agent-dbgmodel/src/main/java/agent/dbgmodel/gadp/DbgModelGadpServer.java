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
package agent.dbgmodel.gadp;

import java.io.IOException;
import java.net.SocketAddress;
import java.util.concurrent.ExecutionException;

import org.apache.commons.lang3.exception.ExceptionUtils;

import agent.dbgeng.gadp.DbgEngGadpServer;
import agent.dbgmodel.gadp.impl.DbgModelGadpServerImpl;
import ghidra.dbg.agent.AgentWindow;
import ghidra.util.Msg;

/**
 * The interface for the SCTL-{@code dbgeng.dll} server
 * 
 * This is just an interface to specify the truly public methods. This is also a convenient place to
 * put all the command-line parsing logic.
 * 
 * This server implements the SCTL commands necessary to have a smooth debugging experience in
 * Ghidra. It implements almost every command that has use on a binary without debugging
 * information. It operates as a standalone debugging server based on {@code dbgeng.dll}, which can
 * accept other {@code dbgeng.dll}-based clients as well as SCTL clients.
 * 
 * Without limitation, the caveats are listed here:
 * 
 * 1) The {@code Tnames} request in not implemented. The only namespaces available are those given
 * in the {@code Rstat} response.
 * 
 * 2) For binaries without a debugging database (pdb file), the symbol commands only search the
 * exported symbols.
 * 
 * 3) The type commands are not implemented. Ghidra can read most PDB files directly.
 * 
 * 4) While SCTL presents thread-specific control, {@code dbgeng.dll} does not. Continue ("g" in
 * {@code dbgeng.dll}) affects all debugged targets, except those with higher suspect counts and
 * those that are frozen. The API makes it impossible to perfectly track which threads are actually
 * executed by "g". The server thus assumes that all threads run when any thread runs, and it will
 * synthesize the commands to reflect that in the connected clients.
 * 
 * 5) The {@code Ttrace} command is not supported. The user can configure filters in the host
 * debugger; however, some events will always be trapped by the SCTL server. Future versions may
 * adjust this.
 * 
 * 6) Snapshots are not supported. {@code dbgeng.dll} as no equivalent.
 * 
 * 7) System calls are no yet reported. Windows programs do not use {@code fork} and {@code exec}.
 * Instead, calls to {@code CreateProcess} cause the server to synthesize {@code Tattach} commands.
 * 
 * 8) The {@code Tunwind1} command is not supported. Ghidra should unwind instead.
 */
public interface DbgModelGadpServer extends DbgEngGadpServer {

	/**
	 * The entry point for the SCTL-DBGENG server in stand-alone mode
	 * 
	 * Run it to see help.
	 * 
	 * @param args the command-line arguments
	 * @throws IOException if an I/O error occurs
	 * @throws ExecutionException
	 * @throws InterruptedException
	 */
	public static void main(String[] args) throws Exception {
		try {
			new DbgModelRunner().run(args);
		}
		catch (Throwable t) {
			System.err.println(ExceptionUtils.getMessage(t));
			System.exit(1);
		}
	}

	/**
	 * Create a new instance of the server
	 * 
	 * @param addr the address to bind the SCTL server to
	 * @param busId the client ID the server should use on the bus for synthesized commands
	 * @param dbgSrvTransport the transport specification for the {@code dbgeng.dll} server
	 * @return the server instance
	 * @throws IOException
	 */
	public static DbgModelGadpServer newInstance(SocketAddress addr) throws IOException {
		return new DbgModelGadpServerImpl(addr);
	}

	/**
	 * Runs the server from the command line or dbgeng javaprovider
	 */
	public class DbgModelRunner extends DbgEngRunner {

		public DbgModelRunner() {
		}

		@Override
		public void run(String args[])
				throws IOException, InterruptedException, ExecutionException {
			parseArguments(args);

			try (DbgModelGadpServer server = newInstance(bindTo)) {
				server.startDbgEng(dbgengArgs.toArray(new String[] {})).exceptionally(e -> {
					Msg.error(this, "Error starting dbgeng/GADP", e);
					System.exit(-1);
					return null;
				});
				new AgentWindow("dbgmodel.dll Agent for Ghidra", server.getLocalAddress());
				while (server.isRunning()) {
					// TODO: Put consoleLoop back?
					Thread.sleep(1000);
				}
			}
		}
	}
}
