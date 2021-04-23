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
package agent.gdb.pty.ssh;

import static org.junit.Assume.assumeFalse;

import java.io.IOException;
import java.io.InputStream;

import org.junit.Before;
import org.junit.Test;

import ch.ethz.ssh2.*;
import ghidra.app.script.AskDialog;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.util.SystemUtilities;
import ghidra.util.exception.CancelledException;

public class SshExperimentsTest extends AbstractGhidraHeadedIntegrationTest {
	@Before
	public void checkInteractive() {
		assumeFalse(SystemUtilities.isInTestingBatchMode());
	}

	@Test
	public void testExpExecCommandIsAsync()
			throws IOException, CancelledException, InterruptedException {
		Connection conn = new Connection("localhost");

		conn.addConnectionMonitor(new ConnectionMonitor() {
			@Override
			public void connectionLost(Throwable reason) {
				System.err.println("Lost connection: " + reason);
			}
		});

		conn.connect();

		String user = SshPtyTest.promptUser();
		while (true) {
			char[] password =
				GhidraSshPtyFactory.promptPassword("localhost", "Password for " + user);
			boolean auth = conn.authenticateWithPassword(user, new String(password));
			if (auth) {
				break;
			}
			System.err.println("Authentication Failed");
		}

		Session session = conn.openSession();
		System.err.println("PRE: signal=" + session.getExitSignal());

		Thread thread = new Thread("reader") {
			@Override
			public void run() {
				InputStream stdout = session.getStdout();
				try {
					stdout.transferTo(System.out);
				}
				catch (IOException e) {
					e.printStackTrace();
				}
			}
		};
		thread.setDaemon(true);
		thread.start();

		// Demonstrates that execCommand returns before the remote command exits
		System.err.println("Invoking sleep remotely");
		session.execCommand("sleep 10");
		System.err.println("Returned from execCommand");
	}

	@Test
	public void testExpEOFImpliesCommandExited()
			throws IOException, CancelledException, InterruptedException {
		Connection conn = new Connection("localhost");

		conn.addConnectionMonitor(new ConnectionMonitor() {
			@Override
			public void connectionLost(Throwable reason) {
				System.err.println("Lost connection: " + reason);
			}
		});

		conn.connect();

		AskDialog<String> dialog = new AskDialog<>("SSH", "Username:", AskDialog.STRING, "");
		if (dialog.isCanceled()) {
			throw new CancelledException();
		}
		String user = dialog.getValueAsString();
		while (true) {
			char[] password =
				GhidraSshPtyFactory.promptPassword("localhost", "Password for " + user);
			boolean auth = conn.authenticateWithPassword(user, new String(password));
			if (auth) {
				break;
			}
			System.err.println("Authentication Failed");
		}

		Session session = conn.openSession();
		System.err.println("PRE: signal=" + session.getExitSignal());

		Thread thread = new Thread("reader") {
			@Override
			public void run() {
				InputStream stdout = session.getStdout();
				try {
					stdout.transferTo(System.out);
				}
				catch (IOException e) {
					e.printStackTrace();
				}
			}
		};
		thread.setDaemon(true);
		thread.start();

		// Demonstrates the ability to wait for the specific command
		System.err.println("Invoking sleep remotely");
		session.execCommand("sleep 3");
		session.waitForCondition(ChannelCondition.EOF, 0);
		System.err.println("Returned from waitForCondition");
	}

	@Test
	public void testExpEnvWorks()
			throws IOException, CancelledException, InterruptedException {
		Connection conn = new Connection("localhost");

		conn.addConnectionMonitor(new ConnectionMonitor() {
			@Override
			public void connectionLost(Throwable reason) {
				System.err.println("Lost connection: " + reason);
			}
		});

		conn.connect();

		AskDialog<String> dialog = new AskDialog<>("SSH", "Username:", AskDialog.STRING, "");
		if (dialog.isCanceled()) {
			throw new CancelledException();
		}
		String user = dialog.getValueAsString();
		while (true) {
			char[] password =
				GhidraSshPtyFactory.promptPassword("localhost", "Password for " + user);
			boolean auth = conn.authenticateWithPassword(user, new String(password));
			if (auth) {
				break;
			}
			System.err.println("Authentication Failed");
		}

		Session session = conn.openSession();
		System.err.println("PRE: signal=" + session.getExitSignal());

		Thread thread = new Thread("reader") {
			@Override
			public void run() {
				InputStream stdout = session.getStdout();
				try {
					stdout.transferTo(System.out);
				}
				catch (IOException e) {
					e.printStackTrace();
				}
			}
		};
		thread.setDaemon(true);
		thread.start();

		// Demonstrates a syntax for specifying env.
		// I suspect this depends on the remote shell.
		System.err.println("Echoing...");
		session.execCommand("MY_DATA=test bash -c 'echo data:$MY_DATA:end'");
		session.waitForCondition(ChannelCondition.EOF, 0);
		System.err.println("Done");
	}
}
