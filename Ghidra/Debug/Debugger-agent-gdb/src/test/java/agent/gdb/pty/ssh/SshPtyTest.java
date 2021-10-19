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

import static org.junit.Assert.assertEquals;
import static org.junit.Assume.assumeFalse;

import java.io.*;

import org.junit.Before;
import org.junit.Test;

import agent.gdb.pty.PtySession;
import ghidra.app.script.AskDialog;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.util.SystemUtilities;
import ghidra.util.exception.CancelledException;

public class SshPtyTest extends AbstractGhidraHeadedIntegrationTest {
	protected GhidraSshPtyFactory factory;

	@Before
	public void setupSshPtyTest() throws CancelledException {
		assumeFalse(SystemUtilities.isInTestingBatchMode());
		factory = new GhidraSshPtyFactory();
		factory.setUsername(promptUser());
	}

	public static String promptUser() throws CancelledException {
		AskDialog<String> dialog = new AskDialog<>("SSH", "Username:", AskDialog.STRING, "");
		if (dialog.isCanceled()) {
			throw new CancelledException();
		}
		return dialog.getValueAsString();
	}

	public static class StreamPumper extends Thread {
		private final InputStream in;
		private final OutputStream out;

		public StreamPumper(InputStream in, OutputStream out) {
			setDaemon(true);
			this.in = in;
			this.out = out;
		}

		@Override
		public void run() {
			byte[] buf = new byte[1024];
			try {
				while (true) {
					int len = in.read(buf);
					if (len <= 0) {
						break;
					}
					out.write(buf, 0, len);
				}
			}
			catch (IOException e) {
			}
		}
	}

	@Test
	public void testSessionBash() throws IOException, InterruptedException {
		try (SshPty pty = factory.openpty()) {
			PtySession bash = pty.getChild().session(new String[] { "bash" }, null);
			OutputStream out = pty.getParent().getOutputStream();
			out.write("exit\n".getBytes("UTF-8"));
			out.flush();
			new StreamPumper(pty.getParent().getInputStream(), System.out).start();
			assertEquals(0, bash.waitExited().intValue());
		}
	}
}
