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

import java.io.IOException;

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
		factory.setHostname("localhost");
		factory.setUsername(promptUser());
		factory.setKeyFile("");
	}

	public static String promptUser() throws CancelledException {
		AskDialog<String> dialog = new AskDialog<>("SSH", "Username:", AskDialog.STRING, "");
		if (dialog.isCanceled()) {
			throw new CancelledException();
		}
		return dialog.getValueAsString();
	}

	@Test
	public void testSessionBash() throws IOException, InterruptedException {
		try (SshPty pty = factory.openpty()) {
			PtySession bash = pty.getChild().session(new String[] { "bash" }, null);
			pty.getParent().getOutputStream().write("exit\n".getBytes());
			assertEquals(0, bash.waitExited().intValue());
		}
	}
}
