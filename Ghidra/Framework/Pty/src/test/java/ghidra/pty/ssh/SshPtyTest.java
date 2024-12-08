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
package ghidra.pty.ssh;

import static org.junit.Assert.assertEquals;
import static org.junit.Assume.assumeFalse;

import java.io.*;

import org.junit.Before;
import org.junit.Test;

import ghidra.app.script.AskDialog;
import ghidra.pty.*;
import ghidra.pty.PtyChild.Echo;
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

	@Test
	public void testSessionBash() throws IOException, InterruptedException {
		try (Pty pty = factory.openpty()) {
			PtySession bash = pty.getChild().session(new String[] { "bash" }, null);
			OutputStream out = pty.getParent().getOutputStream();
			out.write("exit\n".getBytes("UTF-8"));
			out.flush();
			new StreamPumper(pty.getParent().getInputStream(), System.out).start();
			assertEquals(0, bash.waitExited());
		}
	}

	@Test
	public void testDisableEcho() throws IOException, InterruptedException {
		try (Pty pty = factory.openpty()) {
			PtySession bash =
				pty.getChild().session(new String[] { "bash" }, null, Echo.OFF);
			OutputStream out = pty.getParent().getOutputStream();
			out.write("exit\n".getBytes("UTF-8"));
			out.flush();
			new StreamPumper(pty.getParent().getInputStream(), System.out).start();
			assertEquals(0, bash.waitExited());
		}
	}
}
