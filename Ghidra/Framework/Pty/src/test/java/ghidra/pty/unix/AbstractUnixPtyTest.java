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
package ghidra.pty.unix;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.*;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import org.junit.Test;

import ghidra.dbg.testutil.DummyProc;
import ghidra.pty.AbstractPtyTest;
import ghidra.pty.PtyChild.Echo;
import ghidra.pty.PtySession;

public abstract class AbstractUnixPtyTest extends AbstractPtyTest {

	protected abstract UnixPty openpty() throws IOException;

	@Test
	public void testOpenClosePty() throws IOException {
		UnixPty pty = openpty();
		pty.close();
	}

	@Test
	public void testParentToChild() throws IOException {
		try (UnixPty pty = openpty()) {
			PrintWriter writer = new PrintWriter(pty.getParent().getOutputStream());
			BufferedReader reader =
				new BufferedReader(new InputStreamReader(pty.getChild().getInputStream()));

			writer.println("Hello, World!");
			writer.flush();
			assertEquals("Hello, World!", reader.readLine());
		}
	}

	@Test
	public void testChildToParent() throws IOException {
		try (UnixPty pty = openpty()) {
			PrintWriter writer = new PrintWriter(pty.getChild().getOutputStream());
			BufferedReader reader =
				new BufferedReader(new InputStreamReader(pty.getParent().getInputStream()));

			writer.println("Hello, World!");
			writer.flush();
			assertEquals("Hello, World!", reader.readLine());
		}
	}

	@Test
	public void testSessionBash() throws IOException, InterruptedException, TimeoutException {
		try (UnixPty pty = openpty()) {
			PtySession bash =
				pty.getChild().session(new String[] { DummyProc.which("bash") }, null);
			pty.getParent().getOutputStream().write("exit\n".getBytes());
			assertEquals(0, bash.waitExited(2, TimeUnit.SECONDS));
		}
	}

	@Test
	public void testForkIntoNonExistent()
			throws IOException, InterruptedException, TimeoutException {
		try (UnixPty pty = openpty()) {
			PtySession dies =
				pty.getChild().session(new String[] { "thisHadBetterNotExist" }, null);
			/**
			 * Choice of 127 is based on bash setting "exit code" to 127 for "command not found"
			 */
			assertEquals(127, dies.waitExited(2, TimeUnit.SECONDS));
		}
	}

	@Test
	public void testSessionBashEchoTest()
			throws IOException, InterruptedException, TimeoutException {
		Map<String, String> env = new HashMap<>();
		env.put("PS1", "BASH:");
		env.put("PROMPT_COMMAND", "");
		env.put("TERM", "");
		try (UnixPty pty = openpty()) {
			UnixPtyParent parent = pty.getParent();
			PrintWriter writer = new PrintWriter(parent.getOutputStream());
			BufferedReader reader = loggingReader(parent.getInputStream());
			PtySession bash =
				pty.getChild().session(new String[] { DummyProc.which("bash"), "--norc" }, env);
			runExitCheck(3, bash);

			writer.println("echo test");
			writer.flush();
			String line;
			do {
				line = reader.readLine();
			}
			while (!"test".equals(line));

			writer.println("exit 3");
			writer.flush();

			line = reader.readLine();
			assertTrue("Not 'exit 3' or 'BASH:exit 3': '" + line + "'",
				Set.of("BASH:exit 3", "exit 3").contains(line));

			assertEquals(3, bash.waitExited(2, TimeUnit.SECONDS));
		}
	}

	@Test
	public void testSessionBashInterruptCat()
			throws IOException, InterruptedException, TimeoutException {
		Map<String, String> env = new HashMap<>();
		env.put("PS1", "BASH:");
		env.put("PROMPT_COMMAND", "");
		env.put("TERM", "");
		try (UnixPty pty = openpty()) {
			UnixPtyParent parent = pty.getParent();
			PrintWriter writer = new PrintWriter(parent.getOutputStream());
			BufferedReader reader = loggingReader(parent.getInputStream());
			PtySession bash =
				pty.getChild().session(new String[] { DummyProc.which("bash"), "--norc" }, env);
			runExitCheck(3, bash);

			writer.println("echo test");
			writer.flush();
			String line;
			do {
				line = reader.readLine();
			}
			while (!"test".equals(line));

			writer.println("cat");
			writer.flush();
			line = reader.readLine();
			assertTrue("Not 'cat' or 'BASH:cat': '" + line + "'",
				Set.of("BASH:cat", "cat").contains(line));

			writer.println("Hello, cat!");
			writer.flush();
			assertEquals("Hello, cat!", reader.readLine()); // echo back
			assertEquals("Hello, cat!", reader.readLine()); // cat back

			writer.write(3); // should interrupt
			writer.flush();
			do {
				line = reader.readLine();
			}
			while (!"^C".equals(line));
			writer.println("echo test");
			writer.flush();

			do {
				line = reader.readLine();
			}
			while (!"test".equals(line));

			writer.println("exit 3");
			writer.flush();
			assertTrue(Set.of("BASH:exit 3", "exit 3").contains(reader.readLine()));

			assertEquals(3, bash.waitExited(2, TimeUnit.SECONDS));
		}
	}

	@Test
	public void testLocalEchoOn() throws IOException {
		try (UnixPty pty = openpty()) {
			pty.getChild().nullSession();

			PrintWriter writer = new PrintWriter(pty.getParent().getOutputStream());
			BufferedReader reader =
				new BufferedReader(new InputStreamReader(pty.getParent().getInputStream()));

			writer.println("Hello, World!");
			writer.flush();
			assertEquals("Hello, World!", reader.readLine());
		}
	}

	@Test
	public void testLocalEchoOff() throws IOException {
		try (UnixPty pty = openpty()) {
			pty.getChild().nullSession(Echo.OFF);

			PrintWriter writerP = new PrintWriter(pty.getParent().getOutputStream());
			PrintWriter writerC = new PrintWriter(pty.getChild().getOutputStream());
			BufferedReader reader =
				new BufferedReader(new InputStreamReader(pty.getParent().getInputStream()));

			writerP.println("Hello, World!");
			writerP.flush();
			writerC.println("Good bye!");
			writerC.flush();

			assertEquals("Good bye!", reader.readLine());
		}
	}
}
