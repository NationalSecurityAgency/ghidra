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
package agent.gdb.ffi.linux;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.*;
import java.util.*;

import org.junit.Ignore;
import org.junit.Test;

import ghidra.dbg.testutil.DummyProc;

public class PtyTest {
	@Test
	public void testOpenClosePty() throws IOException {
		Pty pty = Pty.openpty();
		pty.close();
	}

	@Test
	public void testMasterToSlave() throws IOException {
		try (Pty pty = Pty.openpty()) {
			PrintWriter writer = new PrintWriter(pty.getMaster().getOutputStream());
			BufferedReader reader =
				new BufferedReader(new InputStreamReader(pty.getSlave().getInputStream()));

			writer.println("Hello, World!");
			writer.flush();
			assertEquals("Hello, World!", reader.readLine());
		}
	}

	@Test
	public void testSlaveToMaster() throws IOException {
		try (Pty pty = Pty.openpty()) {
			PrintWriter writer = new PrintWriter(pty.getSlave().getOutputStream());
			BufferedReader reader =
				new BufferedReader(new InputStreamReader(pty.getMaster().getInputStream()));

			writer.println("Hello, World!");
			writer.flush();
			assertEquals("Hello, World!", reader.readLine());
		}
	}

	@Test
	public void testSessionBash() throws IOException, InterruptedException {
		try (Pty pty = Pty.openpty()) {
			Process bash = pty.getSlave().session(new String[] { DummyProc.which("bash") }, null);
			pty.getMaster().getOutputStream().write("exit\n".getBytes());
			assertEquals(0, bash.waitFor());
		}
	}

	@Test
	public void testForkIntoNonExistent() throws IOException, InterruptedException {
		try (Pty pty = Pty.openpty()) {
			Process dies = pty.getSlave().session(new String[] { "thisHadBetterNotExist" }, null);
			/**
			 * NOTE: Java subprocess dies with code 1 on unhandled exception. TODO: Is there a nice
			 * way to distinguish whether the code is from java or the execed image?
			 */
			assertEquals(1, dies.waitFor());
		}
	}

	public Thread pump(InputStream is, OutputStream os) {
		Thread t = new Thread(() -> {
			byte[] buf = new byte[1024];
			while (true) {
				int len;
				try {
					len = is.read(buf);
					os.write(buf, 0, len);
				}
				catch (IOException e) {
					throw new AssertionError(e);
				}
			}
		});
		t.setDaemon(true);
		t.start();
		return t;
	}

	public BufferedReader loggingReader(InputStream is) {
		return new BufferedReader(new InputStreamReader(is)) {
			@Override
			public String readLine() throws IOException {
				String line = super.readLine();
				System.out.println("log: " + line);
				return line;
			}
		};
	}

	public Thread runExitCheck(int expected, Process proc) {
		Thread exitCheck = new Thread(() -> {
			while (true) {
				try {
					assertEquals("Early exit with wrong code", expected, proc.waitFor());
					return;
				}
				catch (InterruptedException e) {
					System.err.println("Exit check interrupted");
				}
			}
		});
		exitCheck.setDaemon(true);
		exitCheck.start();
		return exitCheck;
	}

	@Test
	public void testSessionBashEchoTest() throws IOException, InterruptedException {
		Map<String, String> env = new HashMap<>();
		env.put("PS1", "BASH:");
		env.put("PROMPT_COMMAND", "");
		try (Pty pty = Pty.openpty()) {
			PtyMaster master = pty.getMaster();
			PrintWriter writer = new PrintWriter(master.getOutputStream());
			BufferedReader reader = loggingReader(master.getInputStream());
			Process bash = pty.getSlave().session(new String[] { DummyProc.which("bash") }, env);
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

			assertTrue(Set.of("BASH:exit 3", "exit 3").contains(reader.readLine()));

			assertEquals(3, bash.waitFor());
		}
	}

	@Test
	@Ignore("Some extra bash kruft is sneaking in, and I don't know how")
	public void testSessionBashInterruptCat() throws IOException, InterruptedException {
		Map<String, String> env = new HashMap<>();
		env.put("PS1", "BASH:");
		try (Pty pty = Pty.openpty()) {
			PtyMaster master = pty.getMaster();
			PrintWriter writer = new PrintWriter(master.getOutputStream());
			BufferedReader reader = loggingReader(master.getInputStream());
			Process bash = pty.getSlave().session(new String[] { DummyProc.which("bash") }, env);
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
			assertTrue(Set.of("BASH:cat", "cat").contains(reader.readLine()));

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

			assertEquals(3, bash.waitFor());
		}
	}
}
