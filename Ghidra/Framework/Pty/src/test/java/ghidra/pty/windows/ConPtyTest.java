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
package ghidra.pty.windows;

import static org.junit.Assert.*;
import static org.junit.Assume.assumeTrue;

import java.io.*;
import java.lang.ProcessBuilder.Redirect;
import java.util.concurrent.TimeUnit;

import org.junit.Before;
import org.junit.Test;

import com.sun.jna.LastErrorException;

import ghidra.framework.OperatingSystem;
import ghidra.pty.*;
import ghidra.pty.testutil.DummyProc;
import ghidra.util.Msg;

public class ConPtyTest extends AbstractPtyTest {
	public static final int JOIN_TIMEOUT_MS = 3000;

	public static final String CMD = DummyProc.which("cmd.exe");
	public static final String GDB = DummyProc.which("gdb.exe");
	public static final String NOTEPAD = DummyProc.which("notepad.exe");

	@Before
	public void checkWindows() {
		assumeTrue(OperatingSystem.WINDOWS == OperatingSystem.CURRENT_OPERATING_SYSTEM);
	}

	@Test
	public void testSessionCmd() throws Exception {
		try (Pty pty = ConPtyFactory.INSTANCE.openpty()) {
			PtySession cmd = pty.getChild().session(new String[] { CMD }, null);
			pty.getParent().getOutputStream().write("exit\r\n".getBytes());
			assertEquals(0, cmd.waitExited(JOIN_TIMEOUT_MS, TimeUnit.MILLISECONDS));
		}
	}

	@Test
	public void testSessionNonExistent() throws IOException, InterruptedException {
		try (Pty pty = ConPtyFactory.INSTANCE.openpty()) {
			pty.getChild().session(new String[] { "thisHadBetterNoExist" }, null);
			fail();
		}
		catch (LastErrorException e) {
			assertEquals(2, e.getErrorCode());
		}
	}

	@Test
	public void testSessionCmdEchoTest() throws Exception {
		try (Pty pty = ConPtyFactory.INSTANCE.openpty()) {
			PtyParent parent = pty.getParent();
			PrintWriter writer = new PrintWriter(parent.getOutputStream());
			BufferedReader reader = loggingReader(parent.getInputStream());
			PtySession cmd = pty.getChild().session(new String[] { CMD }, null);
			runExitCheck(3, cmd);

			writer.println("echo test");
			writer.flush();
			// set up reading cmd output on a thread since "readLine" is blocking
			Thread t = new Thread(() -> {
				String line;
				try {
					do {
						line = reader.readLine();
					}
					while (!"test".equals(line));
				}
				catch (IOException e) {
					Msg.info(this, "done reading");
				}
			});

			t.setDaemon(true);
			t.start();

			writer.println("exit 3");
			writer.flush();

			assertEquals(3, cmd.waitExited(JOIN_TIMEOUT_MS, TimeUnit.MILLISECONDS));
			t.join(JOIN_TIMEOUT_MS);
		}
	}

	@Test
	public void testSessionGdbLineLength() throws Exception {
		try (Pty pty = ConPtyFactory.INSTANCE.openpty()) {
			PtyParent parent = pty.getParent();
			PrintWriter writer = new PrintWriter(parent.getOutputStream());
			BufferedReader reader = loggingReader(parent.getInputStream());
			PtySession gdb = pty.getChild().session(new String[] { GDB }, null);

			writer.println(
				"echo This line is cleary much, much, much, much, much, much, much, much, much " +
					" longer than 80 characters");
			writer.flush();

			// set up reading cmd output on a thread since "readLine" is blocking
			Thread t = new Thread(() -> {
				String line;
				try {
					do {
						line = reader.readLine();
					}
					while (!"test".equals(line));
				}
				catch (IOException e) {
					Msg.info(this, "done reading");
				}
			});

			t.setDaemon(true);
			t.start();

			writer.println("exit 3");
			writer.flush();

			assertEquals(3, gdb.waitExited(JOIN_TIMEOUT_MS, TimeUnit.MILLISECONDS));
			t.join(JOIN_TIMEOUT_MS);
		}
	}

	/**
	 * Verifies that the ConPty is actually necessary to send interrupts to child processes.
	 * <p>
	 * Sending char 3 down the stdin is not sufficient, as demonstrated in this experiment. GDB does
	 * not receive the interrupt, and so the target process remains running, and none of the
	 * subsequent gdb commands are processed. Thus, the target and gdb are still running by the time
	 * we get to the {@link Process#waitFor(long, TimeUnit)} call. It will return false, thus
	 * causing the expected {@link AssertionError}.
	 * 
	 * @throws Exception
	 *             'tis a test
	 */
	@Test(expected = AssertionError.class)
	public void testGdbInterruptPlain() throws Exception {

		boolean terminated = false;
		Process gdb = null;
		try {
			ProcessBuilder builder = new ProcessBuilder(GDB);
			builder.redirectOutput(Redirect.PIPE);
			builder.redirectInput(Redirect.PIPE);
			builder.redirectErrorStream(true);

			gdb = builder.start();

			PrintWriter writer = new PrintWriter(gdb.getOutputStream());
			pump(gdb.getInputStream(), System.out);

			Msg.info(this, "Testing");
			writer.println("echo test");
			writer.println("set new-console on");
			Msg.info(this, "Launching notepad");
			writer.println("file %s".formatted(NOTEPAD.replace("\\", "\\\\")));
			writer.println("run");
			writer.flush();
			Msg.info(this, "Waiting");
			Thread.sleep(3000);
			Msg.info(this, "Interrupting");
			writer.write(3);
			writer.println();
			writer.flush();
			Thread.sleep(1000);
			Msg.info(this, "Killing");
			writer.println("kill");
			writer.flush();
			writer.println("y");
			writer.flush();
			writer.println("quit");
			writer.flush();

			terminated = gdb.waitFor(JOIN_TIMEOUT_MS, TimeUnit.MILLISECONDS);
			assertTrue("Gdb did not terminate", terminated);
		}
		finally {
			if (gdb != null && !terminated) {
				for (ProcessHandle child : gdb.descendants().toList()) {
					Msg.info(this, "Killing descendant process: %d".formatted(child.pid()));
					child.destroyForcibly();
				}
				Msg.info(this, "Killing gdb: %d".formatted(gdb.pid()));
				gdb.destroyForcibly();
			}
		}
	}

	/**
	 * STRANGENESS: This test will fail if Eclipse was started from git-bash on Windows. I can only
	 * guess this is because of some strange interaction between ConPty (under test here) and the
	 * WinPty hack that git-bash still uses? Specifically, the interrupt (char 3) is not causing the
	 * signal to actually get sent to gdb. I haven't the slightest idea where it goes instead, if
	 * anywhere.
	 * 
	 * @throws Exception
	 *             'tis a test
	 */
	@Test
	public void testGdbInterruptConPty() throws Exception {
		PtySession gdb = null;
		try (Pty pty = ConPtyFactory.INSTANCE.openpty()) {
			PtyParent parent = pty.getParent();
			PrintWriter writer = new PrintWriter(parent.getOutputStream());
			gdb = pty.getChild().session(new String[] { GDB }, null);

			pump(parent.getInputStream(), System.err);

			Msg.info(this, "Testing");
			writer.println("echo test");
			writer.println("set new-console on");
			Msg.info(this, "Launching notepad");
			writer.println("file %s".formatted(NOTEPAD.replace("\\", "\\\\")));
			writer.println("run");
			writer.flush();
			Msg.info(this, "Waiting");
			Thread.sleep(3000);

			Msg.info(this, "Interrupting");
			writer.write(3);
			writer.println();
			writer.flush();
			Thread.sleep(1000);

			Msg.info(this, "Killing");
			writer.println("kill");
			writer.flush();
			writer.println("y");
			writer.flush();
			writer.println("quit");
			writer.flush();

			gdb.waitExited(JOIN_TIMEOUT_MS, TimeUnit.MILLISECONDS);
		}
		finally {
			ProcessHandle handle = gdb.handle();
			if (handle != null) {
				for (ProcessHandle child : handle.descendants().toList()) {
					Msg.info(this, "Killing descendant process: %d".formatted(child.pid()));
					child.destroyForcibly();
				}
				Msg.info(this, "Killing gdb: %d".formatted(handle.pid()));
				gdb.destroyForcibly();
			}
		}
	}

	@Test
	public void testGdbMiConPty() throws Exception {
		try (Pty pty = ConPtyFactory.INSTANCE.openpty()) {
			PtyParent parent = pty.getParent();
			PrintWriter writer = new PrintWriter(parent.getOutputStream());
			//BufferedReader reader = loggingReader(parent.getInputStream());
			PtySession gdb = pty.getChild()
					.session(new String[] { GDB, "-i", "mi2" }, null);

			InputStream inputStream = parent.getInputStream();
			inputStream = new AnsiBufferedInputStream(inputStream);
			pump(inputStream, System.out);

			writer.println("-interpreter-exec console \"echo test\"");
			writer.println("-interpreter-exec console \"quit\"");
			writer.flush();

			gdb.waitExited(JOIN_TIMEOUT_MS, TimeUnit.MILLISECONDS);
		}
	}
}
