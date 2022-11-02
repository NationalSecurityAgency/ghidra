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
package agent.gdb.pty.windows;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;
import static org.junit.Assume.assumeTrue;

import java.io.*;
import java.lang.ProcessBuilder.Redirect;

import org.junit.Before;
import org.junit.Test;

import com.sun.jna.LastErrorException;

import agent.gdb.pty.*;
import ghidra.dbg.testutil.DummyProc;
import ghidra.framework.OperatingSystem;

public class ConPtyTest extends AbstractPtyTest {

	@Before
	public void checkWindows() {
		assumeTrue(OperatingSystem.WINDOWS == OperatingSystem.CURRENT_OPERATING_SYSTEM);
	}

	@Test
	public void testSessionCmd() throws IOException, InterruptedException {
		try (Pty pty = ConPty.openpty()) {
			PtySession cmd = pty.getChild().session(new String[] { DummyProc.which("cmd") }, null);
			pty.getParent().getOutputStream().write("exit\r\n".getBytes());
			assertEquals(0, cmd.waitExited());
		}
	}

	@Test
	public void testSessionNonExistent() throws IOException, InterruptedException {
		try (Pty pty = ConPty.openpty()) {
			pty.getChild().session(new String[] { "thisHadBetterNoExist" }, null);
			fail();
		}
		catch (LastErrorException e) {
			assertEquals(2, e.getErrorCode());
		}
	}

	@Test
	public void testSessionCmdEchoTest() throws IOException, InterruptedException {
		try (Pty pty = ConPty.openpty()) {
			PtyParent parent = pty.getParent();
			PrintWriter writer = new PrintWriter(parent.getOutputStream());
			BufferedReader reader = loggingReader(parent.getInputStream());
			PtySession cmd = pty.getChild().session(new String[] { DummyProc.which("cmd") }, null);
			runExitCheck(3, cmd);

			writer.println("echo test");
			writer.flush();
			String line;
			do {
				line = reader.readLine();
			}
			while (!"test".equals(line));

			writer.println("exit 3");
			writer.flush();

			assertEquals(3, cmd.waitExited());
		}
	}

	@Test
	public void testSessionGdbLineLength() throws IOException, InterruptedException {
		try (Pty pty = ConPty.openpty()) {
			PtyParent parent = pty.getParent();
			PrintWriter writer = new PrintWriter(parent.getOutputStream());
			BufferedReader reader = loggingReader(parent.getInputStream());
			PtySession gdb =
				pty.getChild().session(new String[] { "C:\\msys64\\mingw64\\bin\\gdb.exe" }, null);

			writer.println(
				"echo This line is cleary much, much, much, much, much, much, much, much, much " +
					" longer than 80 characters");
			writer.flush();
			String line;
			do {
				line = reader.readLine();
			}
			while (!"test".equals(line));
		}
	}

	@Test
	public void testGdbInterruptPlain() throws Exception {
		ProcessBuilder builder = new ProcessBuilder("C:\\msys64\\mingw64\\bin\\gdb.exe");
		builder.redirectOutput(Redirect.PIPE);
		builder.redirectInput(Redirect.PIPE);
		builder.redirectErrorStream(true);

		Process gdb = builder.start();

		PrintWriter writer = new PrintWriter(gdb.getOutputStream());
		pump(gdb.getInputStream(), System.err);

		System.out.println("Testing");
		writer.println("echo test");
		writer.println("set new-console on");
		System.out.println("Launching notepad");
		writer.println("file C:\\\\Windows\\\\notepad.exe");
		writer.println("run");
		writer.flush();
		System.out.println("Waiting");
		Thread.sleep(3000);
		System.out.println("Interrupting");
		writer.write(3);
		writer.println();
		writer.flush();
		System.out.println("Killing");
		writer.println("kill");
		writer.flush();
		writer.println("y");
		writer.flush();
	}

	@Test
	public void testGdbInterruptConPty() throws Exception {
		try (Pty pty = ConPty.openpty()) {
			PtyParent parent = pty.getParent();
			PrintWriter writer = new PrintWriter(parent.getOutputStream());
			//BufferedReader reader = loggingReader(parent.getInputStream());
			PtySession gdb =
				pty.getChild().session(new String[] { "C:\\msys64\\mingw64\\bin\\gdb.exe" }, null);

			pump(parent.getInputStream(), System.err);

			System.out.println("Testing");
			writer.println("echo test");
			writer.println("set new-console on");
			System.out.println("Launching notepad");
			writer.println("file C:\\\\Windows\\\\notepad.exe");
			writer.println("run");
			writer.flush();
			System.out.println("Waiting");
			Thread.sleep(3000);
			System.out.println("Interrupting");
			writer.write(3);
			writer.println();
			writer.flush();
			System.out.println("Killing");
			writer.println("kill");
			writer.flush();
			writer.println("y");
			writer.flush();

			Thread.sleep(100000);
		}
	}

	@Test
	public void testGdbMiConPty() throws Exception {
		try (Pty pty = ConPty.openpty()) {
			PtyParent parent = pty.getParent();
			PrintWriter writer = new PrintWriter(parent.getOutputStream());
			//BufferedReader reader = loggingReader(parent.getInputStream());
			PtySession gdb = pty.getChild()
					.session(new String[] { "C:\\msys64\\mingw64\\bin\\gdb.exe", "-i", "mi2" },
						null);

			InputStream inputStream = parent.getInputStream();
			inputStream = new AnsiBufferedInputStream(inputStream);
			pump(inputStream, System.out);

			writer.println("-interpreter-exec console \"echo test\"");
			writer.println("-interpreter-exec console \"quit\"");
			writer.flush();

			gdb.waitExited();
			//System.out.println("Exited");
		}
	}
}
