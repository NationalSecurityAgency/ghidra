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

import java.io.*;

import com.sun.jna.LastErrorException;
import com.sun.jna.platform.win32.Kernel32;
import com.sun.jna.platform.win32.WinNT.HANDLE;

public class NamedPipeTest {

	protected Handle checkHandle(HANDLE handle) {
		if (Kernel32.INVALID_HANDLE_VALUE.equals(handle)) {
			throw new LastErrorException(Kernel32.INSTANCE.GetLastError());
		}
		return new Handle(handle);
	}

	// @Test
	/**
	 * Experiment with MinGW GDB, named pipes, and {@code new-ui}.
	 * 
	 * <p>
	 * Run this test, start GDB in a command shell, then issue
	 * "{@code new-ui mi2 \\\\.\\pipe\\GhidraGDB}". With GDB 11.1, GDB will print "New UI allocated"
	 * to the console, and I'll receive {@code =thread-group-added,id="i1"} on the pipe. However,
	 * GDB never seems to process my {@code -add-inferior} command. Furthermore, GDB freezes and no
	 * longer accepts input on the console, either.
	 */
	public void testExpNamedPipes() throws Exception {
		Handle hPipe = checkHandle(Kernel32.INSTANCE.CreateNamedPipe(
			"\\\\.\\pipe\\GhidraGDB" /*lpName*/,
			Kernel32.PIPE_ACCESS_DUPLEX /*dwOpenMode*/,
			Kernel32.PIPE_TYPE_BYTE | Kernel32.PIPE_WAIT /*dwPipeMode*/,
			Kernel32.PIPE_UNLIMITED_INSTANCES /*nMaxInstances*/,
			1024 /*nOutBufferSize*/,
			1024 /*nInBufferSize*/,
			0 /*nDefaultTimeOut*/,
			null /*lpSecurityAttributes*/));

		try (PrintWriter writer = new PrintWriter(new HandleOutputStream(hPipe));
				BufferedReader reader =
					new BufferedReader(new InputStreamReader(new HandleInputStream(hPipe)))) {

			writer.println("-add-inferior");
			writer.flush();

			String line;
			while (null != (line = reader.readLine())) {
				System.out.println(line);
			}
		}
	}
}
