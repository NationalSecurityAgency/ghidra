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
package agent.gdb.pty;

import static org.junit.Assert.assertEquals;

import java.io.*;

public class AbstractPtyTest {
	public Thread pump(InputStream is, OutputStream os) {
		Thread t = new Thread(() -> {
			byte[] buf = new byte[1];
			while (true) {
				int len;
				try {
					len = is.read(buf);
					if (len == -1) {
						return;
					}
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

	public Thread runExitCheck(int expected, PtySession session) {
		Thread exitCheck = new Thread(() -> {
			while (true) {
				try {
					assertEquals("Early exit with wrong code", expected,
						session.waitExited());
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
}
