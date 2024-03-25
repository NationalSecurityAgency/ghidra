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
package ghidra.pty;

import java.io.*;

public class StreamPumper extends Thread {
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
