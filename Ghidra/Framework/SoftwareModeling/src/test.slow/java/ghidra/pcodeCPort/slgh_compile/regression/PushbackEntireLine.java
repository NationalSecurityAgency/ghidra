/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.pcodeCPort.slgh_compile.regression;

import java.io.BufferedReader;
import java.io.IOException;

public class PushbackEntireLine {
	private final BufferedReader reader;
	private String line = null;

	public PushbackEntireLine(BufferedReader reader) {
		this.reader = reader;
	}

	public synchronized String readLine() throws IOException {
		if (line != null) {
			String tmp = line;
			line = null;
			return tmp;
		}
		return reader.readLine();
	}

	public synchronized void putbackLine(String pushedLine) throws IOException {
		if (line != null) {
			throw new IOException("can only putback one line");
		}
		line = pushedLine;
	}

	public void close() throws IOException {
		reader.close();
	}
}
