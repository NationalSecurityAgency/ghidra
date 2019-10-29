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
package ghidra.app.util.disassemble;

import ghidra.util.Msg;

import java.io.*;

public class ExternalStreamHandler extends Thread {
	private InputStream inStream;

	ExternalStreamHandler(InputStream inStream) {
		this.inStream = inStream;
	}

	@Override
	public void run() {
		try {
			InputStreamReader inStreamReader = new InputStreamReader(inStream);
			BufferedReader buffReader = new BufferedReader(inStreamReader);
			String line;
			while ((line = buffReader.readLine()) != null) {
				Msg.error(ExternalDisassemblyFieldFactory.class, "Error in Disassembler: " + line);
			}
		}
		catch (IOException ioe) {
			ioe.printStackTrace();
		}
	}
}
