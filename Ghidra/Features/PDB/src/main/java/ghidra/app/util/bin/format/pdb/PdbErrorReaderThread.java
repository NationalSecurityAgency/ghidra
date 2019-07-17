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
package ghidra.app.util.bin.format.pdb;

import java.io.*;

import ghidra.util.Msg;

class PdbErrorReaderThread extends Thread {
	private InputStream err;
	private StringBuffer errbuf = new StringBuffer();

	PdbErrorReaderThread(InputStream err) {
		super("PdbErrorStreamReaderThread");
		this.err = err;
	}

	boolean hasErrors() {
		return errbuf.length() != 0 && errbuf.indexOf("ERROR") >= 0;
	}

	boolean hasWarnings() {
		return errbuf.length() != 0 && errbuf.indexOf("WARNING") >= 0;
	}

	String getErrorAndWarningMessages() {
		if (errbuf.length() == 0) {
			return null;
		}
		return errbuf.toString();
	}

	@Override
	public void run() {
		try (BufferedReader reader = new BufferedReader(new InputStreamReader(err))) {
			String line = null;
			while ((line = reader.readLine()) != null) {
				errbuf.append(line);
				errbuf.append('\n');
			}
		}
		catch (IOException e) {
			Msg.error(this, "Failed to read error stream.");
		}
	}
}
