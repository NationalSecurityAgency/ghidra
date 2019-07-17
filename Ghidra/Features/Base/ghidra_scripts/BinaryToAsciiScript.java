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
//Converts a binary file into an ascii hex file.
//@category Conversion

import ghidra.app.script.GhidraScript;
import ghidra.util.Conv;

import java.io.*;


public class BinaryToAsciiScript extends GhidraScript {

	@Override
	public void run() throws Exception {
		File inputBinaryFile = askFile("Select Binary File", "Binary File");

		if (!inputBinaryFile.exists()) {
			popup(inputBinaryFile.getAbsolutePath() + " does not exist.");
			return;
		}

		File outAsciiFile = askFile("Select Ascii File", "Ascii File");

		if (inputBinaryFile.equals(outAsciiFile)) {
			popup("Input file and output file are the same. "+inputBinaryFile.getAbsolutePath());
			return;
		}

		if (outAsciiFile.exists()) {
			if (!askYesNo("Ascii File Already Exists", "The ascii file already exists.\nDo you want to overwrite it?")) {
				return;
			}
		}

		int bytesPerLine = askInt("Bytes per Line", "How many ascii bytes per line?");

		if (bytesPerLine < 1) {
			popup("Invalid bytes per line quantity: " + bytesPerLine + ".\n " +
					"Value must be greater than zero.");
			return;
		}

		InputStream in = new FileInputStream(inputBinaryFile);

		PrintWriter out = new PrintWriter(outAsciiFile);

		byte [] buffer = new byte[4096];

		int bytesWritten = 0;
		while (true) {
			if (monitor.isCancelled()) {
				break;
			}

			int nRead = in.read(buffer);

			if (nRead == -1) {
				break;
			}

			for (int i = 0 ; i < nRead ; ++i) {
				if (monitor.isCancelled()) {
					break;
				}

				if (bytesWritten > 0 && (bytesWritten % bytesPerLine) == 0) {
					out.append('\n');
				}

				out.write( Conv.toHexString(buffer[i]) );

				++bytesWritten;
			}
		}

		in.close();
		out.close();
	}

}
