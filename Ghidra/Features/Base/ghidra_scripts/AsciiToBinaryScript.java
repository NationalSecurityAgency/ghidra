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
//Converts an ascii hex file into binary file. Works for files with spaces and without. Assumes hex bytes are zero padded so all values are two bytes long.
//@category Conversion

import ghidra.app.script.GhidraScript;

import java.io.*;

public class AsciiToBinaryScript extends GhidraScript {

	private static final String EMPTY_STRING = "";
	private static final String SPACE = " ";

	@Override
	public void run() throws Exception {
		File inAsciiFile = askFile("Select Ascii File", "Ascii File");

		if (!inAsciiFile.exists()) {
			popup(inAsciiFile.getAbsolutePath() + " does not exist.");
			return;
		}

		File outBinaryFile = askFile("Select Binary File", "Binary File");

		if (outBinaryFile.equals(inAsciiFile)) {
			popup("Input file and output file are the same. Please choose a different file for the output." +
				inAsciiFile.getAbsolutePath());
			return;
		}

		if (outBinaryFile.exists()) {
			if (!askYesNo("Binary File Already Exists",
				"The binary file already exists.\nDo you want to overwrite it?")) {
				return;
			}
		}

		BufferedReader in = new BufferedReader(new FileReader(inAsciiFile));
		OutputStream out = new FileOutputStream(outBinaryFile);

		while (true) {
			if (monitor.isCancelled()) {
				break;
			}

			String line = in.readLine();
			if (line == null) {
				break;
			}

			line = line.replace(SPACE, EMPTY_STRING);

			int length = line.length();
			for (int i = 0; i < length; i += 2) {
				if (monitor.isCancelled()) {
					break;
				}

				String asciiByte = line.substring(i, i + 2);
				int value = Integer.parseInt(asciiByte, 16);
				out.write(value);
			}
		}

		in.close();
		out.close();
	}

}
