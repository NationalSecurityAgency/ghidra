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
package ghidra.app.util.bin.format.pdb2.pdbreader;

import java.io.IOException;
import java.io.Writer;

/**
 * Utils for PdbReader
 */
public class PdbReaderUtils {
	private static final String dashes =
		"------------------------------------------------------------\n";

	private PdbReaderUtils() {
		// Do nothing
	}

	public static void dumpHead(Writer writer, Object obj) throws IOException {
		String name = obj.getClass().getSimpleName();
		int len = name.length();
		writer.write(name + dashes.substring(len));
	}

	public static void dumpTail(Writer writer, Object obj) throws IOException {
		String name = obj.getClass().getSimpleName();
		int len = name.length();
		writer.write("End " + name + dashes.substring(len + 4));
	}

}
