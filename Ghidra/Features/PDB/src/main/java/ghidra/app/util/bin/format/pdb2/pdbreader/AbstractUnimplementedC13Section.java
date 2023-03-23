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

import ghidra.util.task.TaskMonitor;

/**
 * Abstract class for C13 Sections which do not yet have a good implementation.
 * Class exists to output the fact (in a dump) that data of this type has been encountered.
 */
abstract class AbstractUnimplementedC13Section extends C13Section {

	private PdbByteReader myReader = null;

	protected AbstractUnimplementedC13Section(PdbByteReader reader, boolean ignore,
			TaskMonitor monitor) {
		super(ignore);
		myReader = reader;
	}

	@Override
	public String toString() {
		return getClass().getSimpleName();
	}

	@Override
	void dump(Writer writer) throws IOException {
		String n = getClass().getSimpleName();
		int len = n.length();
		writer.write(n + dashes.substring(len));
		writer.write("***NOT IMPLEMENTED***  Bytes follow...\n");
		writer.write(myReader.dump());
		writer.write("\n");
		writer.write("End " + n + dashes.substring(len + 4));
	}
}
