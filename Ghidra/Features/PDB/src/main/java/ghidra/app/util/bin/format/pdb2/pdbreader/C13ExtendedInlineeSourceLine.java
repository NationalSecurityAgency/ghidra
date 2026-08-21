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

import java.util.ArrayList;
import java.util.List;

import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * An extended version of the PDB C13 inlinee source line record that has extra file IDs
 */
public class C13ExtendedInlineeSourceLine extends C13InlineeSourceLine {

	static int getBaseRecordSize() {
		return 16;
	}

	private List<Integer> extraFileIds = new ArrayList<>(); // array of longs

	C13ExtendedInlineeSourceLine(PdbByteReader reader, TaskMonitor monitor)
			throws PdbException, CancelledException {
		super(reader);
		long numExtraFiles = reader.parseUnsignedIntVal(); // unsigned int
		for (long i = 0; i < numExtraFiles; i++) {
			monitor.checkCancelled();
			extraFileIds.add(reader.parseInt());
		}
	}

	/**
	 * Returns the number of extra file IDs
	 * @return the number
	 */
	public int getNumExtraFileIds() {
		return extraFileIds.size();
	}

	/**
	 * Returns the list of extra file IDs
	 * @return the extra file IDs
	 */
	public List<Integer> getExtraFileIds() {
		return extraFileIds;
	}

	@Override
	public String toString() {
		StringBuilder builder = new StringBuilder();
		builder.append(String.format("0x%09x, 0x%06x, %d", inlinee, fileId, sourceLineNum));
		for (Integer id : extraFileIds) {
			builder.append(String.format(" 0x%06x", id));
		}
		return builder.toString();
	}
}
