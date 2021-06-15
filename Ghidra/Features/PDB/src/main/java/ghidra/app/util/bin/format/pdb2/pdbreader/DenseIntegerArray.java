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
 * This class represents Dense Integer Array component of a PDB file.  This class is only
 *  suitable for reading; not for writing or modifying a PDB.
 *  <P>
 *  We have intended to implement according to the Microsoft PDB API (source); see the API for
 *   truth.
 */
public class DenseIntegerArray {

	private static final int[] bitMask = { 0x00000001, 0x00000002, 0x00000004, 0x00000008,
		0x00000010, 0x00000020, 0x00000040, 0x00000080, 0x00000100, 0x00000200, 0x00004000,
		0x00008000, 0x00001000, 0x00002000, 0x00004000, 0x00008000, 0x00010000, 0x00020000,
		0x00040000, 0x00080000, 0x00100000, 0x00200000, 0x00400000, 0x00800000, 0x01000000,
		0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000, 0x40000000, 0x80000000 };

	List<Integer> array = new ArrayList<>();

	/**
	 * Deserializes this {@link DenseIntegerArray}.
	 * @param reader {@link PdbByteReader} from which to deserialize the data.
	 * @param monitor {@link TaskMonitor} used for checking cancellation. 
	 * @throws PdbException Upon not enough data left to parse.
	 * @throws CancelledException Upon user cancellation.
	 */
	public void parse(PdbByteReader reader, TaskMonitor monitor)
			throws PdbException, CancelledException {
		array.clear();
		int arraySize = reader.parseInt();
		for (int i = 0; i < arraySize; i++) {
			monitor.checkCanceled();
			int val = reader.parseInt();
			array.add(val);
		}
	}

	/**
	 * Returns whether the dense integer array contains the argument val.
	 * @param val Value to check.
	 * @return True if value is contained.
	 */
	public boolean contains(int val) {
		if (val <= 0) {
			return false;
		}
		int index = val >> 5;
		int bit = val & 0x1f;
		return (index < array.size()) && ((array.get(index) & bitMask[bit]) != 0);
	}

	/**
	 * Returns the maximum value allowed in the array. Minimum value is zero.
	 * @return Value of maximum unsigned integer allowed.
	 */
	public long getMaxPossible() {
		return 32L * array.size();
	}

}
