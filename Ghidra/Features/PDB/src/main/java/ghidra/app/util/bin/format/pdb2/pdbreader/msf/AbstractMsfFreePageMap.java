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
package ghidra.app.util.bin.format.pdb2.pdbreader.msf;

import java.io.IOException;
import java.util.*;

import ghidra.util.LittleEndianDataConverter;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * This class is the Free Page Map for the Multi-Stream Format File (see Microsoft API).  The
 *  Free Page Map is a bit-encoding of whether a page within the {@link AbstractMsf} is
 *  currently used--for purposes of reusing available pages.
 * <P>
 * This class was crafted to take the place of the formal Free Page Map in a complete 
 *  (read/write/modify) solution, but might not need to be used for a "reader" technology.
 * <P>
 * NOTE: This implementation is incomplete: we are not processing or accessing the bits yet.
 * <P>
 * ENGINEERING PATH: Use java.util.BitSet for storage after processing.  Could probably eliminate
 *  the {@code List<Integer> map} storage.
 */
abstract class AbstractMsfFreePageMap {

	//==============================================================================================
	// Internals
	//==============================================================================================
	// Make sure the integral type used (e.g., Integer) is the same on the next two lines.
	private List<Integer> map = new ArrayList<>();
	protected static final int MAP_FIELD_SIZE = Integer.BYTES;

	protected AbstractMsf msf;

	//==============================================================================================
	// Package-Protected Internals
	//==============================================================================================
	/**
	 * Constructor.
	 * @param msf The {@link AbstractMsf} to which this class belongs.
	 */
	AbstractMsfFreePageMap(AbstractMsf msf) {
		this.msf = msf;
	}

	/**
	 * Debug method to dump some of the internals of this class.
	 * @return Data dumped in a pretty format.
	 */
	String dump() {
		StringBuilder builder = new StringBuilder();
		builder.append("------------------------------------------------------------");
		builder.append("\npageSize: ");
		builder.append(msf.getPageSize());
		builder.append("\nMSFHeaderBig: ");
		builder.append(isBig());
		for (int i = 0; i < map.size(); i++) {
			builder.append(String.format("\n[%d]: ", i));
			builder.append(map.get(i));
		}
		builder.append("\n------------------------------------------------------------");
		return builder.toString();
	}

	//==============================================================================================
	// Abstract Methods
	//==============================================================================================
	/**
	 * Method used to deserialize this class from disk.
	 * @param monitor {@link TaskMonitor} used for checking cancellation.
	 * @throws IOException On file seek or read, invalid parameters, bad file configuration, or
	 *  inability to read required bytes.
	 * @throws CancelledException Upon user cancellation.
	 */
	abstract void deserialize(TaskMonitor monitor) throws IOException, CancelledException;

	/**
	 * Method indicating whether the Free Page Map is a "Big" Free Page Map.  Currently, we have
	 * at least two types extending this class.  One is "Big" (the newer v7.00) and the other is
	 * not.  The {@link #dump()} method makes use of this method. 
	 * @return true if it is a "Big" version of this class.
	 */
	abstract boolean isBig();

	//==============================================================================================
	// Internal Data Methods
	//==============================================================================================
	/**
	 * Internal method for adding a records to the map from the {@code byte[]} argument.
	 * @param bytes The {@code byte[]} containing the data.
	 * @param monitor {@link TaskMonitor} used for checking cancellation.
	 * @throws CancelledException Upon user cancellation.
	 */
	protected void addMap(byte[] bytes, TaskMonitor monitor) throws CancelledException {
		// TODO: If we implement FreePageMap further, then consider passing in a PdbByteReader
		//  and using the reader to parse the appropriate Integral types.
		for (int index = 0; index < bytes.length - MAP_FIELD_SIZE; index += MAP_FIELD_SIZE) {
			monitor.checkCanceled();
			byte[] selectedBytes = Arrays.copyOfRange(bytes, index, index + MAP_FIELD_SIZE);
			map.add(LittleEndianDataConverter.INSTANCE.getInt(selectedBytes));
		}
	}

}
