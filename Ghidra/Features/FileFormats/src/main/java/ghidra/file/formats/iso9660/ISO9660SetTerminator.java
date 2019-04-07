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
package ghidra.file.formats.iso9660;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

import java.io.IOException;

/**
 * The terminator flag to note the end of the set of volume descriptors
 * on this ISO
 */
public class ISO9660SetTerminator extends ISO9660BaseVolume {

	private long endVolumeIndex;

	public ISO9660SetTerminator(BinaryReader reader) throws IOException {

		super(reader);
		endVolumeIndex = reader.getPointerIndex();

	}

	public long getEndVolumeIndex() {
		return endVolumeIndex;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure struc = new StructureDataType("ISO9600SetTerminator", 0);
		struc.add(BYTE, "Type", "Volume Descriptor Type");
		struc.add(new ArrayDataType(BYTE, super.getIdentifier().length, 1), "Identifier",
			"Identifier");
		struc.add(BYTE, "Version", "Volume Descriptor Version");

		return struc;
	}

}
