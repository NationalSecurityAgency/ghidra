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

/**
 * An individual PDB C13 Cross-Scope Import record
 */
public class C13CrossScopeImport {
	private int offsetObjectFilePath; // the module file; signed 32-bit
	private long numCrossReferences; // unsigned 32-bit
	private List<Long> referenceIds; // Array of unsigned 32-bit values

	public static int getBaseRecordSize() {
		return 8;
	}

	public C13CrossScopeImport(PdbByteReader reader) throws PdbException {
		offsetObjectFilePath = reader.parseInt();
		numCrossReferences = reader.parseUnsignedIntVal();
		referenceIds = new ArrayList<>();
		for (long i = 0; i < numCrossReferences; i++) {
			referenceIds.add(reader.parseUnsignedIntVal());
		}
	}

	/**
	 * Returns the offset to the module file pathname in the filename records
	 * @return the offset of the module file pathname
	 */
	public long getOffsetObjectFilePath() {
		return offsetObjectFilePath;
	}

	/**
	 * Returns the number of cross references
	 * @return the number of cross references
	 */
	public long getNumCrossReferences() {
		return numCrossReferences;
	}

	/**
	 * Returns the list of cross-references.  Not sure exactly what these are at this time
	 * @return the cross-references
	 */
	public List<Long> getReferenceIds() {
		return referenceIds;
	}

	@Override
	public String toString() {
		StringBuilder builder = new StringBuilder();
		builder.append(String.format("0x%08x, %5d", offsetObjectFilePath, numCrossReferences));
		for (Long id : referenceIds) {
			builder.append(String.format(" 0x%08x", id));
		}
		return builder.toString();
	}
}
