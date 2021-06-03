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

/**
 * This class represents a Symbol Hash Record used by Global Symbol Information and Public
 * Symbol Information.
 * @see GlobalSymbolInformation
 */
public class SymbolHashRecord implements Comparable<SymbolHashRecord> {

	private long offsetVal;
	private int referenceCount;

	/**
	 * Parses the contents of of this record.
	 * @param reader {@link PdbByteReader} from which to deserialize the data.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	public void parse(PdbByteReader reader) throws PdbException {
		// MSFT does a bunch of pointer gyrations for this "+ 1"
		offsetVal = reader.parseUnsignedIntVal() + 1;
		referenceCount = reader.parseInt();
	}

	/**
	 * Returns the offset component of the MSFT symbol hash record.
	 * @return offset component of the hash record.
	 */
	public long getOffset() {
		return offsetVal;
	}

	/**
	 * Returns the reference count component of the MSFT symbol hash record.
	 * @return reference count component of the hash record.
	 */
	public long getReferenceCount() {
		return referenceCount;
	}

	@Override
	public int compareTo(SymbolHashRecord o) {
		return (int) ((offsetVal != o.getOffset()) ? offsetVal - o.getOffset()
				: referenceCount - o.getReferenceCount());
	}

}
