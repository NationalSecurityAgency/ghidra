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
package ghidra.pdb.pdbreader;

import ghidra.pdb.*;

/**
 * Abstract class for PDB Offset values.  Extensions control the size of the value that
 *  needs deserialized.
 */
public abstract class AbstractOffset extends AbstractParsableItem {

	protected int offsetVal;

	/**
	 * Returns the offset value.
	 * @return Offset value.  Defaults to zero if not parsed.
	 */
	public int get() {
		return offsetVal;
	}

	/**
	 * Parses the offset value from the {@link PdbByteReader}.
	 * @param reader {@link PdbByteReader}.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	public void parse(PdbByteReader reader) throws PdbException {
		offsetVal = doParse(reader);
	}

	/**
	 * Parses the offset value from the {@link PdbByteReader}.
	 * @param reader {@link PdbByteReader}.
	 * @return the offset value.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	protected abstract int doParse(PdbByteReader reader) throws PdbException;

}
