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
 * Abstract class for PDB Type Index values.  Extensions control the size of the value that
 *  needs deserialized.
 */
public abstract class AbstractTypeIndex extends AbstractParsableItem {

	protected int indexVal;

	/**
	 * Returns the index value.
	 * @return The value of the index.  Defaults to zero if not parsed.
	 */
	public int get() {
		return indexVal;
	}

	/**
	 * Parses the index value from the {@link PdbByteReader}.
	 * @param reader {@link PdbByteReader} from which to read the value.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	public void parse(PdbByteReader reader) throws PdbException {
		indexVal = doParse(reader);
	}

	/**
	 * Parses the index value from the {@link PdbByteReader}.
	 * @param reader {@link PdbByteReader} from which to read the value.
	 * @return the type index value.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	protected abstract int doParse(PdbByteReader reader) throws PdbException;

}
