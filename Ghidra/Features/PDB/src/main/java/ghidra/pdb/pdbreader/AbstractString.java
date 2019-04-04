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
 * Abstract class for PDB Strings.  Extensions control what String encoding is allowed and how
 *  the String is deserialized.
 */
public abstract class AbstractString extends AbstractParsableItem {

	//==============================================================================================
	// Internals
	//==============================================================================================
	protected String string = "";

	//==============================================================================================
	// API
	//==============================================================================================
	/**
	 * Returns the string value.
	 * @return {@link String} value.  Defaults to empty String if not parsed.
	 */
	public String get() {
		return string;
	}

	@Override
	public void emit(StringBuilder builder) {
		builder.append(string);
	}

	/**
	 * Parses the string from the {@link PdbByteReader}.
	 * @param reader {@link PdbByteReader}.
	 * @throws PdbException upon error parsing the string.
	 */
	public void parse(PdbByteReader reader) throws PdbException {
		string = doParse(reader);
	}

	//==============================================================================================
	// Abstract Methods
	//==============================================================================================
	/**
	 * Parses the string from the {@link PdbByteReader}.
	 * @param reader {@link PdbByteReader}.
	 * @return the {@link String}. 
	 * @throws PdbException upon error parsing the string.
	 */
	protected abstract String doParse(PdbByteReader reader) throws PdbException;

}
