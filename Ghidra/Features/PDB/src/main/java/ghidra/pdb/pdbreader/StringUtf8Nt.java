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

import ghidra.pdb.PdbByteReader;
import ghidra.pdb.PdbException;

/**
 * Class extending {@link AbstractString} that has a UTF-8 String encoding with a null terminator.
 */
public class StringUtf8Nt extends AbstractString {

	/**
	 * Constructor.
	 * @param pdb {@link AbstractPdb} to which this type belongs.
	 */
	public StringUtf8Nt(AbstractPdb pdb) {
		super(pdb);
	}

	@Override
	protected String doParse(PdbByteReader reader) throws PdbException {
		return reader.parseNullTerminatedUtf8String();
	}

}
