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
package ghidra.app.util.bin.format.pdb2.pdbreader.type;

import ghidra.app.util.bin.format.pdb2.pdbreader.AbstractPdb;

/**
 * Important: This is not a real type.  This "Bad" type takes the place of a type that has
 *  encountered a parsing issue vis-a-vis a PdbException.
 */
public class BadMsType extends AbstractMsType implements MsTypeField {

	/** This should not be a the PDB_ID value of a real AbstractMsType. */
	public static final int PDB_ID = 0xff01;

	// Pdb ID  that had an issue;
	int badPdbId;

	/**
	 * Constructor for this "Bad" type.
	 * @param pdb {@link AbstractPdb} to which this type belongs.
	 * @param badPdbId The type ID for which an error occurred.
	 */
	public BadMsType(AbstractPdb pdb, int badPdbId) {
		super(pdb, null);
		this.badPdbId = badPdbId;
	}

	@Override
	public int getPdbId() {
		return PDB_ID;
	}

	@Override
	public void emit(StringBuilder builder, Bind bind) {
		if (builder.length() != 0) {
			builder.insert(0, " ");
		}
		builder.insert(0, String.format("BAD_TYPE: ID=0X%04X", badPdbId));
	}

}
