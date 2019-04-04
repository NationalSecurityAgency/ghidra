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
package ghidra.pdb.pdbreader.type;

import ghidra.pdb.PdbByteReader;
import ghidra.pdb.pdbreader.AbstractPdb;

public class Cobol1MsType extends AbstractMsType {

	public static final int PDB_ID = 0x000c;

	// TODO: This is made up data.  API and examples are unknown.
	private byte[] data;

	/**
	 * Constructor for this type.
	 * @param pdb {@link AbstractPdb} to which this type belongs.
	 * @param reader {@link PdbByteReader} from which this type is deserialized.
	 */
	public Cobol1MsType(AbstractPdb pdb, PdbByteReader reader) {
		super(pdb, reader);
		//System.out.println(reader.dump());
		// TODO: This is made up data.  API and examples are unknown.
		data = reader.parseBytesRemaining();
	}

	@Override
	public int getPdbId() {
		return PDB_ID;
	}

	@Override
	public void emit(StringBuilder builder, Bind bind) {
		builder.append("Cobol1MsType\n");
		builder.append(String.format("  additional data length: %d\n", data.length));
	}

}
