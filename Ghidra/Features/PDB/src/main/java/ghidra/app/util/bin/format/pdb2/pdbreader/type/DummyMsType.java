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
import ghidra.app.util.bin.format.pdb2.pdbreader.PdbByteReader;

/**
 * Important: This is not a real type.  This "Dummy" type has been created to help with testing.
 */
public class DummyMsType extends AbstractMsType {

	/** This should not be a the PDB_ID value of a real AbstractMsType. */
	public static final int PDB_ID = 0xff00;

	String typeNamePrefix;

	/**
	 * Constructor for this type.
	 * @param pdb {@link AbstractPdb} to which this type belongs.
	 * @param reader {@link PdbByteReader} from which this type is deserialized.
	 * @param typeNamePrefix Type name prefix for this dummy type.
	 */
	public DummyMsType(AbstractPdb pdb, PdbByteReader reader, String typeNamePrefix) {
		super(pdb, reader);
		this.typeNamePrefix = typeNamePrefix;
	}

	/**
	 * Constructor for this type.
	 * @param pdb {@link AbstractPdb} to which this type belongs.
	 * @param reader {@link PdbByteReader} from which this type is deserialized.
	 */
	public DummyMsType(AbstractPdb pdb, PdbByteReader reader) {
		super(pdb, reader);
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
		builder.insert(0, "DummyMsType");
		if (typeNamePrefix != null) {
			builder.insert(0, typeNamePrefix);
		}
	}

}
