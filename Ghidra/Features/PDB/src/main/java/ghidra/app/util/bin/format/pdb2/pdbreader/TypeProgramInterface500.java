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

import java.io.IOException;
import java.io.Writer;

/**
 * This class is the version of {@link AbstractTypeProgramInterface} for Microsoft v5.00 PDB.
 */
public class TypeProgramInterface500 extends AbstractTypeProgramInterface {

	//==============================================================================================
	// Internals
	//==============================================================================================
	protected int hashStreamNumber;

	//==============================================================================================
	// API
	//==============================================================================================
	/**
	 * Constructor.
	 * @param pdb {@link AbstractPdb} that owns this {@link AbstractTypeProgramInterface}.
	 * @param recordCategory the RecordCategory of these records.
	 * @param streamNumber The stream number that contains the {@link AbstractTypeProgramInterface}.
	 */
	public TypeProgramInterface500(AbstractPdb pdb, RecordCategory recordCategory,
			int streamNumber) {
		super(pdb, recordCategory, streamNumber);
	}

	//==============================================================================================
	// Abstract Methods
	//==============================================================================================
	@Override
	protected void deserializeHeader(PdbByteReader reader) throws PdbException {
		versionNumber = reader.parseInt();
		headerLength = 20; // TODO: confirm this with real data.  Could be 18?
		typeIndexMin = reader.parseInt();
		typeIndexMaxExclusive = reader.parseInt();
		dataLength = reader.parseInt();
		hashStreamNumber = reader.parseUnsignedShortVal();
		hash.initHeader200500(hashStreamNumber, typeIndexMin, typeIndexMaxExclusive);
	}

	@Override
	protected void dumpHeader(Writer writer) throws IOException {
		StringBuilder builder = new StringBuilder();
		builder.append("\nversionNumber: ");
		builder.append(versionNumber);
		builder.append("\ntypeIndexMin: ");
		builder.append(typeIndexMin);
		builder.append("\ntypeIndexMaxExclusive: ");
		builder.append(typeIndexMaxExclusive);
		builder.append("\ndataLength: ");
		builder.append(dataLength);
		builder.append("\nhashStreamNumber: ");
		builder.append(hashStreamNumber);
		writer.write(builder.toString());
	}

	//==============================================================================================
	// Package-Protected Internals
	//==============================================================================================
	/**
	 * IMPORTANT: This method is for testing only.  It allows us to set a basic object.
	 *  Note: not all values are initialized.  This is a dummy constructor used to create a dummy
	 *  {@link AbstractTypeProgramInterface}.
	 *  Note: not all values are initialized.
	 * @param pdb {@link AbstractPdb} that owns this {@link AbstractTypeProgramInterface}.
	 * @param typeIndexMin The IndexMin to set/use.
	 * @param typeIndexMaxExclusive One greater than the MaxIndex to set/use.
	 */
	TypeProgramInterface500(AbstractPdb pdb, int typeIndexMin, int typeIndexMaxExclusive) {
		super(pdb, typeIndexMin, typeIndexMaxExclusive);
	}

}
