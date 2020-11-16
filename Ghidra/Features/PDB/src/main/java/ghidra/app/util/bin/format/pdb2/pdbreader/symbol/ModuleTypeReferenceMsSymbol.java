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
package ghidra.app.util.bin.format.pdb2.pdbreader.symbol;

import ghidra.app.util.bin.format.pdb2.pdbreader.*;

/**
 * This class represents the Module Type Reference symbol.
 * <P>
 * Note: we do not necessarily understand each of these symbol type classes.  Refer to the
 *  base class for more information.
 */
public class ModuleTypeReferenceMsSymbol extends AbstractMsSymbol {

	public static final int PDB_ID = 0x115f;

	private boolean doesNotReferenceAnyType;
	private boolean referencesZ7PchTypes;
	private boolean containsZ7PchTypes;
	private boolean containsZ7TypeInformation;
	private boolean containsZiOrZITypeInformation;
	private boolean containsOtherModuleTypeReferences;

	private int typeReferenceStreamNumber = -1;
	private int typeIdStreamNumber = -1; // Not sure if this is named appropriately
	private int moduleContainingReferencedPchTypes = -1;
	private int moduleSharingReferencedTypes = -1;

	/**
	 * Constructor for this symbol.
	 * @param pdb {@link AbstractPdb} to which this symbol belongs.
	 * @param reader {@link PdbByteReader} from which this symbol is deserialized.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	public ModuleTypeReferenceMsSymbol(AbstractPdb pdb, PdbByteReader reader) throws PdbException {
		super(pdb, reader);
		long flags = reader.parseUnsignedIntVal();
		processFlags(flags);
		int val0 = reader.parseUnsignedShortVal();
		int val1 = reader.parseUnsignedShortVal();
		if (containsZ7TypeInformation) {
			typeReferenceStreamNumber = val0;
			if (referencesZ7PchTypes) {
				moduleContainingReferencedPchTypes = val1 + 1;
			}
		}
		else if (!doesNotReferenceAnyType) {
			if (containsZiOrZITypeInformation) {
				typeReferenceStreamNumber = val0;
				typeIdStreamNumber = val1;
			}
			if (containsOtherModuleTypeReferences) {
				moduleSharingReferencedTypes = val0 + 1;
			}
		}
		reader.align4();
	}

	@Override
	public int getPdbId() {
		return PDB_ID;
	}

	@Override
	public void emit(StringBuilder builder) {
		builder.append(String.format("%s: ", getSymbolTypeName()));
		if (doesNotReferenceAnyType) {
			builder.append("No TypeRef");
		}
		else if (containsZ7TypeInformation) {
			builder.append(
				String.format("/Z7 TypeRef, StreamNumber=%04X", typeReferenceStreamNumber));
			if (containsZ7PchTypes) {
				builder.append(", own PCH types");
			}
			if (referencesZ7PchTypes) {
				builder.append(String.format(", reference PCH types in Module %04X",
					moduleContainingReferencedPchTypes));
			}
		}
		else {
			builder.append("/Zi TypeRef");
			if (containsZiOrZITypeInformation) {
				builder.append(String.format(", StreamNumber=%04X (type), StreamNumber=%04X (ID)",
					typeReferenceStreamNumber, typeIdStreamNumber));
			}
			if (containsOtherModuleTypeReferences) {
				builder.append(
					String.format(", shared with Module %04X", moduleSharingReferencedTypes));
			}
		}
		builder.append("\n");
	}

	@Override
	protected String getSymbolTypeName() {
		return "MODTYPEREF";
	}

	private void processFlags(long flags) {
		doesNotReferenceAnyType = ((flags & 0x01) == 0x01);
		flags >>= 1;
		referencesZ7PchTypes = ((flags & 0x01) == 0x01);
		flags >>= 1;
		containsZ7PchTypes = ((flags & 0x01) == 0x01);
		flags >>= 1;
		containsZ7TypeInformation = ((flags & 0x01) == 0x01);
		flags >>= 1;
		containsZiOrZITypeInformation = ((flags & 0x01) == 0x01);
		flags >>= 1;
		containsOtherModuleTypeReferences = ((flags & 0x01) == 0x01);
	}

}
