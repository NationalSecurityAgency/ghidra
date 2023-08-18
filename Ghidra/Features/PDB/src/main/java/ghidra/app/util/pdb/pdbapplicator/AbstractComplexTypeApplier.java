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
package ghidra.app.util.pdb.pdbapplicator;

import ghidra.app.util.SymbolPath;
import ghidra.app.util.SymbolPathParser;
import ghidra.app.util.bin.format.pdb2.pdbreader.RecordNumber;
import ghidra.app.util.bin.format.pdb2.pdbreader.type.AbstractComplexMsType;
import ghidra.app.util.pdb.PdbNamespaceUtils;

/**
 * Applier for {@link AbstractComplexMsType} types.
 */
public abstract class AbstractComplexTypeApplier extends MsTypeApplier {

	// Intended for: AbstractComplexMsType
	/**
	 * Constructor for complex type applier.
	 * @param applicator {@link DefaultPdbApplicator} for which this class is working.
	 */
	public AbstractComplexTypeApplier(DefaultPdbApplicator applicator) {
		super(applicator);
	}

	/**
	 * Returns the SymbolPath for the complex type parameter without using the record number
	 * @param type the MS complex PDB type
	 * @return the path
	 * @see #getFixedSymbolPath(AbstractComplexMsType type)
	 */
	SymbolPath getSymbolPath(AbstractComplexMsType type) {
		String fullPathName = type.getName();
		return new SymbolPath(SymbolPathParser.parse(fullPathName));
	}

	/**
	 * Returns the definition record for the specified complex type in case the record passed
	 *  in is only its forward reference
	 * @param mType the MS complex PDB type
	 * @param type the derivative complex type class
	 * @param <T> the derivative class template argument
	 * @return the path
	 */
	public <T extends AbstractComplexMsType> T getDefinitionType(AbstractComplexMsType mType,
			Class<T> type) {
		Integer num = applicator.getNumber(mType);
		Integer mappedIndex = applicator.getMappedComplexType(num);
		if (mappedIndex != null) {
			mType =
				applicator.getPdb().getTypeRecord(RecordNumber.typeRecordNumber(mappedIndex), type);
		}
		return type.cast(mType);
	}

	/**
	 * Returns the SymbolPath for the complex type.  This ensures that the SymbolPath pertains
	 *  to the definition type in situations where the record number of the definition (vs. that
	 *  of the forward reference) is needed for creation of the path
	 * @param type the MS complex PDB type
	 * @return the path
	 */
	//return mine or my def's (and set mine)
	SymbolPath getFixedSymbolPath(AbstractComplexMsType type) {
		SymbolPath path = getSymbolPath(type);
		Integer num = applicator.getNumber(type);
		Integer mappedIndex = applicator.getMappedComplexType(num);
		if (mappedIndex != null) {
			return PdbNamespaceUtils.convertToGhidraPathName(path, mappedIndex);
		}
		return PdbNamespaceUtils.convertToGhidraPathName(path, num);
	}

}
