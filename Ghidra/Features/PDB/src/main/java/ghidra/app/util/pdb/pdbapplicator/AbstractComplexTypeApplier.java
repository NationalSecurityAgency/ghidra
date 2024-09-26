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
import ghidra.app.util.bin.format.pdb2.pdbreader.type.AbstractMsType;
import ghidra.app.util.pdb.PdbNamespaceUtils;
import ghidra.util.Msg;
import mdemangler.*;
import mdemangler.datatype.MDDataType;

/**
 * Applier for {@link AbstractComplexMsType} types.
 */
public abstract class AbstractComplexTypeApplier extends MsDataTypeApplier {

	// Intended for: AbstractComplexMsType
	/**
	 * Constructor for complex type applier
	 * @param applicator {@link DefaultPdbApplicator} for which this class is working
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
		return getSymbolPath(type.getName(), type.getMangledName());
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
		mType = applicator.getMappedTypeRecord(mType.getRecordNumber(), type);
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
		RecordNumber mappedNumber = applicator.getMappedRecordNumber(type.getRecordNumber());
		Integer num = mappedNumber.getNumber();
		return PdbNamespaceUtils.convertToGhidraPathName(path, num);
	}

	/**
	 * Returns the symbol path for the data type referenced by the type record number provided
	 * @param applicator the applicator
	 * @param recordNumber the record number
	 * @return the symbol path
	 */
	public static SymbolPath getSymbolPath(DefaultPdbApplicator applicator,
			RecordNumber recordNumber) {
		AbstractMsType t = applicator.getTypeRecord(recordNumber);
		if (!(t instanceof AbstractComplexMsType ct)) {
			return null;
		}
		CppCompositeType cpp = applicator.getClassType(ct);
		if (cpp != null) {
			return cpp.getSymbolPath();
		}
		return getSymbolPath(ct.getName(), ct.getMangledName());
	}

	private static SymbolPath getSymbolPath(String name, String mangledName) {
		SymbolPath symbolPath = null;
		// We added logic to check the mangled name first because we found some LLVM "lambda"
		//  symbols where the regular name was a generic "<lambda_0>" with a namespace, but this
		//  often had a member that also lambda that was marked with the exact same namespace/name
		//  as the containing structure.  We found that the mangled names had more accurate and
		//  distinguished lambda numbers.
		if (mangledName != null) {
			symbolPath = getSymbolPathFromMangledTypeName(mangledName, name);
		}
		if (symbolPath == null) {
			symbolPath =
				MDMangUtils.standarizeSymbolPathUnderscores(
					new SymbolPath(SymbolPathParser.parse(name)));
		}
		return symbolPath;
	}

	private static SymbolPath getSymbolPathFromMangledTypeName(String mangledString,
			String fullPathName) {
		MDMang demangler = new MDMangGhidra();
		try {
			MDDataType mdDataType = demangler.demangleType(mangledString, true);
			// 20240626:  Ultimately, it might be better to retrieve the Demangled-type to pass
			// to the DemangledObject.createNamespace() method to convert to a true Ghidra
			// Namespace that are flagged as functions (not capable at this time) or types or
			// raw namespace nodes.  Note, however, that the  Demangler is still weak in this
			// area as there are codes that we still not know how to interpret.
			return MDMangUtils.consolidateSymbolPath(mdDataType, fullPathName, true);
			// Could consider the following simplification method instead
			// return MDMangUtils.getSimpleSymbolPath(mdDataType);
		}
		catch (MDException e) {
			// Couldn't demangle.
			// Message might cause too much noise (we have a fallback, above, to use the regular
			// name, but this could cause an error... see the notes above about why a mangled
			// name is checked first).
			Msg.info(AbstractComplexTypeApplier.class,
				"PDB issue dmangling type name: " + e.getMessage() + " for : " + mangledString);
		}
		return null;
	}

}
