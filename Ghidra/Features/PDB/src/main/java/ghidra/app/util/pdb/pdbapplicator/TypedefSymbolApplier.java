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
import ghidra.app.util.bin.format.pdb2.pdbreader.*;
import ghidra.app.util.bin.format.pdb2.pdbreader.symbol.AbstractMsSymbol;
import ghidra.app.util.bin.format.pdb2.pdbreader.symbol.AbstractUserDefinedTypeMsSymbol;
import ghidra.app.util.bin.format.pdb2.pdbreader.type.AbstractComplexMsType;
import ghidra.app.util.bin.format.pdb2.pdbreader.type.AbstractMsType;
import ghidra.program.model.data.*;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;

/**
 * Applier for {@link AbstractUserDefinedTypeMsSymbol} symbols.
 */
public class TypedefSymbolApplier extends MsSymbolApplier {

	private DataType resolvedDataType = null;
	private AbstractUserDefinedTypeMsSymbol udtSymbol;

	/**
	 * Constructor
	 * @param applicator the {@link DefaultPdbApplicator} for which we are working.
	 * @param iter the Iterator containing the symbol sequence being processed
	 */
	public TypedefSymbolApplier(DefaultPdbApplicator applicator, MsSymbolIterator iter) {
		super(applicator, iter);
		AbstractMsSymbol abstractSymbol = iter.next();
		if (!(abstractSymbol instanceof AbstractUserDefinedTypeMsSymbol)) {
			throw new AssertException(
				"Invalid symbol type: " + abstractSymbol.getClass().getSimpleName());
		}
		udtSymbol = (AbstractUserDefinedTypeMsSymbol) abstractSymbol;
	}

	@Override
	void applyTo(MsSymbolApplier applyToApplier) {
		// Do nothing
	}

	@Override
	void apply() throws PdbException, CancelledException {
		resolvedDataType = applyUserDefinedTypeMsSymbol(udtSymbol);
	}

	/**
	 * Returns the name.
	 * @return Name.
	 */
	String getName() {
		return udtSymbol.getName();
	}

	/**
	 * Returns the type record number.
	 * @return Type record number.
	 */
	RecordNumber getTypeRecordNumber() {
		return udtSymbol.getTypeRecordNumber();
	}

	DataType getResolvedDataType() throws PdbException {
		if (resolvedDataType == null) {
			throw new PdbException("Data type not resolved");
		}
		return resolvedDataType;
	}

	// Typedefs
	private DataType applyUserDefinedTypeMsSymbol(AbstractUserDefinedTypeMsSymbol symbol)
			throws CancelledException, PdbException {

		String name = symbol.getName();

		AbstractMsType mType = applicator.getPdb().getTypeRecord(getTypeRecordNumber());
		MsTypeApplier applier = applicator.getTypeApplier(symbol.getTypeRecordNumber());
		// TODO:... NOT SURE IF WILL ALWAYS BE A DATATYPE OR WILL BE A VARIABLE OR ????
		if (applier == null) {
			return null;
		}
		DataType dataType = applicator.getCompletedDataType(getTypeRecordNumber());
		if (dataType == null) {
			return null;
		}

		// This code (for Composites and Enums) circumvents a collision on the names with the
		//  compromise that we do not store the TypeDefDataType into the DataTypeManager.
		//  Another issue is that we likely already have the DataType in the DataTypeManager,
		//  but the TypeDefDataType also wants to create it... we would need a mechanism to
		//  create a TypeDefDataType which uses an existing underlying DataType.
		// Note, too, that we do not compare name with dataType.getName() as the latter does not
		//  contain namespace information.
		if (mType instanceof AbstractComplexMsType) {
			if (name.equals(mType.getName())) {
				return dataType;
			}
		}

		SymbolPath symbolPath = new SymbolPath(name);
		CategoryPath categoryPath =
			applicator.getTypedefsCategory(applicator.getCurrentModuleNumber(), symbolPath);
		DataType typedef = new TypedefDataType(categoryPath.getParent(), categoryPath.getName(),
			dataType, applicator.getDataTypeManager());

		return applicator.resolve(typedef);
	}

}
