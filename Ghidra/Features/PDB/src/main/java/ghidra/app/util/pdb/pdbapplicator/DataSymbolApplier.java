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

import ghidra.app.util.bin.format.pdb2.pdbreader.*;
import ghidra.app.util.bin.format.pdb2.pdbreader.symbol.AbstractDataMsSymbol;
import ghidra.app.util.bin.format.pdb2.pdbreader.symbol.AbstractMsSymbol;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.DumbMemBufferImpl;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;

/**
 * Applier for {@link AbstractDataMsSymbol} symbols.
 */
public class DataSymbolApplier extends MsSymbolApplier
		implements DirectSymbolApplier, NestableSymbolApplier {

	private AbstractDataMsSymbol symbol;

	/**
	 * Constructor
	 * @param applicator the {@link DefaultPdbApplicator} for which we are working.
	 * @param symbol the symbol for this applier
	 */
	public DataSymbolApplier(DefaultPdbApplicator applicator, AbstractDataMsSymbol symbol) {
		super(applicator);
		this.symbol = symbol;
	}

	@Override
	public void apply(MsSymbolIterator iter) throws PdbException, CancelledException {
		getValidatedSymbol(iter, true);
		Address address = applicator.getAddress(symbol);
		if (applicator.isInvalidAddress(address, symbol.getName())) {
			return;
		}
		// createData() can return false on failure, but we want to put the symbol down regardless
		createData(address);
		Address symbolAddress = applicator.getAddress(symbol);
		applicator.createSymbol(symbolAddress, symbol.getName(), false);
	}

	@Override
	public void applyTo(NestingSymbolApplier applyToApplier, MsSymbolIterator iter)
			throws PdbException, CancelledException {
		getValidatedSymbol(iter, true);
		if (applyToApplier instanceof FunctionSymbolApplier functionSymbolApplier) {
			Address address = applicator.getAddress(symbol);
			if (applicator.isInvalidAddress(address, symbol.getName())) {
				return; // silently return
			}
			// createData() can return false on failure, but we want to put the symbol down regardless
			createData(address);
			DataType dataType = applicator.getCompletedDataType(symbol.getTypeRecordNumber());
			functionSymbolApplier.setLocalVariable(address, symbol.getName(), dataType);
		}
	}

	MsTypeApplier getTypeApplier(AbstractMsSymbol abstractSymbol) {
		if (!(abstractSymbol instanceof AbstractDataMsSymbol dataSymbol)) {
			throw new AssertException(
				"Invalid symbol type: " + abstractSymbol.getClass().getSimpleName());
		}
		return applicator.getTypeApplier(dataSymbol.getTypeRecordNumber());
	}

	boolean createData(Address address) throws CancelledException, PdbException {
		RecordNumber typeRecordNumber = symbol.getTypeRecordNumber();
		if (typeRecordNumber.isNoType()) {
			return false;
		}
		DataType dataType = applicator.getCompletedDataType(typeRecordNumber);
		if (dataType == null) { // TODO: check that we can have null here.
			return false;
		}
		if (applicator.getImageBase().equals(address) &&
			!"_IMAGE_DOS_HEADER".equals(dataType.getName())) {
			return false; // Squash some noise
		}
		if (!(dataType instanceof FunctionDefinition)) {
			//TODO: might want to do an ApplyDatatypeCmd here!!!
			DumbMemBufferImpl memBuffer =
				new DumbMemBufferImpl(applicator.getProgram().getMemory(), address);
			DataTypeInstance dti = DataTypeInstance.getDataTypeInstance(dataType, memBuffer, false);
			if (dti == null) {
				applicator.appendLogMsg(
					"Error: Failed to apply datatype " + dataType.getName() + " at " + address);
				return false;
			}
			createData(address, dti.getDataType(), dti.getLength());
		}
		return true;
	}

	private void createData(Address address, DataType dataType, int dataTypeLength) {

		// Ensure that we do not clear previously established code and data
		Data existingData = null;
		CodeUnit cu = applicator.getProgram().getListing().getCodeUnitContaining(address);
		if (cu != null) {
			if ((cu instanceof Instruction) || !address.equals(cu.getAddress())) {
				applicator.appendLogMsg("Warning: Did not create data type \"" +
					dataType.getName() + "\" at address " + address + " due to conflict");
				return;
			}
			Data d = (Data) cu;
			if (d.isDefined()) {
				existingData = d;
			}
		}

		if (dataType == null) {
			return;
		}
		if (dataType.getLength() <= 0 && dataTypeLength <= 0) {
			applicator.appendLogMsg("Unknown dataTypeLength specified at address " + address +
				" for " + dataType.getName());
			return;
		}

		// TODO: This is really bad logic and should be refactored
		// All conflicting data, not just the one containing address,
		// needs to be considered and not blindly cleared.

		if (existingData != null) {
			DataType existingDataType = existingData.getDataType();
			if (isEquivalent(existingData, existingData.getLength(), dataType)) {
				return;
			}
			if (isEquivalent2(existingDataType, dataType)) {
				return;
			}
			if (existingDataType.isEquivalent(dataType)) {
				return;
			}
		}
		if (existingData == null) {
			try {
				applicator.getProgram()
						.getListing()
						.clearCodeUnits(address, address.add(dataTypeLength - 1), false);
				if (dataType.getLength() == -1) {
					applicator.getProgram()
							.getListing()
							.createData(address, dataType, dataTypeLength);
				}
				else {
					applicator.getProgram().getListing().createData(address, dataType);
				}
			}
			catch (CodeUnitInsertionException e) {
				applicator.appendLogMsg("Unable to create " + dataType.getDisplayName() + " at 0x" +
					address + ": " + e.getMessage());
			}
		}
		else if (isDataReplaceable(existingData)) {
			try {
				applicator.getProgram()
						.getListing()
						.clearCodeUnits(address, address.add(dataTypeLength - 1), false);
				applicator.getProgram().getListing().createData(address, dataType, dataTypeLength);
			}
			catch (CodeUnitInsertionException e) {
				applicator.appendLogMsg("Unable to replace " + dataType.getDisplayName() +
					" at 0x" + address + ": " + e.getMessage());
			}
		}
		else {
			DataType existingDataType = existingData.getDataType();
			String existingDataTypeString =
				existingDataType == null ? "null" : existingDataType.getDisplayName();
			applicator.appendLogMsg("Warning: Did not create data type \"" +
				dataType.getDisplayName() + "\" at address " + address +
				".  Preferring existing datatype \"" + existingDataTypeString + "\"");
		}
	}

	private boolean isDataReplaceable(Data data) {
		DataType dataType = data.getDataType();
		if (dataType instanceof Pointer) {
			Pointer pointer = (Pointer) dataType;
			DataType pointerDataType = pointer.getDataType();
			if (pointerDataType == null || pointerDataType.isEquivalent(DataType.DEFAULT)) {
				return true;
			}
		}
		else if (dataType instanceof Array) {
			Array array = (Array) dataType;
			DataType arrayDataType = array.getDataType();
			if (arrayDataType == null || arrayDataType.isEquivalent(DataType.DEFAULT)) {
				return true;
			}
		}

		// All forms of Undefined data are replaceable
		// TODO: maybe it should check the length of the data type before putting it down.
		if (Undefined.isUndefined(dataType)) {
			return true;
		}
		return false;
	}

	private boolean isEquivalent(Data existingData, int existingDataTypeLength,
			DataType newDataType) {
		if (existingData.hasStringValue()) {
			if (newDataType instanceof ArrayDataType) {
				Array array = (Array) newDataType;
				DataType arrayDataType = array.getDataType();
				if (arrayDataType instanceof ArrayStringable) {
					if (array.getLength() == existingDataTypeLength) {
						return true;
					}
				}
			}
		}
		return false;
	}

	/**
	 * "char[12] *"   "char * *"
	 *
	 * "ioinfo * *"   "ioinfo[64] *"
	 */
	private boolean isEquivalent2(DataType datatype1, DataType datatype2) {

		if (datatype1 == datatype2) {
			return true;
		}

		if (datatype1 == null || datatype2 == null) {
			return false;
		}

		if (datatype1 instanceof Array) {
			Array array1 = (Array) datatype1;
			if (datatype2 instanceof Array) {
				Array array2 = (Array) datatype2;
				return isEquivalent2(array1.getDataType(), array2.getDataType());
			}
		}
		else if (datatype1 instanceof Pointer) {
			Pointer pointer1 = (Pointer) datatype1;
			if (datatype2 instanceof Array) {
				Array array2 = (Array) datatype2;
				return isEquivalent2(pointer1.getDataType(), array2.getDataType());
			}
		}
		return datatype1.isEquivalent(datatype2);
	}

	private AbstractDataMsSymbol getValidatedSymbol(MsSymbolIterator iter, boolean iterate) {
		AbstractMsSymbol abstractSymbol = iterate ? iter.next() : iter.peek();
		if (!(abstractSymbol instanceof AbstractDataMsSymbol dataSymbol)) {
			throw new AssertException(
				"Invalid symbol type: " + abstractSymbol.getClass().getSimpleName());
		}
		return dataSymbol;
	}

}
