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
package ghidra.app.cmd.data.rtti;

import static ghidra.app.util.datatype.microsoft.MSDataTypeUtils.*;

import ghidra.app.cmd.data.*;
import ghidra.app.util.datatype.microsoft.DataApplyOptions;
import ghidra.app.util.datatype.microsoft.DataValidationOptions;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;

/**
 * This command will create a virtual function table using an array data type. 
 * If there are any existing instructions in the area to be made into data, the command will fail.
 * Any data in the area will be replaced with the new dataType.
 */
public class CreateVfTableBackgroundCmd extends AbstractCreateDataBackgroundCmd<VfTableModel> {

	private static final String NAME = "vftable";
	private static final String VF_TABLE_LABEL = "vftable";
	private static final String META_LABEL = "meta";
	private static final String NAME_SEPARATOR = "_";

	/**
	 * Constructs a command for applying a vf table at an address.
	 * @param address the address where the vf table should be created.
	 * @param validationOptions the options for controlling how validation is performed when 
	 * determining whether or not to create the data structure at the indicated address.
	 * @param applyOptions the options for creating the new data structure and its associated
	 * markup in the program as well as whether to follow other data references and create their 
	 * data too.
	 */
	public CreateVfTableBackgroundCmd(Address address, DataValidationOptions validationOptions,
			DataApplyOptions applyOptions) {

		super(NAME, address, 1, validationOptions, applyOptions);
	}

	/**
	 * Constructs a command for applying a vf table dataType at the address indicated by the 
	 * model.
	 * @param vfTableModel the model for the data type
	 * @param applyOptions the options for creating the new data structure and its associated
	 * markup in the program as well as whether to follow other data references and create their 
	 * data too.
	 */
	CreateVfTableBackgroundCmd(VfTableModel vfTableModel, DataApplyOptions applyOptions) {
		super(vfTableModel, applyOptions);
	}

	@Override
	protected VfTableModel createModel(Program program) {
		if (model == null || program != model.getProgram()) {
			model = new VfTableModel(program, getDataAddress(), validationOptions);
		}
		return model;
	}

	@Override
	protected boolean createAssociatedData() throws CancelledException {

		monitor.checkCanceled();

		boolean createTerminatorSuccess;
		try {
			createTerminatorSuccess = createTableTerminator();
		}
		catch (InvalidDataTypeException e) {
			createTerminatorSuccess = false;
			// log message and continue with other markup.
			handleErrorMessage(model.getProgram(), model.getAddress(), e.getMessage());
		}

		boolean createMetaSuccess = createMetaPointer();

		return createTerminatorSuccess && createMetaSuccess;
	}

	private boolean createTableTerminator() throws CancelledException, InvalidDataTypeException {

		Program program = model.getProgram();

		// Create a zero pointer at the end of the vf table.
		DataType dataType = getDataType();
		if (dataType == null) {
			return false;
		}
		long displacement = dataType.getLength();
		Address terminatorAddress = getDataAddress().add(displacement);
		try {
			Address referencedAddress = getAbsoluteAddress(program, terminatorAddress);
			if (referencedAddress == null || referencedAddress.getOffset() != 0) {
				return false;
			}
			Data data = DataUtilities.createData(program, terminatorAddress,
				PointerDataType.dataType, -1, false, getClearDataMode());
			TypeDescriptorModel rtti0Model = model.getRtti0Model();
			if (rtti0Model != null) {
				monitor.checkCanceled();
				String demangledTypeDescriptor = rtti0Model.getDemangledTypeDescriptor();
				String prefixString = ((demangledTypeDescriptor != null)
						? (demangledTypeDescriptor + Namespace.DELIMITER)
						: "");
				data.setComment(CodeUnit.EOL_COMMENT,
					"terminator for " + prefixString + VF_TABLE_LABEL);
				return true;
			}
			return false;
		}
		catch (CodeUnitInsertionException e) {
			Msg.error(this, "Couldn't create vf table's null terminator pointer. " + e.getMessage(),
				e);
			return false;
		}
	}

	private boolean createMetaPointer() {

		Program program = model.getProgram();
		Address metaAddress = getDataAddress().subtract(program.getDefaultPointerSize());

		// Create a pointer to the RTTI4 associated with the vf table.
		DataType metaPointer = new PointerDataType(program.getDataTypeManager());
		try {
			DataUtilities.createData(program, metaAddress, metaPointer, metaPointer.getLength(),
				false, getClearDataMode());
			return true;
		}
		catch (CodeUnitInsertionException e) {
			Msg.error(this, "Couldn't create vf table's meta pointer. " + e.getMessage(), e);
			return false;
		}
	}

	@Override
	protected boolean createMarkup() throws CancelledException, InvalidDataTypeException {

		boolean createdVfTableMarkup = createVfTableMarkup();
		boolean createdMetaMarkup = createMetaMarkup();

		return createdVfTableMarkup && createdMetaMarkup;
	}

	private boolean createVfTableMarkup() throws CancelledException, InvalidDataTypeException {

		Address vfTableAddress = getDataAddress();
		Program program = model.getProgram();

		monitor.checkCanceled();

		TypeDescriptorModel rtti0Model = model.getRtti0Model();

		if (rtti0Model == null) {
			return true;
		}
		
		// Label
		boolean shouldCreateComment = true;
		if (applyOptions.shouldCreateLabel()) {
			shouldCreateComment = RttiUtil.createSymbolFromDemangledType(program, vfTableAddress, rtti0Model,
					VF_TABLE_LABEL);
		}

		// Plate Comment
		if (shouldCreateComment) {
			// comment created if a label was created, or createLabel option off
			EHDataTypeUtilities.createPlateCommentIfNeeded(program, RttiUtil.CONST_PREFIX +
					RttiUtil.getDescriptorTypeNamespace(rtti0Model) + Namespace.DELIMITER,
					VF_TABLE_LABEL, null, vfTableAddress, applyOptions);
		}

		// Create functions that are referred to by the vf table.
		if (applyOptions.shouldCreateFunction()) {
			int elementCount = model.getElementCount();
			for (int tableElementIndex = 0; tableElementIndex < elementCount; tableElementIndex++) {
				monitor.checkCanceled();
				Address vfPointer = model.getVirtualFunctionPointer(tableElementIndex);
				if (vfPointer != null) {
					EHDataTypeUtilities.createFunctionIfNeeded(program, vfPointer);
				}
			}
		}

		return true;
	}

	private boolean createMetaMarkup() throws CancelledException, InvalidDataTypeException {

		Program program = model.getProgram();
		Address metaAddress = getMetaAddress(program);

		monitor.checkCanceled();

		TypeDescriptorModel rtti0Model = model.getRtti0Model();

		if (rtti0Model == null) {
			return true;
		}
		
		monitor.checkCanceled();

		// Label
		boolean shouldCreateComment = true;
		if (applyOptions.shouldCreateLabel()) {
			shouldCreateComment = RttiUtil.createSymbolFromDemangledType(program, metaAddress, rtti0Model,
					VF_TABLE_LABEL + NAME_SEPARATOR + META_LABEL + "_ptr");
		}

		// Plate Comment
		if (shouldCreateComment) {
			// comment created if a label was created, or createLabel option off
			EHDataTypeUtilities.createPlateCommentIfNeeded(
					program, META_LABEL + " pointer for " +
						RttiUtil.getDescriptorTypeNamespace(rtti0Model) + Namespace.DELIMITER,
					VF_TABLE_LABEL, null, metaAddress, applyOptions);
		}

		return true;
	}

	/**
	 * Gets the address for the location of the meta data, which is a pointer to the RTTI4
	 * structure for this virtual function table (vftable).
	 * @param program the program containing the vftable being created by this command
	 * @return the address that contains the pointer to the RTTI 4 structure associated with 
	 * the vftable.
	 */
	private Address getMetaAddress(Program program) {
		return getDataAddress().subtract(program.getDefaultPointerSize());
	}

}
