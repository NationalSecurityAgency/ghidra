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
package ghidra.app.cmd.data;

import ghidra.app.util.datatype.microsoft.DataApplyOptions;
import ghidra.app.util.datatype.microsoft.DataValidationOptions;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;

/**
 * This command will create a TypeDescriptor data type. Since unsized arrays are not properly
 * handled due to the current data type API limitations, this creates a dynamic RTTI0DataType.
 */
public class CreateTypeDescriptorBackgroundCmd
		extends AbstractCreateDataBackgroundCmd<TypeDescriptorModel> {

	private static final String RTTI_0_NAME = "RTTI Type Descriptor";

	/**
	 * Constructs a command for applying a TypeDescriptor data type at an address using the 
	 * default validation and apply options.
	 * @param address the address where the data should be created using the data type.
	 */
	public CreateTypeDescriptorBackgroundCmd(Address address) {
		super(TypeDescriptorModel.DATA_TYPE_NAME, address, 1);
	}

	/**
	 * Constructs a command for applying a TypeDescriptor data type at an address using the 
	 * indicated options.
	 * @param address the address where the data should be created using the data type.
	 * @param validationOptions the options for controlling how validation is performed when 
	 * determining whether or not to create the data structure at the indicated address.
	 * @param applyOptions the options for creating the new data structure and its associated
	 * markup in the program as well as whether to follow other data references and create their 
	 * data too.
	 */
	public CreateTypeDescriptorBackgroundCmd(Address address,
			DataValidationOptions validationOptions, DataApplyOptions applyOptions) {
		super(TypeDescriptorModel.DATA_TYPE_NAME, address, 1, validationOptions, applyOptions);
	}

	/**
	 * Constructs a command for applying a TypeDescriptor data type at the address indicated
	 * by the model and using the indicated options.
	 * @param model the model indicating the TypeDescriptor data to be created by this command.
	 * @param applyOptions the options for creating the new data structure and its associated
	 * markup in the program as well as whether to follow other data references and create their 
	 * data too.
	 */
	public CreateTypeDescriptorBackgroundCmd(TypeDescriptorModel model,
			DataApplyOptions applyOptions) {
		super(model, applyOptions);
	}

	private void loadModel(Program program) {
		if (model == null || program != model.getProgram()) {
			model = new TypeDescriptorModel(program, getDataAddress(), validationOptions);
		}
	}

	@Override
	protected TypeDescriptorModel createModel(Program program) {
		if (model == null) {
			loadModel(program);
		}
		return model;
	}

	/**
	 * Create the data corresponding to a RTTI0 TypeDescriptor structure which contains a flexible-array
	 * as its last component ( char[0]  name ).  The string data associated with this flexible char array will
	 * be applied as a sized character array immediately following the structure whose size does not include
	 * the char array bytes.
	 * @return false if the data type was not created because it already exists, true otherwise
	 * @throws CodeUnitInsertionException
	 * @throws CancelledException
	 */
	@Override
	protected boolean createData() throws CodeUnitInsertionException, CancelledException {
		if (!super.createData()) { // create the TypeDesciptor structure 
			return false;
		}

		// Determine the size of the flexible char array storage and create  properly sized array
		DataType dataType = model.getDataType();
		int structLen = dataType.getLength();
		Address arrayAddr = model.getAddress().add(structLen);
		DataType charArray =
			new ArrayDataType(CharDataType.dataType, model.getDataTypeLength() - structLen, 1);

		// Create 'name' char[0] data at the address immediately following structure
		Program program = model.getProgram();
		Data nameData = DataUtilities.createData(program, arrayAddr, charArray,
			charArray.getLength(), false, getClearDataMode());

		nameData.setComment(CodeUnit.EOL_COMMENT, "TypeDescriptor.name");

		return true;
	}

	@Override
	protected boolean createAssociatedData() throws CancelledException {

		// No associated data to create.
		return true;
	}

	@Override
	protected boolean createMarkup() throws CancelledException, InvalidInputException {

		monitor.checkCanceled();

		Program program = model.getProgram();
		String demangledName = model.getDemangledTypeDescriptor();
		if (demangledName == null) {
			return false;
		}
		String prefix = demangledName + " ";

		// Plate Comment
		EHDataTypeUtilities.createPlateCommentIfNeeded(program, prefix, RTTI_0_NAME, null,
			getDataAddress(), applyOptions);

		monitor.checkCanceled();

		// Label
		EHDataTypeUtilities.createSymbolIfNeeded(program, prefix, RTTI_0_NAME, null,
			getDataAddress(), applyOptions);

		return true;
	}

}
