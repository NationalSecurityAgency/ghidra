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
package ghidra.app.cmd.data.exceptionhandling;

import ghidra.app.cmd.data.AbstractCreateDataBackgroundCmd;
import ghidra.app.util.datatype.microsoft.DataApplyOptions;
import ghidra.app.util.datatype.microsoft.DataValidationOptions;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;

/**
 * This command will create a ESTypeList exception handler data type. 
 * If there are any existing instructions in the area to be made into data, the command will fail.
 * Any data in the area will be replaced with the new dataType.
 */
public class CreateEHESTypeListBackgroundCmd
		extends AbstractCreateDataBackgroundCmd<EHESTypeListModel> {

	/**
	 * Constructs a command for applying an ESTypeList exception handling data type at an address.
	 * @param address the address where the data should be created using the data type.
	 */
	public CreateEHESTypeListBackgroundCmd(Address address) {
		super(EHESTypeListModel.DATA_TYPE_NAME, address, 1);
	}

	/**
	 * Constructs a command for applying an ESTypeList exception handling data type at an address.
	 * @param address the address where the data should be created using the data type.
	 * @param validationOptions the options for controlling how validation is performed when 
	 * determining whether or not to create the data structure at the indicated address.
	 * @param applyOptions the options for creating the new data structure and its associated
	 * markup in the program as well as whether to follow other data references and create their 
	 * data too.
	 */
	public CreateEHESTypeListBackgroundCmd(Address address, DataValidationOptions validationOptions,
			DataApplyOptions applyOptions) {
		super(EHESTypeListModel.DATA_TYPE_NAME, address, 1, validationOptions, applyOptions);
	}

	/**
	 * Constructs a command for applying a ESTypeList exception handling data type at the 
	 * address indicated by the model.
	 * @param esTypeListModel the model for the data type
	 * @param applyOptions the options for creating the new data structure and its associated
	 * markup in the program as well as whether to follow other data references and create their 
	 * data too.
	 */
	CreateEHESTypeListBackgroundCmd(EHESTypeListModel esTypeListModel,
			DataApplyOptions applyOptions) {
		super(esTypeListModel, applyOptions);
	}

	@Override
	protected EHESTypeListModel createModel(Program program) {
		if (model == null) {
			model = new EHESTypeListModel(program, getDataAddress(), validationOptions);
		}
		return model;
	}

	@Override
	protected boolean createAssociatedData() throws CancelledException {
		return createCatchHandlerMapEntries();
	}

	private boolean createCatchHandlerMapEntries() throws CancelledException {
		monitor.setMessage("Creating HandlerTypes for ESTypeList");
		Program program = model.getProgram();

		Address compAddress;
		Address handlerTypeMapAddress;
		int catchHandlerCount;
		try {
			compAddress = model.getComponentAddressOfHandlerTypeMapAddress();
			handlerTypeMapAddress = model.getHandlerTypeMapAddress();
			catchHandlerCount = model.getHandlerTypeCount();
		}
		catch (InvalidDataTypeException e) {
			throw new AssertException(e); // Shouldn't happen. create...() is only called if model is valid.
		}

		if (handlerTypeMapAddress == null || (catchHandlerCount == 0)) {
			return true; // No catch handler info to create.
		}

		monitor.checkCanceled();

		EHCatchHandlerModel catchHandlerModel;
		try {
			catchHandlerModel = model.getCatchHandlerModel();
		}
		catch (InvalidDataTypeException e) {
			throw new AssertException(e);  // Shouldn't happen. create...() is only called if model is valid.
		}
		try {
			catchHandlerModel.validate();
		}
		catch (InvalidDataTypeException e1) {
			handleErrorMessage(program, catchHandlerModel.getName(), handlerTypeMapAddress,
				compAddress, e1);
			return false;
		}

		monitor.checkCanceled();

		CreateEHCatchHandlerMapBackgroundCmd cmd =
			new CreateEHCatchHandlerMapBackgroundCmd(catchHandlerModel, applyOptions);
		return cmd.applyTo(program, monitor);
	}

	@Override
	protected boolean createMarkup() throws CancelledException {

		return true; // No markup.
	}
}
