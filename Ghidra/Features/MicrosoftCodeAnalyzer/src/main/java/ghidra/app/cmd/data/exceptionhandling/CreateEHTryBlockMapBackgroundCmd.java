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
 * This command will create a TryBlockMapEntry exception handler data type or an array of them. 
 * If there are any existing instructions in the area to be made into data, the command will fail.
 * Any data in the area will be replaced with the new dataType.
 */
public class CreateEHTryBlockMapBackgroundCmd
		extends AbstractCreateDataBackgroundCmd<EHTryBlockModel> {

	/**
	 * Constructs a command for applying a TryBlockMapEntry exception handling data type at an 
	 * address.
	 * @param address the address where the data should be created using the data type.
	 * @param count the number of the indicated data type to create.
	 */
	public CreateEHTryBlockMapBackgroundCmd(Address address, int count) {
		super(EHTryBlockModel.DATA_TYPE_NAME, address, count);
	}

	/**
	 * Constructs a command for applying a TryBlockMapEntry exception handling data type at an 
	 * address.
	 * @param address the address where the data should be created using the data type.
	 * @param count the number of the indicated data type to create.
	 * @param validationOptions the options for controlling how validation is performed when 
	 * determining whether or not to create the data structure at the indicated address.
	 * @param applyOptions the options for creating the new data structure and its associated
	 * markup in the program as well as whether to follow other data references and create their 
	 * data too.
	 */
	public CreateEHTryBlockMapBackgroundCmd(Address address, int count,
			DataValidationOptions validationOptions, DataApplyOptions applyOptions) {
		super(EHTryBlockModel.DATA_TYPE_NAME, address, count, validationOptions, applyOptions);
	}

	/**
	 * Constructs a command for applying a TryBlockMapEntry exception handling data type at the 
	 * address indicated by the model.
	 * @param tryBlockModel the model for the data type
	 * @param applyOptions the options for creating the new data structure and its associated
	 * markup in the program as well as whether to follow other data references and create their 
	 * data too.
	 */
	CreateEHTryBlockMapBackgroundCmd(EHTryBlockModel tryBlockModel, DataApplyOptions applyOptions) {
		super(tryBlockModel, applyOptions);
	}

	@Override
	protected EHTryBlockModel createModel(Program program) {
		if (model == null) {
			model = new EHTryBlockModel(program, count, getDataAddress(), validationOptions);
		}
		return model;
	}

	@Override
	protected boolean createAssociatedData() throws CancelledException {
		return createCatchHandlerMapEntries();
	}

	private boolean createCatchHandlerMapEntries() throws CancelledException {
		monitor.setMessage("Creating HandlerTypes from TryBlockMap");
		boolean result = true;
		Program program = model.getProgram();

		for (int tryBlockEntryOrdinal = 0; tryBlockEntryOrdinal < count; tryBlockEntryOrdinal++) {
			monitor.checkCanceled();
			Address compAddress;
			Address catchHandlerMapAddress;
			int catchHandlerCount;
			try {
				compAddress =
					model.getComponentAddressOfCatchHandlerMapAddress(tryBlockEntryOrdinal);
				catchHandlerMapAddress = model.getCatchHandlerMapAddress(tryBlockEntryOrdinal);
				catchHandlerCount = model.getCatchHandlerCount(tryBlockEntryOrdinal);
			}
			catch (InvalidDataTypeException e) {
				throw new AssertException(e); // Shouldn't happen. create...() is only called if model is valid.
			}

			if (catchHandlerMapAddress == null || (catchHandlerCount == 0)) {
				continue; // No catch handler info to create.
			}

			EHCatchHandlerModel catchHandlerModel;
			try {
				catchHandlerModel = model.getCatchHandlerModel(tryBlockEntryOrdinal);
			}
			catch (InvalidDataTypeException e) {
				throw new AssertException(e); // Shouldn't happen. create...() is only called if model is valid.
			}
			try {
				catchHandlerModel.validate();
			}
			catch (InvalidDataTypeException e1) {
				handleErrorMessage(program, catchHandlerModel.getName(), catchHandlerMapAddress,
					compAddress, e1);
				result = false;
				continue;
			}

			monitor.checkCanceled();

			CreateEHCatchHandlerMapBackgroundCmd cmd =
				new CreateEHCatchHandlerMapBackgroundCmd(catchHandlerModel, applyOptions);
			result &= cmd.applyTo(program, monitor);
		}
		return result;
	}

	@Override
	protected boolean createMarkup() throws CancelledException {

		return true; // No markup.
	}
}
