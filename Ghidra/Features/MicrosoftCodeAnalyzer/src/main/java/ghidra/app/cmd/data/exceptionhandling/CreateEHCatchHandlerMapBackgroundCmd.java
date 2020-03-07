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

import ghidra.app.cmd.data.*;
import ghidra.app.util.datatype.microsoft.DataApplyOptions;
import ghidra.app.util.datatype.microsoft.DataValidationOptions;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.exception.*;

/**
 * This command will create a HandlerType exception handler data type or an array of them. 
 * If there are any existing instructions in the area to be made into data, the command will fail.
 * Any data in the area will be replaced with the new dataType.
 */
public class CreateEHCatchHandlerMapBackgroundCmd
		extends AbstractCreateDataBackgroundCmd<EHCatchHandlerModel> {

	/**
	 * Constructs a command for applying a HandlerType exception handling data type at an 
	 * address.
	 * @param address the address where the data should be created using the data type.
	 * @param count the number of the indicated data type to create.
	 */
	public CreateEHCatchHandlerMapBackgroundCmd(Address address, int count) {
		super(EHCatchHandlerModel.DATA_TYPE_NAME, address, count);
	}

	/**
	 * Constructs a command for applying a HandlerType exception handling data type at an 
	 * address.
	 * @param address the address where the data should be created using the data type.
	 * @param count the number of the indicated data type to create.
	 * @param validationOptions the options for controlling how validation is performed when 
	 * determining whether or not to create the data structure at the indicated address.
	 * @param applyOptions the options for creating the new data structure and its associated
	 * markup in the program as well as whether to follow other data references and create their 
	 * data too.
	 */
	public CreateEHCatchHandlerMapBackgroundCmd(Address address, int count,
			DataValidationOptions validationOptions, DataApplyOptions applyOptions) {
		super(EHCatchHandlerModel.DATA_TYPE_NAME, address, count, validationOptions, applyOptions);
	}

	/**
	 * Constructs a command for applying a HandlerType exception handling data type at the 
	 * address indicated by the model.
	 * @param catchHandlerModel the model for the data type
	 * @param applyOptions the options for creating the new data structure and its associated
	 * markup in the program as well as whether to follow other data references and create their 
	 * data too.
	 */
	CreateEHCatchHandlerMapBackgroundCmd(EHCatchHandlerModel catchHandlerModel,
			DataApplyOptions applyOptions) {
		super(catchHandlerModel, applyOptions);
	}

	@Override
	protected EHCatchHandlerModel createModel(Program program) {
		if (model == null) {
			model = new EHCatchHandlerModel(program, count, getDataAddress(), validationOptions);
		}
		return model;
	}

	@Override
	protected boolean createAssociatedData() throws CancelledException {
		return createTypeDescriptors();
	}

	/**
	 * Creates the associated TypeDescriptor data.
	 * @param program the program where this command is applying the data.
	 * @param monitor the task monitor for cancelling creation of the TypeDescriptor.
	 * @return true if successful.
	 * @throws CancelledException if the user cancels this task.
	 */
	private boolean createTypeDescriptors() throws CancelledException {
		monitor.setMessage("Creating TypeDescriptors for HandlerTypes");
		boolean result = true;
		Program program = model.getProgram();

		for (int catchHandlerOrdinal = 0; catchHandlerOrdinal < count; catchHandlerOrdinal++) {
			monitor.checkCanceled();
			Address compAddress;
			Address typeDescriptorAddress;
			try {
				compAddress = model.getComponentAddressOfTypeDescriptorAddress(catchHandlerOrdinal);
				typeDescriptorAddress = model.getTypeDescriptorAddress(catchHandlerOrdinal);
			}
			catch (InvalidDataTypeException e) {
				throw new AssertException(e); // Shouldn't happen. create...() is only called if model is valid.
			}

			if (typeDescriptorAddress == null) {
				continue; // No type descriptor for this HandlerType record.
			}

			TypeDescriptorModel typeDescriptorModel;
			try {
				typeDescriptorModel = model.getTypeDescriptorModel(catchHandlerOrdinal);
			}
			catch (InvalidDataTypeException e) {
				throw new AssertException(e);  // Shouldn't happen. create...() is only called if model is valid.
			}
			try {
				typeDescriptorModel.validate();
			}
			catch (InvalidDataTypeException e1) {
				handleErrorMessage(program, typeDescriptorModel.getName(),
					typeDescriptorModel.getAddress(), compAddress, e1);
				result = false;
				continue;
			}
			int typeDescriptorCount = typeDescriptorModel.getCount();
			if (typeDescriptorCount == 0) {
				continue; // No type descriptor for this HandlerType record.
			}

			CreateTypeDescriptorBackgroundCmd cmd =
				new CreateTypeDescriptorBackgroundCmd(typeDescriptorModel, applyOptions);
			result &= cmd.applyTo(program, monitor);
		}
		return result;
	}

	@Override
	protected boolean createMarkup() throws CancelledException {

		return createHandlerRefsAndSymbols();
	}

	/**
	 * Creates data references to the catch handler function and based on options it creates a 
	 * label for the catch handler function, disassembles it, and creates the function.
	 * @param program the program where this command is creating references and symbols.
	 * @param monitor the task monitor for cancelling creation of the catch handler reference,
	 * label, and function.
	 * @return true if successful.
	 * @throws CancelledException if the user cancels this task.
	 */
	private boolean createHandlerRefsAndSymbols() throws CancelledException {
		monitor.setMessage("Creating catch handler markup");
		Program program = model.getProgram();
		boolean result = true;
		EHCatchHandlerModel catchHandlerModel = createModel(program);
		for (int catchHandlerOrdinal = 0; catchHandlerOrdinal < count; catchHandlerOrdinal++) {
			monitor.checkCanceled();
			Address compAddress;
			Address refAddress;
			try {
				compAddress =
					catchHandlerModel.getComponentAddressOfCatchHandlerAddress(catchHandlerOrdinal);
				refAddress = catchHandlerModel.getCatchHandlerAddress(catchHandlerOrdinal);
			}
			catch (InvalidDataTypeException e) {
				throw new AssertException(e); // Shouldn't happen. create...() is only called if model is valid.
			}
			if (refAddress == null) {
				continue; // No catch handler for this HandlerType record.
			}
			if (applyOptions.shouldCreateLabel()) {
				String catchHandlerName;
				try {
					catchHandlerName = catchHandlerModel.getCatchHandlerName(catchHandlerOrdinal);
					Symbol symbol = EHDataTypeUtilities.createSymbolIfNeeded(program,
						catchHandlerName, refAddress);
					if (symbol == null) {
						result = false;
					}
				}
				catch (InvalidDataTypeException | InvalidInputException e) {
					String message =
						"Couldn't create name for catch handler at " + refAddress.toString() + ".";
					handleErrorMessage(program, compAddress, message + " " + e.getMessage(),
						message);
					result = false;
				}
			}
			if (applyOptions.shouldCreateFunction()) {
				boolean success = EHDataTypeUtilities.createFunctionIfNeeded(program, refAddress);
				if (!success) {
					result = false;
				}
			}
		}
		return result;
	}
}
