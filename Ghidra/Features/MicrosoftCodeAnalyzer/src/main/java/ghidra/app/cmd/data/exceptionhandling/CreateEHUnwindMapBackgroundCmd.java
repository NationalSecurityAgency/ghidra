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
import ghidra.app.cmd.data.EHDataTypeUtilities;
import ghidra.app.util.datatype.microsoft.DataApplyOptions;
import ghidra.app.util.datatype.microsoft.DataValidationOptions;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.exception.*;

/**
 * This command will create a UnwindMapEntry exception handler data type or an array of them. 
 * If there are any existing instructions in the area to be made into data, the command will fail.
 * Any data in the area will be replaced with the new dataType.
 */
public class CreateEHUnwindMapBackgroundCmd extends AbstractCreateDataBackgroundCmd<EHUnwindModel> {

	/**
	 * Constructs a command for applying an UnwindMapEntry exception handling data type at an 
	 * address.
	 * @param address the address where the data should be created using the data type.
	 * @param count the number of the indicated data type to create.
	 */
	public CreateEHUnwindMapBackgroundCmd(Address address, int count) {
		super(EHUnwindModel.DATA_TYPE_NAME, address, count);
	}

	/**
	 * Constructs a command for applying an UnwindMapEntry exception handling data type at an 
	 * address.
	 * @param address the address where the data should be created using the data type.
	 * @param count the number of the indicated data type to create.
	 * @param validationOptions the options for controlling how validation is performed when 
	 * determining whether or not to create the data structure at the indicated address.
	 * @param applyOptions the options for creating the new data structure and its associated
	 * markup in the program as well as whether to follow other data references and create their 
	 * data too.
	 */
	public CreateEHUnwindMapBackgroundCmd(Address address, int count,
			DataValidationOptions validationOptions, DataApplyOptions applyOptions) {
		super(EHUnwindModel.DATA_TYPE_NAME, address, count, validationOptions, applyOptions);
	}

	/**
	 * Constructs a command for applying a UnwindMapEntry exception handling data type at the 
	 * address indicated by the model.
	 * @param unwindModel the model for the data type
	 * @param applyOptions the options for creating the new data structure and its associated
	 * markup in the program as well as whether to follow other data references and create their 
	 * data too.
	 */
	CreateEHUnwindMapBackgroundCmd(EHUnwindModel unwindModel, DataApplyOptions applyOptions) {
		super(unwindModel, applyOptions);
	}

	@Override
	protected EHUnwindModel createModel(Program program) {
		if (model == null) {
			model = new EHUnwindModel(program, count, getDataAddress(), validationOptions);
		}
		return model;
	}

	@Override
	protected boolean createAssociatedData() throws CancelledException {
		return createActionRefsAndSymbols();
	}

	private boolean createActionRefsAndSymbols() throws CancelledException {
		monitor.setMessage("Creating Unwind action markup");
		boolean result = true;
		Program program = model.getProgram();

		for (int unwindEntryOrdinal = 0; unwindEntryOrdinal < count; unwindEntryOrdinal++) {
			monitor.checkCanceled();
			Address compAddress;
			Address actionAddress;
			try {
				compAddress = model.getComponentAddressOfActionAddress(unwindEntryOrdinal);
				actionAddress = model.getActionAddress(unwindEntryOrdinal);
			}
			catch (InvalidDataTypeException e) {
				throw new AssertException(e); // Shouldn't happen. create...() is only called if model is valid.
			}
			if (actionAddress == null) {
				continue; // No unwind action address for this UnwindMap record.
			}
			if (applyOptions.shouldCreateLabel()) {
				try {
					Symbol symbol =
						EHDataTypeUtilities.createSymbolIfNeeded(program, "Unwind", actionAddress);
					if (symbol == null) {
						result = false;
					}
				}
				catch (InvalidInputException e) {
					String message = "Couldn't create name for unwind action at " +
						actionAddress.toString() + ".";
					handleErrorMessage(program, compAddress, message + " " + e.getMessage(),
						message);
					result = false;
				}
			}
			if (applyOptions.shouldCreateFunction()) {
				boolean success =
					EHDataTypeUtilities.createFunctionIfNeeded(program, actionAddress);
				if (!success) {
					result = false;
				}
			}
		}
		return result;
	}

	@Override
	protected boolean createMarkup() throws CancelledException {

		return true; // No markup.
	}
}
