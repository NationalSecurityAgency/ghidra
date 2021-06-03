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
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;

/**
 * This command will create a IPToStateMapEntry exception handler data type or an array of them. 
 * If there are any existing instructions in the area to be made into data, the command will fail.
 * Any data in the area will be replaced with the new dataType.
 */
public class CreateEHIPToStateMapBackgroundCmd
		extends AbstractCreateDataBackgroundCmd<EHIPToStateModel> {

	/**
	 * Constructs a command for applying an IPToStateMapEntry exception handling data type at an 
	 * address.
	 * @param address the address where the data should be created using the data type.
	 * @param count the number of the indicated data type to create.
	 */
	public CreateEHIPToStateMapBackgroundCmd(Address address, int count) {
		super(EHIPToStateModel.DATA_TYPE_NAME, address, count);
	}

	/**
	 * Constructs a command for applying an IPToStateMapEntry exception handling data type at an 
	 * address.
	 * @param address the address where the data should be created using the data type.
	 * @param count the number of the indicated data type to create.
	 * @param validationOptions the options for controlling how validation is performed when 
	 * determining whether or not to create the data structure at the indicated address.
	 * @param applyOptions the options for creating the new data structure and its associated
	 * markup in the program as well as whether to follow other data references and create their 
	 * data too.
	 */
	public CreateEHIPToStateMapBackgroundCmd(Address address, int count,
			DataValidationOptions validationOptions, DataApplyOptions applyOptions) {
		super(EHIPToStateModel.DATA_TYPE_NAME, address, count, validationOptions, applyOptions);
	}

	/**
	 * Constructs a command for applying a IPToStateMapEntry exception handling data type at the 
	 * address indicated by the model.
	 * @param ipToStateModel the model for the data type
	 * @param applyOptions the options for creating the new data structure and its associated
	 * markup in the program as well as whether to follow other data references and create their 
	 * data too.
	 */
	CreateEHIPToStateMapBackgroundCmd(EHIPToStateModel ipToStateModel,
			DataApplyOptions applyOptions) {
		super(ipToStateModel, applyOptions);
	}

	@Override
	protected EHIPToStateModel createModel(Program program) {
		if (model == null) {
			model = new EHIPToStateModel(program, count, getDataAddress(), validationOptions);
		}
		return model;
	}

	@Override
	protected boolean createAssociatedData() throws CancelledException {
		return createIpRefs();
	}

	private boolean createIpRefs() {

		// NOTE: Current components which utilize ibo32 get a reference created
		// automatically by the CodeManager.  Components which produce Scalar values
		// (e.g., ULONG) are ignored.

		return true;
	}

	@Override
	protected boolean createMarkup() throws CancelledException {

		return true; // No markup.
	}
}
