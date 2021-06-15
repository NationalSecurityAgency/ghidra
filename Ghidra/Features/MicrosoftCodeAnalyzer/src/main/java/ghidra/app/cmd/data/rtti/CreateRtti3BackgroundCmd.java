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

import ghidra.app.cmd.data.*;
import ghidra.app.util.datatype.microsoft.DataApplyOptions;
import ghidra.app.util.datatype.microsoft.DataValidationOptions;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.util.exception.CancelledException;

/**
 * This command will create an RTTI3 data type. 
 * If there are any existing instructions in the area to be made into data, the command will fail.
 * Any data in the area will be replaced with the new dataType.
 */
public class CreateRtti3BackgroundCmd extends AbstractCreateDataBackgroundCmd<Rtti3Model> {

	private static final String RTTI_3_NAME = "RTTI Class Hierarchy Descriptor";

	/**
	 * Constructs a command for applying an RTTI3 dataType at an address.
	 * @param address the address where the data should be created using the data type.
	 * @param validationOptions the options for controlling how validation is performed when 
	 * determining whether or not to create the data structure at the indicated address.
	 * @param applyOptions the options for creating the new data structure and its associated
	 * markup in the program as well as whether to follow other data references and create their 
	 * data too.
	 */
	public CreateRtti3BackgroundCmd(Address address, DataValidationOptions validationOptions,
			DataApplyOptions applyOptions) {

		super(Rtti3Model.DATA_TYPE_NAME, address, 1, validationOptions, applyOptions);
	}

	/**
	 * Constructs a command for applying an RTTI3 dataType at the address indicated by the 
	 * model.
	 * @param rtti3Model the model for the data type
	 * @param applyOptions the options for creating the new data structure and its associated
	 * markup in the program as well as whether to follow other data references and create their 
	 * data too.
	 */
	CreateRtti3BackgroundCmd(Rtti3Model rtti3Model, DataApplyOptions applyOptions) {
		super(rtti3Model, applyOptions);
	}

	@Override
	protected Rtti3Model createModel(Program program) {
		if (model == null || program != model.getProgram()) {
			model = new Rtti3Model(program, getDataAddress(), validationOptions);
		}
		return model;
	}

	@Override
	protected boolean createAssociatedData() throws CancelledException {

		try {
			return createRtti2();
		}
		catch (InvalidDataTypeException e) {
			// log message
			handleErrorMessage(model.getProgram(), model.getAddress(), e.getMessage());
			return false; // return since no other markup
		}
	}

	private boolean createRtti2() throws CancelledException, InvalidDataTypeException {

		monitor.checkCanceled();

		CreateRtti2BackgroundCmd cmd =
			new CreateRtti2BackgroundCmd(model.getRtti2Model(), applyOptions);
		return cmd.applyTo(model.getProgram(), monitor);
	}

	@Override
	protected boolean createMarkup() throws CancelledException, InvalidDataTypeException {

		monitor.checkCanceled();

		Program program = model.getProgram();
		TypeDescriptorModel rtti0Model = model.getRtti0Model();

		if (rtti0Model == null) {
			return true;
		}

		monitor.checkCanceled();
		
		// Label
		boolean shouldCreateComment = true;
		if (applyOptions.shouldCreateLabel()) {
			shouldCreateComment = RttiUtil.createSymbolFromDemangledType(program, getDataAddress(), rtti0Model, RTTI_3_NAME);
		}

		// Plate Comment
		if (shouldCreateComment) {
			// comment created if a label was created, or createLabel option off
			EHDataTypeUtilities.createPlateCommentIfNeeded(program,
					RttiUtil.getDescriptorTypeNamespace(rtti0Model) + Namespace.DELIMITER,
					RTTI_3_NAME, null, getDataAddress(), applyOptions);
		}


		return true;
	}

}
