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
 * This command will create an RTTI2 data type. 
 * If there are any existing instructions in the area to be made into data, the command will fail.
 * Any data in the area will be replaced with the new dataType.
 */
public class CreateRtti2BackgroundCmd extends AbstractCreateDataBackgroundCmd<Rtti2Model> {

	private static final String RTTI_2_NAME = "RTTI Base Class Array";

	// The following count variable is only for initializing the model. 
	// Get the actual number of RTTI 1 entries from the model directly using model.getCount().
	private int rtti1Count;

	/**
	 * Constructs a command for applying an RTTI2 dataType at an address.
	 * @param address the address where the data should be created using the data type.
	 * @param rtti1Count the number of RTTI1 data types expected at the RTTI2 address.
	 * @param validationOptions the options for controlling how validation is performed when 
	 * determining whether or not to create the data structure at the indicated address.
	 * @param applyOptions the options for creating the new data structure and its associated
	 * markup in the program as well as whether to follow other data references and create their 
	 * data too.
	 */
	public CreateRtti2BackgroundCmd(Address address, int rtti1Count,
			DataValidationOptions validationOptions, DataApplyOptions applyOptions) {
		super(Rtti2Model.DATA_TYPE_NAME, address, 1, validationOptions, applyOptions);
		this.rtti1Count = rtti1Count;
	}

	/**
	 * Constructs a command for applying an RTTI2 dataType at the address indicated by the 
	 * model.
	 * @param rtti2Model the model for the data type
	 * @param applyOptions the options for creating the new data structure and its associated
	 * markup in the program as well as whether to follow other data references and create their 
	 * data too.
	 */
	CreateRtti2BackgroundCmd(Rtti2Model rtti2Model, DataApplyOptions applyOptions) {
		super(rtti2Model, applyOptions);
	}

	@Override
	protected Rtti2Model createModel(Program program) {
		if (model == null || program != model.getProgram()) {
			model = new Rtti2Model(program, rtti1Count, getDataAddress(), validationOptions);
		}
		return model;
	}

	@Override
	protected boolean createAssociatedData() throws CancelledException {
		return createRtti1s();
	}

	private boolean createRtti1s() throws CancelledException {

		int itemCount = model.getCount();
		// Loop over the RTTI 1 pointers and create referenced RTTI 1 structures.
		for (int rtti1Index = 0; rtti1Index < itemCount; rtti1Index++) {
			try {
				if (!createRtti1(rtti1Index)) {
					return false; // Failed to create the RTTI1 data, markup, or associated data.
				}
			}
			catch (InvalidDataTypeException e) {
				return false; // Failed to create the RTTI1 data, markup, or associated data.
			}
		}
		return true;
	}

	private boolean createRtti1(int rtti1Index)
			throws CancelledException, InvalidDataTypeException {

		monitor.checkCanceled();

		CreateRtti1BackgroundCmd cmd =
			new CreateRtti1BackgroundCmd(model.getRtti1Model(rtti1Index), applyOptions);
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
			shouldCreateComment = RttiUtil.createSymbolFromDemangledType(program, getDataAddress(), rtti0Model, RTTI_2_NAME);
		}

		// Plate Comment
		if (shouldCreateComment) {
			// comment created if a label was created, or createLabel option off
			EHDataTypeUtilities.createPlateCommentIfNeeded(program,
				RttiUtil.getDescriptorTypeNamespace(rtti0Model) + Namespace.DELIMITER,
				RTTI_2_NAME, null, getDataAddress(), applyOptions);
		}
		
		return true;
	}

}
