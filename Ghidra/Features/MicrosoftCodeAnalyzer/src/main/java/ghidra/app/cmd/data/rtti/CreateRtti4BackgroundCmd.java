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

import java.util.List;
import java.util.Set;

import ghidra.app.cmd.data.*;
import ghidra.app.util.datatype.microsoft.DataApplyOptions;
import ghidra.app.util.datatype.microsoft.DataValidationOptions;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.util.ProgramMemoryUtil;
import ghidra.util.exception.CancelledException;

/**
 * This command will create an RTTI4 data type. 
 * If there are any existing instructions in the area to be made into data, the command will fail.
 * Any data in the area will be replaced with the new dataType.
 */
public class CreateRtti4BackgroundCmd extends AbstractCreateDataBackgroundCmd<Rtti4Model> {

	private static final String RTTI_4_NAME = "RTTI Complete Object Locator";
	private List<MemoryBlock> vfTableBlocks;

	/**
	 * Constructs a command for applying an RTTI4 dataType at an address.
	 * @param address the address where the data should be created using the data type.
	 * @param vfTableBlocks a list of the only memory blocks to be searched for vf tables.
	 * @param validationOptions the options for controlling how validation is performed when 
	 * determining whether or not to create the data structure at the indicated address.
	 * @param applyOptions the options for creating the new data structure and its associated
	 * markup in the program as well as whether to follow other data references and create their 
	 * data too.
	 */
	public CreateRtti4BackgroundCmd(Address address, List<MemoryBlock> vfTableBlocks,
			DataValidationOptions validationOptions, DataApplyOptions applyOptions) {

		super(Rtti4Model.DATA_TYPE_NAME, address, 1, validationOptions, applyOptions);
		this.vfTableBlocks = vfTableBlocks;
	}

	@Override
	protected Rtti4Model createModel(Program program) {
		if (model == null || program != model.getProgram()) {
			model = new Rtti4Model(program, address, validationOptions);
		}
		return model;
	}

	@Override
	protected boolean createAssociatedData() throws CancelledException {

		monitor.checkCanceled();

		boolean createRtti0Success;
		try {
			createRtti0Success = createRtti0();
		}
		catch (InvalidDataTypeException e) {
			createRtti0Success = false;
			// log message and continue with other markup.
			handleErrorMessage(model.getProgram(), model.getAddress(), e.getMessage());
		}

		boolean createRtti3Success;
		try {
			createRtti3Success = createRtti3();
		}
		catch (InvalidDataTypeException e) {
			createRtti3Success = false;
			// log message and continue with other markup.
			handleErrorMessage(model.getProgram(), model.getAddress(), e.getMessage());
		}

		boolean createVfTableSuccess = createVfTable();

		return createRtti0Success && createRtti3Success && createVfTableSuccess;
	}

	private boolean createRtti0() throws CancelledException, InvalidDataTypeException {

		monitor.checkCanceled();

		CreateTypeDescriptorBackgroundCmd cmd =
			new CreateTypeDescriptorBackgroundCmd(model.getRtti0Model(), applyOptions);
		return cmd.applyTo(model.getProgram(), monitor);
	}

	private boolean createRtti3() throws CancelledException, InvalidDataTypeException {

		monitor.checkCanceled();

		CreateRtti3BackgroundCmd cmd =
			new CreateRtti3BackgroundCmd(model.getRtti3Model(), applyOptions);
		return cmd.applyTo(model.getProgram(), monitor);
	}

	private boolean createVfTable() throws CancelledException {

		monitor.checkCanceled();

		Program program = model.getProgram();

		Address rtti4Address = address;
		int defaultPointerSize = program.getDefaultPointerSize();
		int alignment = defaultPointerSize; // Align the vf table based on the size of the pointers in it.
		Set<Address> directRtti4Refs =
			ProgramMemoryUtil.findDirectReferences(program, vfTableBlocks, alignment, rtti4Address,
				monitor);

		VfTableModel validVfTableModel = null;
		for (Address possibleVfMetaAddr : directRtti4Refs) {

			monitor.checkCanceled();

			Address possibleVfTableAddr = possibleVfMetaAddr.add(defaultPointerSize);

			// Validate the model. Don't apply the command if invalid.
			try {
				VfTableModel vfTableModel =
					new VfTableModel(program, possibleVfTableAddr, validationOptions);
				vfTableModel.validate();

				if (validVfTableModel != null) {
					String message = "More than one possible vfTable found for " +
						Rtti4Model.DATA_TYPE_NAME + " @ " + rtti4Address;
					handleErrorMessage(program, rtti4Address, message);
					return false;
				}
				validVfTableModel = vfTableModel;
			}
			catch (InvalidDataTypeException e) {
				continue; // This isn't a valid model.
			}
		}

		if (validVfTableModel == null) {
			String message =
				"No vfTable found for " + Rtti4Model.DATA_TYPE_NAME + " @ " + rtti4Address;
			handleErrorMessage(program, rtti4Address, message);
			return false;
		}

		monitor.checkCanceled();

		CreateVfTableBackgroundCmd cmd =
			new CreateVfTableBackgroundCmd(validVfTableModel, applyOptions);
		return cmd.applyTo(program, monitor);
	}

	@Override
	protected boolean createMarkup() throws CancelledException, InvalidDataTypeException {

		monitor.checkCanceled();

		Program program = model.getProgram();
		TypeDescriptorModel rtti0Model = model.getRtti0Model();

		monitor.checkCanceled();

		if (rtti0Model != null) {

			// Plate Comment
			EHDataTypeUtilities.createPlateCommentIfNeeded(program, RttiUtil.CONST_PREFIX +
				RttiUtil.getDescriptorTypeNamespace(rtti0Model) + Namespace.DELIMITER,
				RTTI_4_NAME, null, address, applyOptions);

			monitor.checkCanceled();

			// Label
			if (applyOptions.shouldCreateLabel()) {
				RttiUtil.createSymbolFromDemangledType(program, address, rtti0Model, RTTI_4_NAME);
			}
		}

		return true;
	}

}
