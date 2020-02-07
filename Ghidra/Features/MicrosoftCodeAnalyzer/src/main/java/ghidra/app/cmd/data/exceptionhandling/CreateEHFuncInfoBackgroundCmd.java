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
import ghidra.program.model.lang.UndefinedValueException;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;

/**
 * This command will create a FuncInfo exception handler data type. 
 * If there are any existing instructions in the area to be made into data, the command will fail.
 * Any data in the area will be replaced with the new dataType.
 */
public class CreateEHFuncInfoBackgroundCmd
		extends AbstractCreateDataBackgroundCmd<EHFunctionInfoModel> {

	/**
	 * Constructs a command for applying a FuncInfo exception handling dataType at an address.
	 * @param address the address where the data should be created using the data type.
	 */
	public CreateEHFuncInfoBackgroundCmd(Address address) {
		super(EHFunctionInfoModel.DATA_TYPE_NAME, address, 1);
	}

	/**
	 * Constructs a command for applying a FuncInfo exception handling dataType at an address.
	 * @param address the address where the data should be created using the data type.
	 * @param validationvalidationOptions, applyOptions the options for controlling how validation is performed when 
	 * determining whether or not to create the data structure at the indicated address.
	 * @param applyOptions the options for creating the new data structure and its associated
	 * markup in the program as well as whether to follow other data references and create their 
	 * data too.
	 */
	public CreateEHFuncInfoBackgroundCmd(Address address, DataValidationOptions validationOptions,
			DataApplyOptions applyOptions) {
		super(EHFunctionInfoModel.DATA_TYPE_NAME, address, 1, validationOptions, applyOptions);
	}

	/**
	 * Constructs a command for applying a FuncInfo exception handling data type at the 
	 * address indicated by the model.
	 * @param funcInfoModel the model for the data type
	 * @param applyOptions the options for creating the new data structure and its associated
	 * markup in the program as well as whether to follow other data references and create their 
	 * data too.
	 */
	CreateEHFuncInfoBackgroundCmd(EHFunctionInfoModel funcInfoModel,
			DataApplyOptions applyOptions) {
		super(funcInfoModel, applyOptions);
	}

	@Override
	protected EHFunctionInfoModel createModel(Program program) {
		if (model == null) {
			model = new EHFunctionInfoModel(program, getDataAddress(), validationOptions);
		}
		return model;
	}

	@Override
	protected boolean createAssociatedData() throws CancelledException {
		// If this is being called then the model should be valid.
		boolean unwindMapSuccess = createUnwindMapEntries();
		boolean tryBlockMapSuccess = createTryBlockMapEntries();
		boolean ipToStateMapSuccess = createIPToStateMapEntries();
		boolean typeListSuccess = createESTypeListEntries();
		return unwindMapSuccess && tryBlockMapSuccess && ipToStateMapSuccess && typeListSuccess;
	}

	private boolean createUnwindMapEntries() throws CancelledException {
		monitor.setMessage("Creating UnwindMap");
		monitor.checkCanceled();

		Address compAddress;
		Address unwindMapAddress;
		int unwindCount;
		try {
			compAddress = model.getComponentAddressOfUnwindMapAddress();
			unwindMapAddress = model.getUnwindMapAddress();
			unwindCount = model.getUnwindCount();
		}
		catch (InvalidDataTypeException e) {
			throw new AssertException(e); // Shouldn't happen. create...() is only called if model is valid.
		}

		if (unwindMapAddress == null || (unwindCount == 0)) {
			return true; // No unwind info to create.
		}

		EHUnwindModel unwindModel;
		try {
			unwindModel = model.getUnwindModel();
		}
		catch (InvalidDataTypeException e) {
			throw new AssertException(e); // Shouldn't happen. create...() is only called if model is valid.
		}
		try {
			unwindModel.validate();
		}
		catch (InvalidDataTypeException e1) {
			handleErrorMessage(model.getProgram(), unwindModel.getName(), unwindMapAddress,
				compAddress, e1);
			return false;
		}

		CreateEHUnwindMapBackgroundCmd cmd =
			new CreateEHUnwindMapBackgroundCmd(unwindModel, applyOptions);
		return cmd.applyTo(model.getProgram(), monitor);
	}

	private boolean createTryBlockMapEntries() throws CancelledException {
		monitor.setMessage("Creating TryBlockMap");
		monitor.checkCanceled();

		Address compAddress;
		Address tryBlockMapAddress;
		int tryBlockCount;
		try {
			compAddress = model.getComponentAddressOfTryBlockMapAddress();
			tryBlockMapAddress = model.getTryBlockMapAddress();
			tryBlockCount = model.getTryBlockCount();
		}
		catch (InvalidDataTypeException e) {
			throw new AssertException(e); // Shouldn't happen. create...() is only called if model is valid.
		}

		if (tryBlockMapAddress == null || tryBlockCount == 0) {
			return true; // No try block info to create.
		}

		EHTryBlockModel tryBlockModel;
		try {
			tryBlockModel = model.getTryBlockModel();
		}
		catch (InvalidDataTypeException e) {
			throw new AssertException(e); // Shouldn't happen. create...() is only called if model is valid.
		}
		try {
			tryBlockModel.validate();
		}
		catch (InvalidDataTypeException e1) {
			handleErrorMessage(model.getProgram(), tryBlockModel.getName(), tryBlockMapAddress,
				compAddress, e1);
			return false;
		}

		CreateEHTryBlockMapBackgroundCmd cmd =
			new CreateEHTryBlockMapBackgroundCmd(tryBlockModel, applyOptions);
		return cmd.applyTo(model.getProgram(), monitor);
	}

	private boolean createIPToStateMapEntries() throws CancelledException {
		monitor.setMessage("Creating IPToStateMap");
		monitor.checkCanceled();

		Address compAddress;
		Address ipToStateMapAddress;
		int ipToStateCount;
		try {
			compAddress = model.getComponentAddressOfIPToStateMapAddress();
			ipToStateMapAddress = model.getIPToStateMapAddress();
			ipToStateCount = model.getIPToStateCount();
		}
		catch (InvalidDataTypeException e) {
			throw new AssertException(e); // Shouldn't happen. create...() is only called if model is valid.
		}

		if (ipToStateMapAddress == null || ipToStateCount == 0) {
			return true; // No IP to state info to create.
		}

		EHIPToStateModel ipToStateModel;
		try {
			ipToStateModel = model.getIPToStateModel();
		}
		catch (InvalidDataTypeException e) {
			throw new AssertException(e); // Shouldn't happen. create...() is only called if model is valid.
		}
		try {
			ipToStateModel.validate();
		}
		catch (InvalidDataTypeException e1) {
			handleErrorMessage(model.getProgram(), ipToStateModel.getName(), ipToStateMapAddress,
				compAddress, e1);
			return false;
		}

		CreateEHIPToStateMapBackgroundCmd cmd =
			new CreateEHIPToStateMapBackgroundCmd(ipToStateModel, applyOptions);
		return cmd.applyTo(model.getProgram(), monitor);
	}

	private boolean createESTypeListEntries() throws CancelledException {
		monitor.setMessage("Creating ESTypeList");
		monitor.checkCanceled();

		Address compAddress;
		Address esTypeListAddress;
		EHESTypeListModel esTypeListModel;
		try {
			compAddress = model.getComponentAddressOfESTypeListAddress();
			esTypeListAddress = model.getESTypeListAddress();
			esTypeListModel = model.getESTypeListModel();
		}
		catch (UndefinedValueException e) {
			return true; // No ES type list to create.
		}
		catch (InvalidDataTypeException e) {
			throw new AssertException(e); // Shouldn't happen. create...() is only called if model is valid.
		}
		if (esTypeListAddress == null) {
			return true; // No ES type list to create.
		}

		try {
			esTypeListModel.validate();
		}
		catch (InvalidDataTypeException e1) {
			handleErrorMessage(model.getProgram(), esTypeListModel.getName(), esTypeListAddress,
				compAddress, e1);
			return false;
		}

		CreateEHESTypeListBackgroundCmd cmd =
			new CreateEHESTypeListBackgroundCmd(esTypeListModel, applyOptions);
		return cmd.applyTo(model.getProgram(), monitor);
	}

	@Override
	protected boolean createMarkup() throws CancelledException {

		return true; // No markup.
	}
}
