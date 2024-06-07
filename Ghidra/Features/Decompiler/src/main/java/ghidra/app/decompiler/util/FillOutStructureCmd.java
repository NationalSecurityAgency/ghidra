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
package ghidra.app.decompiler.util;

import java.util.Objects;

import ghidra.app.decompiler.*;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.framework.cmd.BackgroundCommand;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.*;
import ghidra.util.Msg;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

/**
 * Automatically creates a structure definition based on the references found by the decompiler.
 *
 * If the parameter is already a structure pointer, any new references found will be added
 * to the structure, even if the structure must grow.
 *
 */
public class FillOutStructureCmd extends BackgroundCommand<Program> {

	private DecompileOptions decompileOptions;
	private ProgramLocation location;

	/**
	 * Constructor.
	 * 
	 * @param location the current program location.  Supported location types include:
	 *   {@link DecompilerLocation}, {@link VariableLocation} or 
	 *   {@link FunctionParameterFieldLocation}.
	 * @param decompileOptions decompiler options.  
	 *   (see {@link DecompilerUtils#getDecompileOptions(ServiceProvider, Program)})
	 */
	public FillOutStructureCmd(ProgramLocation location, DecompileOptions decompileOptions) {
		super("Fill Out Structure", true, false, true);
		this.decompileOptions = Objects.requireNonNull(decompileOptions);
		this.location = Objects.requireNonNull(location);
	}

	@Override
	public boolean applyTo(Program program, TaskMonitor monitor) {

		if (program != location.getProgram()) {
			throw new AssertionError("program does not match location");
		}

		try {
			Function function =
				program.getFunctionManager().getFunctionContaining(location.getAddress());
			if (function == null) {
				setStatusMsg("Function not found at " + location.getAddress());
				return false;
			}

			FillOutStructureHelper fillStructureHelper =
				new FillOutStructureHelper(program, decompileOptions, monitor);

			HighVariable var = null;

			if (!(location instanceof DecompilerLocation dloc)) {
				// if we don't have one, make one, and map variable to a varnode
				Address storageAddr = computeStorageAddress(function);
				var = fillStructureHelper.computeHighVariable(storageAddr, function);
			}
			else {

				// get the Varnode under the cursor
				ClangToken token = dloc.getToken();
				if (token == null) {
					setStatusMsg("Unable to identify variable from decompiler token");
					return false;
				}

				var = token.getHighVariable();
				Varnode exactSpot = token.getVarnode();

				if ((var != null) && (exactSpot != null)) {
					HighFunction hfunc = var.getHighFunction();
					try { // Adjust HighVariable based on exact varnode selected, if there are merged groups
						var = hfunc.splitOutMergeGroup(var, exactSpot);
					}
					catch (PcodeException ex) {
						setStatusMsg("Unable to isolate variable from merged group");
						return false;
					}
				}
			}

			Structure structDT = fillStructureHelper.processStructure(var, function, false, true);
			if (structDT == null) {
				setStatusMsg("Failed to fill-out structure");
				return false;
			}

			DataType pointerDT = new PointerDataType(structDT);

			// Delay adding to the manager until full structure is accumulated
			pointerDT = program.getDataTypeManager()
					.addDataType(pointerDT, DataTypeConflictHandler.DEFAULT_HANDLER);

			boolean isThisParam = DecompilerUtils.testForAutoParameterThis(var, function);
			if (!isThisParam) {
				commitVariable(var, pointerDT, isThisParam);
			}

			return true;
		}
		catch (Exception e) {
			Msg.showError(this, null, "Auto Create Structure Failed",
				"Failed to create Structure variable", e);
		}
		return false;
	}

	/**
	 * Retype the HighVariable to a given data-type to the database
	 * @param var is the decompiler variable to retype
	 * @param newDt is the data-type
	 * @param isThisParam is true if the variable is a 'this' pointer
	 */
	private void commitVariable(HighVariable var, DataType newDt, boolean isThisParam) {
		if (!isThisParam) {
			try {
				HighFunctionDBUtil.updateDBVariable(var.getSymbol(), null, newDt,
					SourceType.USER_DEFINED);
			}
			catch (DuplicateNameException e) {
				throw new AssertException("Unexpected exception", e);
			}
			catch (InvalidInputException e) {
				Msg.error(this,
					"Failed to re-type variable " + var.getName() + ": " + e.getMessage());
			}
		}
	}

	/**
	 * Compute the storage address associated with a particular Location
	 * @param function is the function owning the location
	 * @return the corresponding storage address or null
	 */
	private Address computeStorageAddress(Function function) {

		Address storageAddress = null;

		// make sure what we are over can be mapped to decompiler
		// param, local, etc...

		if (location instanceof VariableLocation) {
			VariableLocation varLoc = (VariableLocation) location;
			storageAddress = varLoc.getVariable().getVariableStorage().getMinAddress();
		}
		else if (location instanceof FunctionParameterFieldLocation) {
			FunctionParameterFieldLocation funcPFL = (FunctionParameterFieldLocation) location;
			storageAddress = funcPFL.getParameter().getVariableStorage().getMinAddress();
		}
		return storageAddress;
	}

}
