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
package ghidra.app.cmd.function;

import ghidra.framework.cmd.BackgroundCommand;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Capture all selected function signature data types from the current program and put them 
 * in the data type manager.
 */
public class CaptureFunctionDataTypesCmd extends BackgroundCommand {
	private Program program;
	private DataTypeManager dtm;
	private AddressSetView set;
	private CaptureFunctionDataTypesListener listener;

	/**
	 * Constructs a new command to create function definition data types
	 * in the given data type manager from the function's whose entry points are in the
	 * address set.
	 * @param dtm data type manager containing the function signature data types
	 * @param set set of addresses containing the entry points of the functions whose signatures
	 * are to be turned into data types.
	 */
	public CaptureFunctionDataTypesCmd(DataTypeManager dtm, AddressSetView set,
			CaptureFunctionDataTypesListener listener) {
		super("Capture Function Data Types", true, false, false);
		this.dtm = dtm;
		this.set = set;
		this.listener = listener;
	}

	/**
	 * 
	 * @see ghidra.framework.cmd.BackgroundCommand#applyTo(ghidra.framework.model.DomainObject, ghidra.util.task.TaskMonitor)
	 */
	@Override
	public boolean applyTo(DomainObject obj, TaskMonitor monitor) {
		program = (Program) obj;

		monitor.setMessage("Capturing Function Data Types");
		boolean success = false;
		int transactionID = dtm.startTransaction("Capture function data types");
		CategoryPath category =
			new CategoryPath(CategoryPath.ROOT, "_CAPTURED_FROM_" + program.getName());
		try {
			FunctionManager functionManager = program.getFunctionManager();
			FunctionIterator functions = functionManager.getFunctions(set, true);
			while (functions.hasNext()) {
				monitor.checkCanceled();
				Function function = functions.next();
				FunctionSignature signature = function.getSignature(true);
				FunctionDefinitionDataType functionDef =
					new FunctionDefinitionDataType(category, signature.getName(), signature);
				dtm.resolve(functionDef, null);
			}
			success = true;
		}
		catch (CancelledException e) {
			// success flag will be false
		}
		finally {
			dtm.endTransaction(transactionID, success);
		}
		return success;
	}

	@Override
	public void taskCompleted() {
		listener.captureFunctionDataTypesCompleted(this);
		super.taskCompleted();
	}

}
