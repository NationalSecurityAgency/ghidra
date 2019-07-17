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

import ghidra.app.services.DataTypeManagerService;
import ghidra.framework.cmd.Command;
import ghidra.framework.model.DomainObject;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.framework.store.FileSystem;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;

/**
 * Command for creating a function definition data type based on the
 * function signature for a function at an address.  
 */
public class CreateFunctionDefinitionCmd implements Command {
	private Address entry;
	private final ServiceProvider serviceProvider;
	private String statusMsg = "";

	/**
	 * Constructs a new command for creating a function definition.
	 * @param entry entry point address for the function whose signature is to 
	 * be used to create the function defintion data type.
	 */
	public CreateFunctionDefinitionCmd(Address entry, ServiceProvider serviceProvider) {
		this.entry = entry;
		this.serviceProvider = serviceProvider;
	}

	/**
	 * 
	 * @see ghidra.framework.cmd.Command#getName()
	 */
	@Override
	public String getName() {
		return "Create Function Definition";
	}

	/**
	 * 
	 * @see ghidra.framework.cmd.Command#applyTo(ghidra.framework.model.DomainObject)
	 */
	@Override
	public boolean applyTo(DomainObject obj) {
		Program program = (Program) obj;
		// save off the function signature
		//   get the body, comment, stack, return type
		Listing listing = program.getListing();
		DataTypeManager dtm = listing.getDataTypeManager();
		Function func = listing.getFunctionAt(entry);
		if (func == null) {
			return false;
		}
		FunctionSignature sig;
		try {
			sig = func.getSignature(true);
		}
		catch (IllegalArgumentException e) {
			if (func.getName().indexOf(FileSystem.SEPARATOR_CHAR) >= 0) {
				statusMsg = "Datatype names can not contain a '" + FileSystem.SEPARATOR_CHAR + "'";
			}
			else {
				statusMsg = e.getMessage();
			}
			return false;
		}
		FunctionDefinitionDataType functionDef = new FunctionDefinitionDataType(sig);
		DataType newType = dtm.resolve(functionDef, null);

		DataTypeManagerService service = serviceProvider.getService(DataTypeManagerService.class);
		if (service != null) {
			service.setDataTypeSelected(newType);
		}

		return true;
	}

	/**
	 * @see ghidra.framework.cmd.Command#getStatusMsg()
	 */
	@Override
	public String getStatusMsg() {
		return statusMsg;
	}

}
