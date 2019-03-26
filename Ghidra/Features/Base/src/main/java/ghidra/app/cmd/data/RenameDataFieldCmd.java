/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.app.cmd.data;

import ghidra.framework.cmd.Command;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.util.exception.DuplicateNameException;


/**
 * Command to rename a component in a data type. 
 *
 */
public class RenameDataFieldCmd implements Command {
	
	private DataTypeComponent comp;
	private String newName;

	private String statusMsg = "";
	
	/**
	 * Construct a new RenameDataFieldCmd.
	 * @param comp component in data type to be renamed
	 * @param newName new name for the component
	 */
	public RenameDataFieldCmd(DataTypeComponent comp, String newName) {
		this.comp = comp;
		this.newName = newName;
	}

	/*
	 *  (non-Javadoc)
	 * @see ghidra.framework.cmd.Command#applyTo(ghidra.framework.model.DomainObject)
	 */
	public boolean applyTo(DomainObject obj) {
		if (comp == null) {
			statusMsg = "Null data type";
			return false;
		}
		try {
			comp.setFieldName(newName);
			return true;
		} catch(DuplicateNameException e) {
			statusMsg = "Type name already exists: " + newName;
		}
		return false;
	}

	/*
	 *  (non-Javadoc)
	 * @see ghidra.framework.cmd.Command#getStatusMsg()
	 */
	public String getStatusMsg() {
		return statusMsg;
	}

	/*
	 *  (non-Javadoc)
	 * @see ghidra.framework.cmd.Command#getName()
	 */
	public String getName() {
		return "Rename Data Field";
	}
}
