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
package ghidra.app.cmd.data;

import java.util.Objects;

import ghidra.framework.cmd.Command;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;

/**
 * Command to rename a component in a {@link Composite} data type. 
 *
 */
public class RenameDataFieldCmd implements Command<Program> {

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

	@Override
	public boolean applyTo(Program program) {
		if (comp == null) {
			statusMsg = "Null data type";
			return false;
		}

		String name = InternalDataTypeComponent.cleanupFieldName(newName);

		if (!Objects.equals(name, comp.getFieldName())) {
			comp = comp.setFieldName(newName);
			if (!Objects.equals(name, comp.getFieldName())) {
				statusMsg = "Unable to rename component";
				return false;
			}
		}

		return true;
	}

	@Override
	public String getStatusMsg() {
		return statusMsg;
	}

	/*
	 *  (non-Javadoc)
	 * @see ghidra.framework.cmd.Command#getName()
	 */
	@Override
	public String getName() {
		return "Rename Data Field";
	}
}
