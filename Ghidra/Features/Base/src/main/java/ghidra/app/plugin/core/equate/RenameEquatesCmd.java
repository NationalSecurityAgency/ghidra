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
package ghidra.app.plugin.core.equate;

import ghidra.framework.cmd.Command;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.*;

/**
 * Command for moving all references to an equate to some other equate. If an equate
 * for the new name does not exist, it will be created and all references will be moved
 * to it before deleting the original equate.  If an equate already exists with that
 * name (it better have the correct value or we shouldn't have gotten this far!), its
 * references will be merged with the original equate references.  The undo method
 * will restore everything back to where it was when this object was created.  The
 * redo method will repeat the rename operation.
 */
class RenameEquatesCmd implements Command<Program> {

	private String newEquateName;
	private String oldEquateName;

	private String msg;

	/**
	 * Constructor
	 * @param oldEquateName the name of equate to be renamed.
	 * @param newEquateName the new name for the equate
	 */
	RenameEquatesCmd(String oldEquateName, String newEquateName) {
		this.oldEquateName = oldEquateName;
		this.newEquateName = newEquateName;
	}

	@Override
	public String getName() {
		return "Rename Equates";
	}

	@Override
	public boolean applyTo(Program program) {
		EquateTable etable = program.getEquateTable();

		// See if there's an entry in the table for the old equate name.  There should be,
		// otherwise there's a problem.
		Equate fromEquate = etable.getEquate(oldEquateName);
		if (fromEquate == null) {
			msg = "Equate not found: " + oldEquateName;
			return false;
		}

		// Now get the entry in the Equate table for the new equate name.  If there's
		// already an entry with this name, just use that...otherwise, create a new one.
		Equate toEquate = etable.getEquate(newEquateName);
		if (toEquate == null) {
			try {
				toEquate = etable.createEquate(newEquateName, fromEquate.getValue());
			}
			catch (DuplicateNameException e) {
				throw new AssertException();
			}
			catch (InvalidInputException e) {
				msg = "Invalid equate name: " + newEquateName;
				return false;
			}
		}

		// Finally, move all references to the old equate to the new one.
		EquateReference[] refList = fromEquate.getReferences();
		etable.removeEquate(oldEquateName);
		for (EquateReference element : refList) {
			toEquate.addReference(element.getAddress(), element.getOpIndex());
		}
		return true;
	}

	@Override
	public String getStatusMsg() {
		return msg;
	}

}
