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
package ghidra.util.table.field;

import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Program;
import ghidra.program.util.*;

/**
 * This table column displays the Label for either the program location or the address
 * associated with a row in the table.
 */
public class EOLCommentTableColumn extends
		ProgramLocationTableColumnExtensionPoint<ProgramLocation, String> {

	@Override
	public ProgramLocation getProgramLocation(ProgramLocation rowObject, Settings settings,
			Program program, ServiceProvider serviceProvider) {

		String comment = getEOLComment(rowObject, program);
		if (comment != null) {
			return new EolCommentFieldLocation(program, rowObject.getAddress(), null, null, 0, 0, 0);
		}
		return rowObject;
	}

	@Override
	public String getColumnName() {
		return "EOL Comment";
	}

	@Override
	public String getValue(ProgramLocation rowObject, Settings settings, Program program,
			ServiceProvider serviceProvider) throws IllegalArgumentException {
		return getEOLComment(rowObject, program);
	}

	private String getEOLComment(ProgramLocation loc, Program program)
			throws IllegalArgumentException {
		ProgramLocation location = loc;
		if (loc instanceof VariableLocation) {
			return null;
		}
		Address address = location.getAddress();
		return program.getListing().getComment(CodeUnit.EOL_COMMENT, address);
	}
}
