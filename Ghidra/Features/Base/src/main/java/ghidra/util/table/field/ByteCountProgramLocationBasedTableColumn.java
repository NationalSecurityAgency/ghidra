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
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.util.ProgramLocation;

public class ByteCountProgramLocationBasedTableColumn extends
		ProgramLocationTableColumnExtensionPoint<ProgramLocation, Integer> {

	@Override
	public String getColumnName() {
		return "Byte Count";
	}

	@Override
	public Integer getValue(ProgramLocation rowObject, Settings settings, Program program,
			ServiceProvider serviceProvider) throws IllegalArgumentException {

		CodeUnit cu = program.getListing().getCodeUnitContaining(rowObject.getAddress());
		if (cu == null) { // can happen for 'SpecialAddress'es
			return 0;
		}

		try {
			return cu.getBytes().length;
		}
		catch (MemoryAccessException e) {
			return 0;
		}
	}

	@Override
	public ProgramLocation getProgramLocation(ProgramLocation rowObject, Settings settings,
			Program program, ServiceProvider serviceProvider) {
		return rowObject;
	}

}
