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
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;

/**
 * This table field displays the Function Purge for either the program location or the address
 * associated with a row in the table.
 */
public class FunctionPurgeTableColumn extends ProgramBasedDynamicTableColumnExtensionPoint<Function, String> {
	
	@Override
    public String getColumnDisplayName(Settings settings) {
        return getColumnName();
    }

	@Override
    public String getColumnName() {
		return "Function Purge";
	}

	@Override
    public String getValue(Function rowObject, Settings settings, Program pgm, 
	        ServiceProvider serviceProvider) throws IllegalArgumentException {
		Function function = rowObject;
		String stringDepth = "UNK";
		int depth = function.getStackPurgeSize();
		switch (depth) {
		case Function.INVALID_STACK_DEPTH_CHANGE:
		    stringDepth = "INV";
		    break;
		case Function.UNKNOWN_STACK_DEPTH_CHANGE:
		    stringDepth = "UNK";
		    break;
		default:
		    if (depth < 0) {
		        stringDepth = "-" + Integer.toHexString(-depth);
		    } else {
		        stringDepth = Integer.toHexString(depth);
		    }
		}
		return stringDepth;
	}
}
