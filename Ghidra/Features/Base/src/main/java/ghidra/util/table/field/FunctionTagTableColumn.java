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

import java.util.stream.Collectors;

import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;

/**
 * Table column for displaying all function tags associated with a given function. Tags
 * will be displayed as a set of comma-delimited strings, in sorted order.
 */
public class FunctionTagTableColumn
		extends ProgramBasedDynamicTableColumnExtensionPoint<Function, String> {

	@Override
	public String getColumnName() {
		return "Tags";
	}

	@Override
	public String getValue(Function rowObject, Settings settings, Program data,
			ServiceProvider serviceProvider) throws IllegalArgumentException {

		//@formatter:off
		return rowObject.getTags().stream()
								  .sorted()
								  .map(t -> t.getName())
								  .collect(Collectors.joining(", "));
		//@formatter:on
	}
}
