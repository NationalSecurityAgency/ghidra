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

import docking.widgets.table.GTableCellRenderer;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.table.column.AbstractWrapperTypeColumnRenderer;
import ghidra.util.table.column.GColumnRenderer;

public class FunctionBodySizeTableColumn
		extends ProgramBasedDynamicTableColumnExtensionPoint<Function, Integer> {

	private FunctionBodySizeRenderer renderer = new FunctionBodySizeRenderer();

	@Override
	public String getColumnName() {
		return "Function Size";
	}

	@Override
	public Integer getValue(Function rowObject, Settings settings, Program program,
			ServiceProvider serviceProvider) throws IllegalArgumentException {
		return (int) rowObject.getBody().getNumAddresses();
	}

	@Override
	public GColumnRenderer<Integer> getColumnRenderer() {
		return renderer;
	}

	// this renderer disables the default text filtering; this column is only filterable
	// via the column constraint filtering
	private class FunctionBodySizeRenderer extends GTableCellRenderer
			implements AbstractWrapperTypeColumnRenderer<Integer> {
		// body is handled by parents
	}
}
