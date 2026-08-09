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
package ghidra.app.plugin.core.debug.gui.emulation;

import docking.widgets.table.DefaultEnumeratedColumnTableModel;
import docking.widgets.table.EnumeratedTableColumn;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.MessageType;

class VarTableModel<C extends java.lang.Enum<C> & EnumeratedTableColumn<C, R>, R extends VarRow>
		extends DefaultEnumeratedColumnTableModel<C, R> {

	protected final DebuggerEmulateFunctionDialog dialog;
	protected final Function function;

	public VarTableModel(ServiceProvider tool, String name, Class<C> colType,
			DebuggerEmulateFunctionDialog dialog) {
		super(tool, name, colType);
		this.dialog = dialog;
		this.function = dialog.function;
	}

	ServiceProvider getServiceProvider() {
		return serviceProvider;
	}

	Function getFunction() {
		return function;
	}

	Program getProgram() {
		return function.getProgram();
	}

	DataTypeManager getDataTypeManager() {
		return function.getProgram().getDataTypeManager();
	}

	@Override
	public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
		try {
			super.setValueAt(aValue, rowIndex, columnIndex);
			dialog.clearStatusText();
		}
		catch (Exception e) {
			dialog.setStatusText(e.getMessage(), MessageType.ERROR);
		}
	}

	DebuggerEmulateFunctionDialog getDialog() {
		return dialog;
	}
}
