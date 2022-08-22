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
package ghidra.taint.gui.field;

import docking.widgets.table.AbstractDynamicTableColumn;
import docking.widgets.table.DynamicTableColumn;
import ghidra.app.plugin.core.debug.DebuggerCoordinates;
import ghidra.app.plugin.core.debug.gui.register.DebuggerRegisterColumnFactory;
import ghidra.app.plugin.core.debug.gui.register.RegisterRow;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.pcode.emu.taint.trace.TaintTracePcodeExecutorStatePiece;
import ghidra.trace.model.Trace;

/**
 * A factory for the "Taint" column in the "Registers" panel
 * 
 * <p>
 * For the most part, this is just a matter of accessing the property map and rendering the value on
 * screen. As a cheap shortcut, we'll just instantiate a taint state piece at the panel's
 * coordinates and use it to retrieve the actual taint marks, then render that for display.
 */
public class TaintDebuggerRegisterColumnFactory implements DebuggerRegisterColumnFactory {
	protected static final String PROP_NAME = TaintTracePcodeExecutorStatePiece.NAME;
	public static final String COL_NAME = "Taint";

	@Override
	public DynamicTableColumn<RegisterRow, ?, ?> create() {
		return new AbstractDynamicTableColumn<RegisterRow, String, Void>() {
			@Override
			public String getColumnName() {
				return COL_NAME;
			}

			@Override
			public String getValue(RegisterRow rowObject, Settings settings, Void data,
					ServiceProvider serviceProvider) throws IllegalArgumentException {
				DebuggerCoordinates current = rowObject.getCurrent();
				Trace trace = current.getTrace();
				if (trace == null) {
					return "";
				}

				TaintTracePcodeExecutorStatePiece piece =
					new TaintTracePcodeExecutorStatePiece(current.getTrace(), current.getViewSnap(),
						current.getThread(), current.getFrame());

				return piece.getVar(rowObject.getRegister()).toDisplay();
			}
		};
	}
}
