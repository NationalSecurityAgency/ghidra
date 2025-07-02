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
package ghidra.symz3.gui.field;

import docking.widgets.table.AbstractDynamicTableColumn;
import docking.widgets.table.DynamicTableColumn;
import ghidra.app.plugin.core.debug.gui.register.DebuggerRegisterColumnFactory;
import ghidra.app.plugin.core.debug.gui.register.RegisterRow;
import ghidra.debug.api.tracemgr.DebuggerCoordinates;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.pcode.emu.symz3.trace.SymZ3TracePcodeExecutorStatePiece;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Register;
import ghidra.trace.model.Trace;
import ghidra.trace.model.property.TracePropertyMap;
import ghidra.trace.model.property.TracePropertyMapSpace;

/**
 * A factory for the "Symbolic Expression" column in the "Registers" panel
 * 
 * <p>
 * For the most part, this is just a matter of accessing the property map and rendering the value on
 * screen.
 */
public class SymZ3DebuggerRegisterColumnFactory implements DebuggerRegisterColumnFactory {
	protected static final String PROP_NAME = SymZ3TracePcodeExecutorStatePiece.NAME;
	public static final String COL_NAME = "Symbolic Expression";

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

				TracePropertyMap<String> symMap = current.getTrace()
						.getAddressPropertyManager()
						.getPropertyMap(PROP_NAME, String.class);

				if (symMap == null) {
					return "";
				}

				Register register = rowObject.getRegister();
				TracePropertyMapSpace<String> symSpace;
				AddressSpace addressSpace = register.getAddressSpace();
				if (addressSpace.isRegisterSpace()) {
					symSpace = symMap.getPropertyMapRegisterSpace(current.getThread(),
						current.getFrame(), false);
				}
				else {
					symSpace = symMap.getPropertyMapSpace(addressSpace, false);
				}
				if (symSpace == null) {
					return "";
				}

				// Cheat the deserialization/reserialization here
				String display = symSpace.get(current.getViewSnap(), register.getAddress());
				return display == null ? "" : display;
			}
		};
	}
}
