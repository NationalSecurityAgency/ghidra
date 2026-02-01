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

import java.awt.Component;
import java.util.Objects;

import docking.widgets.table.*;
import ghidra.app.plugin.core.debug.gui.register.*;
import ghidra.debug.api.tracemgr.DebuggerCoordinates;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.pcode.emu.taint.state.TaintPieceHandler;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.trace.model.property.TracePropertyMap;
import ghidra.trace.model.property.TracePropertyMapSpace;
import ghidra.trace.model.thread.TraceThread;
import ghidra.util.table.column.AbstractGColumnRenderer;
import ghidra.util.table.column.GColumnRenderer;

/**
 * A factory for the "Taint" column in the "Registers" panel
 * 
 * <p>
 * For the most part, this is just a matter of accessing the property map and rendering the value on
 * screen.
 */
public class TaintDebuggerRegisterColumnFactory implements DebuggerRegisterColumnFactory {
	private static TracePropertyMapSpace<String> getTaintSpace(DebuggerCoordinates coords,
			Register register) {
		TracePropertyMap<String> taintMap =
			coords.getTrace().getAddressPropertyManager().getPropertyMap(PROP_NAME, String.class);

		if (taintMap == null) {
			return null;
		}

		AddressSpace addressSpace = register.getAddressSpace();
		if (addressSpace.isRegisterSpace()) {
			return taintMap.getPropertyMapRegisterSpace(coords.getThread(),
				coords.getFrame(), false);
		}
		return taintMap.getPropertyMapSpace(addressSpace, false);
	}

	private static String getTaintValue(DebuggerCoordinates coords,
			TracePropertyMapSpace<String> taintSpace, Register register) {
		// Cheat the deserialization/reserialization here
		AddressRange range = coords.getPlatform()
				.getConventionalRegisterRange(taintSpace.getAddressSpace(), register);
		StringBuffer vec = new StringBuffer();
		for (Address addr : range) {
			vec.append('[');
			String taint = taintSpace.get(coords.getViewSnap(), addr);
			vec.append(taint == null ? "" : taint);
			vec.append(']');
		}
		return vec.toString();
	}

	private static String getTaintValue(DebuggerCoordinates coords, RegisterRow row) {
		TraceThread thread = coords.getThread();
		if (thread == null) {
			return null;
		}

		Register register = row.getRegister();
		TracePropertyMapSpace<String> taintSpace = getTaintSpace(coords, register);
		if (taintSpace == null) {
			return null;
		}

		return getTaintValue(coords, taintSpace, register);
	}

	private static class TaintDebuggerRegisterCellRenderer extends AbstractGColumnRenderer<String> {
		@Override
		public Component getTableCellRendererComponent(GTableCellRenderingData data) {
			super.getTableCellRendererComponent(data);
			DebuggerRegistersProvider.applyStateColors(this, data, this::isChanged);
			return this;
		}

		@Override
		public String getFilterString(String t, Settings settings) {
			return t;
		}

		private boolean isChanged(RegisterRow row) {
			if (row.getPrevious().getThread() == null || row.getCurrent().getThread() == null) {
				return false;
			}
			if (row.getPrevious().getLanguage() != row.getCurrent().getLanguage()) {
				return false;
			}
			if (!row.isKnown()) {
				return false;
			}
			Register register = row.getRegister();
			TracePropertyMapSpace<String> curTaintSpace =
				getTaintSpace(row.getCurrent(), register);
			if (curTaintSpace == null) {
				return false; // unlikely
			}
			TracePropertyMapSpace<String> prevTaintSpace =
				getTaintSpace(row.getPrevious(), register);
			if (prevTaintSpace == null) {
				return false;
			}
			String curTaintValue = getTaintValue(row.getCurrent(), curTaintSpace, register);
			String prevTaintValue = getTaintValue(row.getPrevious(), prevTaintSpace, register);
			return !Objects.equals(curTaintValue, prevTaintValue);
		}
	}

	private static final TaintDebuggerRegisterCellRenderer RENDERER =
		new TaintDebuggerRegisterCellRenderer();

	private static class TaintDebuggerRegisterColumn
			extends AbstractDynamicTableColumn<RegisterRow, String, Void> {
		@Override
		public String getColumnName() {
			return COL_NAME;
		}

		@Override
		public GColumnRenderer<String> getColumnRenderer() {
			return RENDERER;
		}

		@Override
		public String getValue(RegisterRow rowObject, Settings settings, Void dataSource,
				ServiceProvider serviceProvider) throws IllegalArgumentException {
			String value = getTaintValue(rowObject.getCurrent(), rowObject);
			return value == null ? "" : value;
		}
	}

	protected static final String PROP_NAME = TaintPieceHandler.NAME;
	public static final String COL_NAME = "Taint";

	@Override
	public DynamicTableColumn<RegisterRow, ?, ?> create() {
		return new TaintDebuggerRegisterColumn();
	}
}
