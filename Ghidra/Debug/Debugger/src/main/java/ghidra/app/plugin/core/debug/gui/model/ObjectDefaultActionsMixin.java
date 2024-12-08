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
package ghidra.app.plugin.core.debug.gui.model;

import java.util.*;

import javax.swing.JTable;

import ghidra.app.plugin.core.debug.gui.control.TargetActionTask;
import ghidra.app.plugin.core.debug.gui.model.ObjectTableModel.ValueProperty;
import ghidra.app.plugin.core.debug.gui.model.ObjectTableModel.ValueRow;
import ghidra.app.plugin.core.debug.gui.model.PathTableModel.PathRow;
import ghidra.app.services.DebuggerListingService;
import ghidra.dbg.target.*;
import ghidra.debug.api.model.DebuggerSingleObjectPathActionContext;
import ghidra.debug.api.target.ActionName;
import ghidra.debug.api.target.Target;
import ghidra.debug.api.target.Target.ActionEntry;
import ghidra.debug.api.tracemgr.DebuggerCoordinates;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.trace.model.target.*;
import ghidra.util.Msg;

public interface ObjectDefaultActionsMixin {

	PluginTool getTool();

	DebuggerCoordinates getCurrent();

	void activatePath(TraceObjectKeyPath path);

	default void toggleObject(TraceObject object) {
		if (!getCurrent().isAliveAndPresent()) {
			return;
		}
		Target target = getCurrent().getTarget();
		Map<String, ActionEntry> actions = target.collectActions(ActionName.TOGGLE,
			new DebuggerSingleObjectPathActionContext(object.getCanonicalPath()));
		ActionEntry action = actions.values()
				.stream()
				.filter(e -> !e.requiresPrompt())
				.sorted(Comparator.comparing(e -> -e.specificity()))
				.findFirst()
				.orElse(null);
		if (action == null) {
			Msg.error(this, "No suitable toggle action for " + object);
			return;
		}
		TargetActionTask.runAction(getTool(), "Toggle", action);
	}

	default void goToAddress(DebuggerListingService listingService, Address address) {
		ProgramLocation loc = new ProgramLocation(getCurrent().getView(), address);
		listingService.goTo(loc, true);
	}

	default void goToAddress(Address address) {
		DebuggerListingService listingService = getTool().getService(DebuggerListingService.class);
		if (listingService == null) {
			return;
		}
		goToAddress(listingService, address);
	}

	default void goToRange(AddressRange range) {
		DebuggerListingService listingService = getTool().getService(DebuggerListingService.class);
		if (listingService == null) {
			return;
		}
		listingService.setCurrentSelection(
			new ProgramSelection(range.getMinAddress(), range.getMaxAddress()));
		goToAddress(listingService, range.getMinAddress());
	}

	default boolean performElementCellDefaultAction(JTable table) {
		int row = table.getSelectedRow();
		int col = table.getSelectedColumn();
		Object cellValue = table.getValueAt(row, col);
		if (cellValue instanceof ValueProperty<?> property) {
			Object propValue = property.getValue();
			if (performDefaultAction(propValue)) {
				return true;
			}
		}
		return false;
	}

	default boolean performValueRowDefaultAction(ValueRow row) {
		if (row == null) {
			return false;
		}
		return performDefaultAction(row.getValue());
	}

	default boolean performPathRowDefaultAction(PathRow row) {
		if (row == null) {
			return false;
		}
		return performDefaultAction(row.getValue());
	}

	default boolean performDefaultAction(TraceObjectValue value) {
		if (value == null) {
			return false;
		}
		return performDefaultAction(value.getValue());
	}

	default boolean performDefaultAction(TraceObject object) {
		Set<Class<? extends TargetObject>> interfaces = object.getTargetSchema().getInterfaces();
		if (interfaces.contains(TargetActivatable.class)) {
			activatePath(object.getCanonicalPath());
			return true;
		}
		/**
		 * Should I check aliveAndPresent() here? If I do, behavior changes when target is dead,
		 * which might be unexpected.
		 */
		if (interfaces.contains(TargetTogglable.class)) {
			toggleObject(object);
			return true;
		}
		long snap = getCurrent().getSnap();
		TraceObjectValue valAddress = object.getAttribute(snap, "_address");
		if (valAddress != null && valAddress.getValue() instanceof Address address) {
			goToAddress(address);
			return true;
		}
		TraceObjectValue valRange = object.getAttribute(snap, "_range");
		if (valRange != null && valRange.getValue() instanceof AddressRange range) {
			goToRange(range);
			return true;
		}
		return false;
	}

	default boolean performDefaultAction(Object value) {
		if (value instanceof Address address) {
			goToAddress(address);
			return true;
		}
		if (value instanceof AddressRange range) {
			goToRange(range);
			return true;
		}
		if (value instanceof TraceObject object) {
			return performDefaultAction(object);
		}
		return false;
	}

}
