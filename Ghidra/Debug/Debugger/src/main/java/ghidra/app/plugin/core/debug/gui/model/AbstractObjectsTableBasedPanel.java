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

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.swing.JTable;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;

import docking.ComponentProvider;
import ghidra.app.plugin.core.debug.gui.model.AbstractQueryTablePanel.CellActivationListener;
import ghidra.app.plugin.core.debug.gui.model.ObjectTableModel.ValueRow;
import ghidra.app.services.DebuggerListingService;
import ghidra.app.services.DebuggerTraceManagerService;
import ghidra.debug.api.model.DebuggerObjectActionContext;
import ghidra.debug.api.tracemgr.DebuggerCoordinates;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.annotation.AutoServiceConsumed;
import ghidra.trace.model.Trace;
import ghidra.trace.model.target.*;

public abstract class AbstractObjectsTableBasedPanel<U extends TraceObjectInterface>
		extends ObjectsTablePanel
		implements ListSelectionListener, CellActivationListener, ObjectDefaultActionsMixin {

	private final ComponentProvider provider;
	private final Class<U> objType;

	@AutoServiceConsumed
	protected DebuggerTraceManagerService traceManager;
	@AutoServiceConsumed
	protected DebuggerListingService listingService;
	@SuppressWarnings("unused")
	private final AutoService.Wiring autoServiceWiring;

	protected DebuggerObjectActionContext myActionContext;

	public AbstractObjectsTableBasedPanel(Plugin plugin, ComponentProvider provider,
			Class<U> objType) {
		super(plugin);
		this.provider = provider;
		this.objType = objType;

		this.autoServiceWiring = AutoService.wireServicesConsumed(plugin, this);

		setLimitToSnap(true);
		setShowHidden(false);

		addSelectionListener(this);
		addCellActivationListener(this);
	}

	public boolean isContextNonEmpty(DebuggerObjectActionContext ctx) {
		return getSelected(ctx).findAny().isPresent();
	}

	public Stream<U> getSelected(DebuggerObjectActionContext ctx) {
		return ctx == null ? null
				: ctx.getObjectValues()
						.stream()
						.filter(v -> v.isObject())
						.map(v -> v.getChild().queryInterface(objType))
						.filter(r -> r != null);
	}

	public DebuggerObjectActionContext getActionContext() {
		return myActionContext;
	}

	protected abstract ModelQuery computeQuery(TraceObject object);

	public void coordinatesActivated(DebuggerCoordinates coordinates) {
		TraceObject object = coordinates.getObject();
		if (object == null) {
			Trace trace = coordinates.getTrace();
			if (trace != null) {
				object = trace.getObjectManager().getRootObject();
			}
		}
		setQuery(object == null ? ModelQuery.EMPTY : computeQuery(object));
		goToCoordinates(coordinates);
	}

	protected void setSelected(Set<?> sel) {
		trySelect(sel.stream()
				.filter(s -> objType.isInstance(s))
				.map(s -> objType.cast(s).getObject())
				.collect(Collectors.toSet()));
	}

	@Override
	public void valueChanged(ListSelectionEvent e) {
		if (e.getValueIsAdjusting()) {
			return;
		}
		List<ValueRow> sel = getSelectedItems();
		if (!sel.isEmpty()) {
			myActionContext = new DebuggerObjectActionContext(
				sel.stream().map(r -> r.getValue()).collect(Collectors.toList()), provider, table);
		}
	}

	@Override
	public void cellActivated(JTable table) {
		if (performElementCellDefaultAction(table)) {
			return;
		}
		performValueRowDefaultAction(getSelectedItem());
	}

	@Override
	public DebuggerCoordinates getCurrent() {
		return current;
	}

	@Override
	public PluginTool getTool() {
		return plugin.getTool();
	}

	@Override
	public void activatePath(TraceObjectKeyPath path) {
		if (current.getTrace() == null) {
			return;
		}
		try {
			traceManager.activate(current.pathNonCanonical(path));
		}
		catch (IllegalArgumentException e) {
			plugin.getTool().setStatusInfo(e.getMessage(), true);
		}
	}
}
