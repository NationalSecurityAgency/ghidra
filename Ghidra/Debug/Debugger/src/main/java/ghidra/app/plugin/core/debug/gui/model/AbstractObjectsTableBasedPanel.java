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
import ghidra.app.plugin.core.debug.DebuggerCoordinates;
import ghidra.app.plugin.core.debug.gui.model.AbstractQueryTablePanel.CellActivationListener;
import ghidra.app.plugin.core.debug.gui.model.ObjectTableModel.ValueProperty;
import ghidra.app.plugin.core.debug.gui.model.ObjectTableModel.ValueRow;
import ghidra.app.services.DebuggerListingService;
import ghidra.framework.plugintool.AutoService;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.annotation.AutoServiceConsumed;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.util.ProgramSelection;
import ghidra.trace.model.target.TraceObject;
import ghidra.trace.model.target.TraceObjectInterface;

public abstract class AbstractObjectsTableBasedPanel<U extends TraceObjectInterface>
		extends ObjectsTablePanel implements ListSelectionListener, CellActivationListener {

	public static boolean isContextNonEmpty(DebuggerObjectActionContext ctx) {
		return ctx != null && !ctx.getObjectValues().isEmpty();
	}

	public static <T extends TraceObjectInterface> Stream<T> getSelected(
			DebuggerObjectActionContext ctx, Class<T> iface) {
		return ctx == null ? null
				: ctx.getObjectValues()
						.stream()
						.filter(v -> v.isObject())
						.map(v -> v.getChild().queryInterface(iface))
						.filter(r -> r != null);
	}

	private final ComponentProvider provider;
	private final Class<U> objType;

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

	public DebuggerObjectActionContext getActionContext() {
		return myActionContext;
	}

	protected abstract ModelQuery computeQuery(TraceObject object);

	public void coordinatesActivated(DebuggerCoordinates coordinates) {
		TraceObject object = coordinates.getObject();
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
				sel.stream().map(r -> r.getValue()).collect(Collectors.toList()), provider, this);
		}
	}

	@Override
	public void cellActivated(JTable table) {
		if (listingService == null) {
			return;
		}
		int row = table.getSelectedRow();
		int col = table.getSelectedColumn();
		Object value = table.getValueAt(row, col);
		if (!(value instanceof ValueProperty<?> property)) {
			return;
		}
		Object propVal = property.getValue();
		if (propVal instanceof Address address) {
			listingService.goTo(address, true);
		}
		else if (propVal instanceof AddressRange range) {
			listingService.setCurrentSelection(
				new ProgramSelection(range.getMinAddress(), range.getMaxAddress()));
			listingService.goTo(range.getMinAddress(), true);
		}
	}
}
