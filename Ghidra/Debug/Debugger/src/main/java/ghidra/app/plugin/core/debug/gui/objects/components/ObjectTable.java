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
package ghidra.app.plugin.core.debug.gui.objects.components;

import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.*;

import javax.swing.*;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;

import docking.widgets.table.AbstractSortedTableModel;
import docking.widgets.table.EnumeratedColumnTableModel;
import ghidra.app.plugin.core.debug.gui.objects.DebuggerObjectsProvider;
import ghidra.app.plugin.core.debug.gui.objects.ObjectContainer;
import ghidra.app.plugin.core.debug.mapping.DebuggerMemoryMapper;
import ghidra.app.services.*;
import ghidra.dbg.target.TargetObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRangeImpl;
import ghidra.util.Swing;
import ghidra.util.table.GhidraTable;
import resources.ResourceManager;

public class ObjectTable<R> implements ObjectPane {

	public static final ImageIcon ICON_TABLE = ResourceManager.loadImage("images/table.png");

	private ObjectContainer container;
	private Class<R> clazz;
	private AbstractSortedTableModel<R> model;
	private GhidraTable table;
	private JScrollPane component;
	private DebuggerListingService listingService;
	private DebuggerModelService modelService;

	public ObjectTable(ObjectContainer container, Class<R> clazz,
			AbstractSortedTableModel<R> model) {
		this.table = new GhidraTable(model);
		this.component = new JScrollPane(table);
		this.container = container;
		this.clazz = clazz;
		this.model = model;
		this.listingService = container.getProvider().getListingService();
		this.modelService = container.getProvider().getModelService();

		table.getSelectionModel().addListSelectionListener(new ListSelectionListener() {
			@Override
			public void valueChanged(ListSelectionEvent e) {
				if (e.getValueIsAdjusting()) {
					return;
				}
				DebuggerObjectsProvider provider = container.getProvider();
				provider.getTool().contextChanged(provider);
			}
		});
		table.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				if (e.getClickCount() == 2) {
					navigateToSelectedObject();
				}
			}
		});
		container.subscribe();
		signalUpdate(container);
	}

	@Override
	public ObjectContainer getContainer() {
		return container;
	}

	@Override
	public TargetObject getTargetObject() {
		return container.getTargetObject();
	}

	@Override
	public JComponent getComponent() {
		return component;
	}

	@Override
	public JComponent getPrincipalComponent() {
		return table;
	}

	@Override
	public String getName() {
		TargetObject targetObject = getTargetObject();
		return targetObject == null ? "Main" : targetObject.getName();
	}

	@Override
	public void signalDataChanged(ObjectContainer oc) {
		Swing.runIfSwingOrRunLater(() -> {
			update(oc);
		});
	}

	@Override
	public void signalContentsChanged(ObjectContainer oc) {
		Swing.runIfSwingOrRunLater(() -> {
			update(oc);
		});
	}

	@Override
	public void signalUpdate(ObjectContainer oc) {
		Swing.runIfSwingOrRunLater(() -> {
			update(oc);
		});
	}

	@Override
	public List<? extends Object> update(ObjectContainer changed) {
		if (changed.equals(container) &&
			((clazz.equals(ObjectElementRow.class) && changed.hasElements()) ||
				(clazz.equals(ObjectAttributeRow.class) && !changed.hasElements()))) {
			return generateRows(changed);
		}
		else if (clazz.equals(ObjectElementRow.class) && !changed.hasElements()) {
			ObjectElementRow match = findMatch(changed);
			if (match != null) {
				return updateMatch(match);
			}
		}
		return new ArrayList<>();
	}

	private List<R> generateRows(ObjectContainer changed) {
		List<R> list = new ArrayList<>();
		for (ObjectContainer child : changed.getCurrentChildren()) {
			if (child.isVisible() || !getContainer().getProvider().isHideIntrinsics()) {
				TargetObject to = child.getTargetObject();
				try {
					R r = clazz
							.getDeclaredConstructor(TargetObject.class,
								DebuggerObjectsProvider.class)
							.newInstance(to, container.getProvider());
					list.add(r);
				}
				catch (Exception e) {
					e.printStackTrace();
				}
			}
		}
		if (model instanceof EnumeratedColumnTableModel) {
			@SuppressWarnings("unchecked")
			EnumeratedColumnTableModel<R> m = (EnumeratedColumnTableModel<R>) model;
			m.clear();
			m.addAll(list);
		}
		for (ObjectContainer child : changed.getCurrentChildren()) {
			if (child.isVisible()) {
				update(child);
			}
		}
		model.fireTableStructureChanged();
		return list;
	}

	private ObjectElementRow findMatch(ObjectContainer changed) {
		TargetObject changedTarget = changed.getTargetObject();
		ObjectElementRow match = null;
		for (int i = 0; i < model.getRowCount(); i++) {
			R r = model.getRowObject(i);
			if (r instanceof ObjectElementRow) {
				ObjectElementRow row = (ObjectElementRow) r;
				if (row.getTargetObject().equals(changedTarget)) {
					row.setAttributes(changed.getAttributeMap());
					match = row;
					break;
				}
			}
		}
		return match;
	}

	private List<R> updateMatch(ObjectElementRow match) {
		@SuppressWarnings("unchecked")
		ObjectEnumeratedColumnTableModel<?, R> m = (ObjectEnumeratedColumnTableModel<?, R>) model;
		m.updateColumns(match);
		m.fireTableDataChanged();
		List<R> list = new ArrayList<>();
		if (match != null) {
			list.add((R) match);
			model.setLastSelectedObjects(list);
			model.fireTableStructureChanged();
		}
		return list;
	}

	public void setColumns() {
		@SuppressWarnings("unchecked")
		ObjectEnumeratedColumnTableModel<?, R> m = (ObjectEnumeratedColumnTableModel<?, R>) model;
		for (int i = 0; i < model.getRowCount(); i++) {
			R r = model.getRowObject(i);
			if (r instanceof ObjectElementRow) {
				m.updateColumns((ObjectElementRow) r);
				break;
			}
		}
		m.fireTableStructureChanged();
	}

	@Override
	public TargetObject getSelectedObject() {
		int selectedColumn = table.getSelectedColumn();
		R r = model.getRowObject(table.getSelectedRow());
		if (r instanceof ObjectAttributeRow) {
			ObjectAttributeRow row = (ObjectAttributeRow) r;
			return row.getTargetObject();
		}
		if (r instanceof ObjectElementRow) {
			ObjectElementRow row = (ObjectElementRow) r;
			TargetObject targetObject = row.getTargetObject();
			if (selectedColumn > 0) {
				List<String> keys = row.getKeys();
				if (selectedColumn >= keys.size()) {
					selectedColumn = 0;
				}
				String key = keys.get(selectedColumn);
				Map<String, ?> attributes = targetObject.getCachedAttributes();
				Object object = attributes.get(key);
				if (object instanceof TargetObject) {
					return (TargetObject) object;
				}
			}
			return targetObject;
		}
		return null;
	}

	public void setSelectedObject(TargetObject selection) {
		for (int i = 0; i < model.getRowCount(); i++) {
			R r = model.getRowObject(i);
			if (r instanceof ObjectAttributeRow) {
				ObjectAttributeRow row = (ObjectAttributeRow) r;
				if (row.getTargetObject().equals(selection)) {
					table.selectRow(i);
					break;
				}
			}
			if (r instanceof ObjectElementRow) {
				ObjectElementRow row = (ObjectElementRow) r;
				if (row.getTargetObject().equals(selection)) {
					table.selectRow(i);
					break;
				}
			}
		}
	}

	@Override
	public void setFocus(TargetObject object, TargetObject focused) {
		Swing.runIfSwingOrRunLater(() -> {
			setSelectedObject(focused);
		});
	}

	@Override
	public void setRoot(ObjectContainer container, TargetObject targetObject) {
		container.setTargetObject(targetObject);
	}

	protected void navigateToSelectedObject() {
		if (listingService != null) {
			int selectedRow = table.getSelectedRow();
			int selectedColumn = table.getSelectedColumn();
			Object value = table.getValueAt(selectedRow, selectedColumn);
			Address addr = null;
			if (value instanceof Address) {
				addr = (Address) value;
			}
			if (value instanceof AddressRangeImpl) {
				AddressRangeImpl range = (AddressRangeImpl) value;
				addr = range.getMinAddress();
			}
			if (value instanceof Long) {
				Long lval = (Long) value;
				addr = container.getTargetObject().getModel().getAddress("ram", lval);
			}
			if (modelService != null) {
				TraceRecorder recorder =
					modelService.getRecorderForSuccessor(container.getTargetObject());
				DebuggerMemoryMapper memoryMapper = recorder.getMemoryMapper();
				Address traceAddr = memoryMapper.targetToTrace(addr);
				listingService.goTo(traceAddr, true);
			}
		}
	}

}
