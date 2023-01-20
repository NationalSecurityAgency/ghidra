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

import java.awt.event.*;
import java.util.*;

import javax.swing.*;

import docking.widgets.table.AbstractSortedTableModel;
import docking.widgets.table.EnumeratedColumnTableModel;
import generic.theme.GIcon;
import ghidra.app.plugin.core.debug.gui.objects.DebuggerObjectsProvider;
import ghidra.app.plugin.core.debug.gui.objects.ObjectContainer;
import ghidra.dbg.DebugModelConventions;
import ghidra.dbg.target.TargetObject;
import ghidra.util.Msg;
import ghidra.util.Swing;
import ghidra.util.table.GhidraTable;

public class ObjectTable<R> implements ObjectPane {

	public static final Icon ICON_TABLE = new GIcon("icon.debugger.table.object");

	private final ObjectContainer container;
	private final Class<R> clazz;
	private final AbstractSortedTableModel<R> model;
	private final GhidraTable table;
	private final JScrollPane component;

	public ObjectTable(ObjectContainer container, Class<R> clazz,
			AbstractSortedTableModel<R> model) {
		this.table = new GhidraTable(model);
		this.component = new JScrollPane(table);
		this.container = container;
		this.clazz = clazz;
		this.model = model;

		table.getSelectionModel().addListSelectionListener(e -> {
			if (e.getValueIsAdjusting()) {
				return;
			}
			DebuggerObjectsProvider provider = container.getProvider();
			provider.getTool().contextChanged(provider);
		});
		table.setDefaultRenderer(String.class,
			new ObjectTableCellRenderer(container.getProvider()));
		table.setDefaultRenderer(Object.class,
			new ObjectTableCellRenderer(container.getProvider()));
		table.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				if (e.getClickCount() == 2 && e.getButton() == MouseEvent.BUTTON1) {
					activateOrNavigateSelectedObject();
				}
			}
		});
		table.addKeyListener(new KeyAdapter() {
			@Override
			public void keyPressed(KeyEvent e) {
				if (e.getKeyCode() == KeyEvent.VK_ENTER) {
					activateOrNavigateSelectedObject();
					e.consume(); // lest it select the next row down
				}
			}
		});
		container.subscribe();
		signalUpdate(container);
	}

	private void activateOrNavigateSelectedObject() {
		int selectedRow = table.getSelectedRow();
		int selectedColumn = table.getSelectedColumn();
		Object value = table.getValueAt(selectedRow, selectedColumn);
		if (container.getProvider()
				.navigateToSelectedObject(container.getTargetObject(), value) != null) {
			return;
		}
		R row = model.getModelData().get(selectedRow); // No filter?
		TargetObject object;
		if (row instanceof ObjectElementRow eRow) {
			object = eRow.getTargetObject();
		}
		else if (row instanceof ObjectAttributeRow aRow) {
			object = aRow.getTargetObject();
		}
		else {
			return;
		}
		if (object instanceof DummyTargetObject) {
			return;
		}
		DebugModelConventions.requestActivation(object).exceptionally(ex -> {
			Msg.error(this, "Could not activate " + object, ex);
			return null;
		});
		/*DebugModelConventions.requestFocus(object).exceptionally(ex -> {
			Msg.error(this, "Could not focus " + object, ex);
			return null;
		});*/
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
			if (r instanceof ObjectElementRow row) {
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
		ObjectEnumeratedColumnTableModel<?, R> m = (ObjectEnumeratedColumnTableModel<?, R>) model;
		for (int i = 0; i < model.getRowCount(); i++) {
			R r = model.getRowObject(i);
			if (r instanceof ObjectElementRow row) {
				m.updateColumns(row);
				break;
			}
		}
		m.fireTableStructureChanged();
	}

	@Override
	public TargetObject getSelectedObject() {
		int selectedColumn = table.getSelectedColumn();
		R r = model.getRowObject(table.getSelectedRow());
		if (r instanceof ObjectAttributeRow row) {
			return row.getTargetObject();
		}
		if (r instanceof ObjectElementRow row) {
			TargetObject targetObject = row.getTargetObject();
			if (selectedColumn > 0) {
				List<String> keys = row.getKeys();
				if (selectedColumn >= keys.size()) {
					selectedColumn = 0;
				}
				String key = keys.get(selectedColumn);
				Map<String, ?> attributes = targetObject.getCachedAttributes();
				Object object = attributes.get(key);
				if (object instanceof TargetObject to) {
					return to;
				}
			}
			return targetObject;
		}
		return null;
	}

	@Override
	public void setSelectedObject(TargetObject selection) {
		for (int i = 0; i < model.getRowCount(); i++) {
			R r = model.getRowObject(i);
			if (r instanceof ObjectAttributeRow row) {
				if (row.getTargetObject().equals(selection)) {
					table.selectRow(i);
					break;
				}
			}
			if (r instanceof ObjectElementRow row) {
				if (row.getTargetObject().equals(selection)) {
					table.selectRow(i);
					break;
				}
			}
		}
	}

	@Override
	public void setFocus(TargetObject object, TargetObject focused) {
		// Should this setSelectedObject, too?
		Swing.runIfSwingOrRunLater(() -> {
			table.repaint();
		});
	}

	@Override
	public void setRoot(ObjectContainer container, TargetObject targetObject) {
		container.setTargetObject(targetObject);
	}

}
