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
package ghidra.app.plugin.core.debug.gui.memview;

import java.awt.BorderLayout;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.*;

import javax.swing.*;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;

import docking.widgets.filter.FilterListener;
import ghidra.app.services.DebuggerListingService;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRangeImpl;
import ghidra.program.model.listing.Program;
import ghidra.util.table.GhidraTable;
import ghidra.util.table.GhidraTableFilterPanel;
import ghidra.util.task.SwingUpdateManager;
import resources.ResourceManager;

public class MemviewTable {

	public static final ImageIcon ICON_TABLE = ResourceManager.loadImage("images/table.png");

	private MemviewMapModel model;
	private GhidraTable table;
	private GhidraTableFilterPanel<?> filterPanel;
	private FilterListener filterListener;
	private SwingUpdateManager applyFilterManager = new SwingUpdateManager(this::applyFilter);
	private JPanel component;

	private MemviewProvider provider;
	private Program program;
	private DebuggerListingService listingService;

	public MemviewTable(MemviewProvider provider) {
		this.provider = provider;
		this.model = new MemviewMapModel(provider);
		this.table = new GhidraTable(model);
		table.setHTMLRenderingEnabled(true);
		this.component = new JPanel(new BorderLayout());
		JScrollPane scrollPane = new JScrollPane(table);
		filterPanel = new GhidraTableFilterPanel<>(table, model);
		component.add(scrollPane, BorderLayout.CENTER);
		component.add(filterPanel, BorderLayout.SOUTH);
		table.setAutoscrolls(true);

		table.getSelectionModel().addListSelectionListener(new ListSelectionListener() {
			@Override
			public void valueChanged(ListSelectionEvent e) {
				if (e.getValueIsAdjusting()) {
					return;
				}
				int modelRow = filterPanel.getModelRow(table.getSelectedRow());
				MemoryBox box = model.getBoxAt(modelRow);
				if (box != null) {
					Set<MemoryBox> boxes = new HashSet<MemoryBox>();
					boxes.add(box);
					provider.selectPanelPosition(boxes);
				}
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

		filterListener = new FilterActionFilterListener();
		filterPanel.addFilterChagnedListener(filterListener);
	}

	public JComponent getComponent() {
		return component;
	}

	public JComponent getPrincipalComponent() {
		return table;
	}

	public void setProgram(Program program) {
		this.program = program;
	}

	public void setListingService(DebuggerListingService listingService) {
		this.listingService = listingService;
	}

	public void setBoxes(Collection<MemoryBox> blist) {
		model.setBoxes(blist);
	}

	public void addBoxes(Collection<MemoryBox> blist) {
		model.addBoxes(blist);
	}

	public void reset() {
		model.reset();
	}

	public List<MemoryBox> getBoxes() {
		return model.getBoxes();
	}

	public void setSelection(Set<MemoryBox> set) {
		table.clearSelection();
		for (MemoryBox box : set) {
			int index = model.getIndexForBox(box);
			int viewRow = filterPanel.getViewRow(index);
			if (viewRow >= 0) {
				table.addRowSelectionInterval(viewRow, viewRow);
				table.scrollToSelectedRow();
			}
		}
	}

	protected void navigateToSelectedObject() {
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
			if (program != null) {
				addr = program.getAddressFactory().getAddressSpace("ram").getAddress(lval);
			}
		}
		if (listingService != null) {
			listingService.goTo(addr, true);
		}
	}

	public void applyFilter() {
		List<MemoryBox> blist = new ArrayList<>();
		for (int i = 0; i < filterPanel.getRowCount(); i++) {
			int row = filterPanel.getModelRow(i);
			if (row >= 0) {
				blist.add(model.getBoxAt(row));
			}
		}
		provider.setBoxesInPanel(blist);
	}

	private class FilterActionFilterListener implements FilterListener {
		@Override
		public void filterChanged(String text) {
			if (provider.isApplyFilter()) {
				applyFilterManager.updateLater();
			}
		}
	}

	/*
	private List<MemviewRow> generateRows(Collection<MemoryBox> changed) {
		List<MemviewRow> list = new ArrayList<>();
		for (MemoryBox box : changed) {
			list.add(new MemviewRow(box));
		}
		if (model instanceof EnumeratedColumnTableModel) {
			@SuppressWarnings("unchecked")
			EnumeratedColumnTableModel<MemviewRow> m =
				(EnumeratedColumnTableModel<MemviewRow>) model;
			m.clear();
			m.addAll(list);
		}
		setColumns();
		model.fireTableStructureChanged();
		return list;
	}
	*/

	/*
	private MemviewRow findMatch(MemoryBox changed) {
		MemviewRow match = null;
		for (int i = 0; i < model.getRowCount(); i++) {
			MemviewRow row = model.getRowObject(i);
			if (row.getBox().equals(changed)) {
				row.setAttributes(changed.getAttributeMap());
				match = row;
				break;
			}
		}
		return match;
	}
	*/

	/*
	private List<MemviewRow> updateMatch(MemviewRow match) {
		MemviewEnumeratedColumnTableModel m = (MemviewEnumeratedColumnTableModel) model;
		m.updateColumns(match);
		m.fireTableDataChanged();
		List<MemviewRow> list = new ArrayList<>();
		if (match != null) {
			list.add(match);
			model.setLastSelectedObjects(list);
			model.fireTableStructureChanged();
		}
		return list;
	}
	*/

	/*
	public void setColumns() {
		MemviewEnumeratedColumnTableModel m = (MemviewEnumeratedColumnTableModel) model;
		for (int i = 0; i < model.getRowCount(); i++) {
			MemviewRow r = model.getRowObject(i);
			m.updateColumns(r);
		}
		m.fireTableStructureChanged();
	}
	*/

	/*
	public TargetObject getSelectedObject() {
		int selectedColumn = table.getSelectedColumn();
		R r = model.getRowObject(table.getSelectedRow());
		if (r instanceof ObjectAttributeRow) {
			ObjectAttributeRow row = (ObjectAttributeRow) r;
			return row.getTargetObject();
		}
		if (r instanceof MemviewRow) {
			MemviewRow row = (MemviewRow) r;
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
	*/

	/*
	public void setSelectedObject(MemoryBox selection) {
		for (int i = 0; i < model.getRowCount(); i++) {
			MemviewRow row = model.getRowObject(i);
			if (row.getBox().equals(selection)) {
				table.selectRow(i);
				break;
			}
		}
	}
	*/

	/*
	public void setFocus(MemoryBox focused) {
		Swing.runIfSwingOrRunLater(() -> {
			setSelectedObject(focused);
		});
	}
	*/

}
