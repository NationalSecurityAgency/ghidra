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
package ghidra.app.plugin.core.bento;

import java.awt.*;
import java.awt.event.*;
import java.util.*;
import java.util.List;

import javax.swing.*;
import javax.swing.event.*;

import generic.theme.GIcon;
import ghidra.app.services.CodeViewerService;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.table.GhidraTable;
import ghidra.util.table.GhidraTableFilterPanel;
import ghidra.util.task.SwingUpdateManager;

public class BentoTable {

	public static final Icon ICON_TABLE = new GIcon("icon.table");

	private BentoMapModel model;
	private GhidraTable table;
	private GhidraTableFilterPanel<?> filterPanel;
	private FilterActionFilterListener filterListener;
	private SwingUpdateManager applyFilterManager =
		new SwingUpdateManager(this::applyFilter);
	private JPanel component;
	private static int clickedColumnIndex = -1;

	private BentoProvider provider;
	private Program program;
	private CodeViewerService codeViewerService;

	public BentoTable(BentoProvider provider) {
		this.provider = provider;
		this.model = new BentoMapModel(provider);
		this.table = new GhidraTable(model);
		table.setHTMLRenderingEnabled(true);
		this.component = new JPanel(new BorderLayout());
		JScrollPane scrollPane = new JScrollPane(table);
		filterPanel = new GhidraTableFilterPanel<>(table, model);
		component.add(scrollPane, BorderLayout.CENTER);
		component.add(filterPanel, BorderLayout.SOUTH);
		table.setAutoscrolls(true);

		String namePrefix = "Memory View";
		table.setAccessibleNamePrefix(namePrefix);
		filterPanel.setAccessibleNamePrefix(namePrefix);

		table.getSelectionModel().addListSelectionListener(e -> {
			if (e.getValueIsAdjusting()) {
				return;
			}
			int modelRow = filterPanel.getModelRow(table.getSelectedRow());
			if (modelRow >= 0) {
				BentoBox box = model.getBoxAt(modelRow);
				if (box != null) {
					Set<BentoBox> boxes = new HashSet<>();
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
		filterPanel.getTableFilterModel().addTableModelListener(filterListener);

		JPopupMenu popupMenu = table.getTableColumnPopupMenu(0);
		JMenuItem menuItemX = new JMenuItem("Set x-axis");
		popupMenu.add(menuItemX);

		menuItemX.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				if (clickedColumnIndex > 0) {
					int xIndex = (clickedColumnIndex - 1) / 2;
					provider.setIndex(true, xIndex);
				}
			}
		});

		JMenuItem menuItemY = new JMenuItem("Set y-axis");
		popupMenu.add(menuItemY);

		menuItemY.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				if (clickedColumnIndex > 0) {
					int yIndex = (clickedColumnIndex - 1) / 2;
					provider.setIndex(false, yIndex);
				}
			}
		});

		popupMenu.addPopupMenuListener(new PopupMenuListener() {
			@Override
			public void popupMenuWillBecomeVisible(PopupMenuEvent e) {
				Component invoker = popupMenu.getInvoker();
				Point mousePos = invoker.getMousePosition();

				if (mousePos != null) {
					if (invoker instanceof JTable) {
						clickedColumnIndex = table.columnAtPoint(mousePos);
					}
					else if (invoker instanceof javax.swing.table.JTableHeader) {
						clickedColumnIndex = table.getTableHeader().columnAtPoint(mousePos);
					}
				}
			}

			@Override
			public void popupMenuWillBecomeInvisible(PopupMenuEvent e) {
				// IGNORE
			}

			@Override
			public void popupMenuCanceled(PopupMenuEvent e) {
				// IGNORE
			}
		});
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

	public void setCodeViewerService(CodeViewerService codeViewerService) {
		this.codeViewerService = codeViewerService;
	}

	public void setBoxes(Collection<BentoBox> blist) {
		model.setBoxes(blist);
	}

	public void addBoxes(Collection<BentoBox> blist) {
		model.addBoxes(blist);
	}

	public void reset() {
		model.reset();
	}

	public List<BentoBox> getBoxes() {
		return model.getBoxes();
	}

	public void setSelection(Set<BentoBox> set) {
		table.clearSelection();
		for (BentoBox box : set) {
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
		if (selectedRow < 0 || selectedColumn < 0) {
			return;
		}

		Object value = table.getValueAt(selectedRow, selectedColumn);
		Address addr = null;
		if (selectedColumn < 0) {
			for (int i = 0; i < table.getColumnCount(); i++) {
				value = table.getValueAt(selectedRow, i);
				if (value instanceof Address) {
					addr = (Address) value;
					break;
				}
			}
		}
		if (value instanceof Address a) {
			addr = a;
		}
		if (value instanceof AddressRange range) {
			addr = range.getMinAddress();
		}
		if (value instanceof Long lval && program != null) {
			addr = program.getAddressFactory().getAddressSpace("ram").getAddress(lval);
		}
		if (codeViewerService != null && program != null && addr != null) {
			ProgramLocation loc = new ProgramLocation(program, addr);
			codeViewerService.goTo(loc, true);
		}
	}

	public void applyFilter() {
		List<BentoBox> blist = new ArrayList<>();
		for (int i = 0; i < filterPanel.getRowCount(); i++) {
			int row = filterPanel.getModelRow(i);
			if (row >= 0) {
				blist.add(model.getBoxAt(row));
			}
		}
		provider.setBoxesInPanel(blist);
	}

	private class FilterActionFilterListener implements TableModelListener {

		@Override
		public void tableChanged(TableModelEvent e) {
			if (provider.isApplyFilter()) {
				applyFilterManager.updateLater();
			}
		}
	}

	void fireTableDataChanged() {
		model.fireTableDataChanged();
	}

	public void setColumns(List<String> cols, BentoPanel panel) {
		model.setColumnNames(cols);
	}

	public String getTitle() {
		return model.getTitle();
	}

	public BentoMapModel getModel() {
		return model;
	}

}
