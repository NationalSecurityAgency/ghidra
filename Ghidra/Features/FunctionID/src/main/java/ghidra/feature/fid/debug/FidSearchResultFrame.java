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
package ghidra.feature.fid.debug;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.event.*;
import java.io.IOException;
import java.util.*;

import javax.swing.*;
import javax.swing.table.TableColumn;
import javax.swing.table.TableColumnModel;

import docking.widgets.table.*;
import ghidra.feature.fid.db.*;
import ghidra.feature.fid.service.FidService;
import ghidra.util.Msg;
import ghidra.util.ReadOnlyException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class FidSearchResultFrame extends JFrame implements FidQueryCloseListener {
	static final int NAME_WIDTH = 480;
	static final int HASH_WIDTH = 160;
	static final int SIZE_WIDTH = 50;
	static final int MINI_WIDTH = 50;
	static final int SMALLER_WIDTH = 240;

	static int[] PREFERRED_WIDTHS =
		new int[] { NAME_WIDTH, HASH_WIDTH, SMALLER_WIDTH, SMALLER_WIDTH, HASH_WIDTH, HASH_WIDTH,
			SIZE_WIDTH, HASH_WIDTH, SIZE_WIDTH, HASH_WIDTH, SIZE_WIDTH, HASH_WIDTH, MINI_WIDTH };

	private FidService service;
	private FidQueryService dbService;
	private List<FunctionRecord> funcList;
	private FidFunctionRecordTableModel model;
	private GTable table;

	public FidSearchResultFrame(String title, List<FunctionRecord> funcList, FidService service,
			FidQueryService dbService) {
		super(title);
		this.service = service;
		this.dbService = dbService;
		this.funcList = funcList;
		model = new FidFunctionRecordTableModel(dbService, funcList);
		table = new GTable(model);
		buildFrame();
		dbService.addCloseListener(this);
	}

	private void buildFrame() {
		GTableCellRenderer renderer = new GTableCellRenderer();
		renderer.setFont(FidDebugUtils.MONOSPACED_FONT);
		int columnCount = table.getColumnCount();
		for (int ii = 0; ii < columnCount; ++ii) {
			Class<?> columnClass = table.getColumnClass(ii);
			table.setDefaultRenderer(columnClass, renderer);
		}

		JScrollPane scrollPane = new JScrollPane(table);
		table.setPreferredScrollableViewportSize(new Dimension(400, 100));
		table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

		GTableFilterPanel<FunctionRecord> filterPanel = new GTableFilterPanel<>(table, model);

		table.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				if (e.getClickCount() == 2) {
					if (table.getSelectedRowCount() == 1) {
						int selectedRow = table.getSelectedRow();
						int modelRow = filterPanel.getModelRow(selectedRow);
						FunctionRecord functionRecord = funcList.get(modelRow);
						FidDebugUtils.openFunctionWindow(functionRecord, service, dbService);
					}
				}
			}
		});

		JMenuBar menuBar = buildMenuActions();

		JPanel mainPanel = new JPanel(new BorderLayout());
		mainPanel.add(scrollPane, BorderLayout.CENTER);
		mainPanel.add(filterPanel, BorderLayout.SOUTH);

		setJMenuBar(menuBar);
		setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE);
		setContentPane(mainPanel);
		setSize(2500, Math.min(600, 150 + 20 * funcList.size()));
		setVisible(true);

		TableColumnModel columnModel = table.getColumnModel();
		Enumeration<TableColumn> columns = columnModel.getColumns();
		int ii = 0;
		while (columns.hasMoreElements()) {
			TableColumn column = columns.nextElement();
			column.setMinWidth(PREFERRED_WIDTHS[ii]);
			++ii;
		}

	}

	private JMenuBar buildMenuActions() {
		JMenuBar menuBar = new JMenuBar();
		JMenu menu = new JMenu("Edit");
		menuBar.add(menu);
		JMenuItem item1 = new JMenuItem("Set auto-fail");
		item1.addActionListener(new ActionListener() {

			@Override
			public void actionPerformed(ActionEvent event) {
				if (funcList.isEmpty()) {
					return;
				}
				try {
					funcList = service.markRecordsAutoFail(funcList, true);
					model.resetWholeTable(funcList);
				}
				catch (ReadOnlyException e) {
					Msg.info(this, e.getMessage());
				}
				catch (IOException e) {
					Msg.error(this, "Error performing 'Set auto-fail'", e);
				}
			}
		});
		menu.add(item1);

		JMenuItem item2 = new JMenuItem("Set auto-pass");
		item2.addActionListener(new ActionListener() {

			@Override
			public void actionPerformed(ActionEvent e) {
				if (funcList.isEmpty()) {
					return;
				}
				try {
					funcList = service.markRecordsAutoPass(funcList, true);
					model.resetWholeTable(funcList);
				}
				catch (IOException e1) {
					Msg.error(this, "Error performing 'Set auto-pass'", e1);
				}
			}
		});
		menu.add(item2);

		JMenuItem item3 = new JMenuItem("Set force-specific");
		item3.addActionListener(new ActionListener() {

			@Override
			public void actionPerformed(ActionEvent e) {
				if (funcList.isEmpty()) {
					return;
				}
				try {
					funcList = service.markRecordsForceSpecific(funcList, true);
					model.resetWholeTable(funcList);
				}
				catch (IOException e1) {
					Msg.error(this, "Error performing 'Set force-specific'", e1);
				}
			}
		});
		menu.add(item3);

		JMenuItem item4 = new JMenuItem("Set force-relation");
		item4.addActionListener(new ActionListener() {

			@Override
			public void actionPerformed(ActionEvent e) {
				if (funcList.isEmpty()) {
					return;
				}
				try {
					funcList = service.markRecordsForceRelation(funcList, true);
					model.resetWholeTable(funcList);
				}
				catch (IOException e1) {
					Msg.error(this, "Error performing 'Set force-relation'", e1);
				}
			}

		});
		menu.add(item4);

		JMenuItem item5 = new JMenuItem("Clear auto-fail");
		item5.addActionListener(new ActionListener() {

			@Override
			public void actionPerformed(ActionEvent e) {
				if (funcList.isEmpty()) {
					return;
				}
				try {
					funcList = service.markRecordsAutoFail(funcList, false);
					model.resetWholeTable(funcList);
				}
				catch (IOException e1) {
					Msg.error(this, "Error performing 'Clear auto-fail'", e1);
				}
			}
		});
		menu.add(item5);

		JMenuItem item6 = new JMenuItem("Clear auto-pass");
		item6.addActionListener(new ActionListener() {

			@Override
			public void actionPerformed(ActionEvent e) {
				if (funcList.isEmpty()) {
					return;
				}
				try {
					funcList = service.markRecordsAutoPass(funcList, false);
					model.resetWholeTable(funcList);
				}
				catch (IOException e1) {
					Msg.error(this, "Error performing 'Clear auto-pass'", e1);
				}
			}
		});
		menu.add(item6);

		JMenuItem item7 = new JMenuItem("Clear force-specific");
		item7.addActionListener(new ActionListener() {

			@Override
			public void actionPerformed(ActionEvent e) {
				if (funcList.isEmpty()) {
					return;
				}
				try {
					funcList = service.markRecordsForceSpecific(funcList, false);
					model.resetWholeTable(funcList);
				}
				catch (IOException e1) {
					Msg.error(this, "Error performing 'Clear force-specific'", e1);
				}
			}
		});
		menu.add(item7);

		JMenuItem item8 = new JMenuItem("Clear force-relation");
		item8.addActionListener(new ActionListener() {

			@Override
			public void actionPerformed(ActionEvent e) {
				if (funcList.isEmpty()) {
					return;
				}
				try {
					funcList = service.markRecordsForceRelation(funcList, false);
					model.resetWholeTable(funcList);
				}
				catch (IOException e1) {
					Msg.error(this, "Error performing 'Clear force-relation'", e1);
				}
			}
		});
		menu.add(item8);

		JMenuItem item9 = new JMenuItem("Save changes");
		item9.addActionListener(new ActionListener() {

			@Override
			public void actionPerformed(ActionEvent e) {
				if (funcList.isEmpty()) {
					return;
				}
				HashSet<FidDB> dedupMap = new HashSet<>();
				for (FunctionRecord funcRec : funcList) {
					FidDB fidDb = funcRec.getFidDb();
					if (dedupMap.contains(fidDb)) {
						continue;			// Already saved
					}
					dedupMap.add(fidDb);
					try {
						fidDb.saveDatabase("saving", TaskMonitor.DUMMY);
					}
					catch (IOException e1) {
						Msg.error(this, "Error performing 'Save changes'", e1);
					}
					catch (CancelledException e1) {
						// can't happen, using Dummy monitory
					}
				}
			}
		});
		menu.add(item9);

		return menuBar;
	}

	@Override
	public void dispose() {
		table.dispose();
		dbService.removeCloseListener(this);
		super.dispose();
	}

	@Override
	public void fidQueryClosed(FidQueryService service) {
		dispose();
	}
}
