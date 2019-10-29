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
package ghidra.app.plugin.core.commentwindow;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.event.MouseEvent;

import javax.swing.*;
import javax.swing.table.JTableHeader;

import docking.ActionContext;
import ghidra.app.services.GoToService;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramSelection;
import ghidra.util.HelpLocation;
import ghidra.util.table.*;

/**
 * Provider for the comment window.
 */
class CommentWindowProvider extends ComponentProviderAdapter {

	private CommentWindowPlugin plugin;

	private GhidraThreadedTablePanel<CommentRowObject> threadedTablePanel;
	private GhidraTableFilterPanel<CommentRowObject> filterPanel;
	private JComponent mainPanel;

	private GhidraTable commentTable;
	private CommentTableModel commentModel;

	CommentWindowProvider(CommentWindowPlugin plugin) {
		super(plugin.getTool(), "Comment Window", plugin.getName());
		setTitle("Comments");
		this.plugin = plugin;
		mainPanel = createWorkPanel();
		tool.addComponentProvider(this, false);
	}

	@Override
	public void componentHidden() {
		commentModel.reload(null);
	}

	@Override
	public void componentShown() {
		commentModel.reload(plugin.getProgram());
	}

	@Override
	public ActionContext getActionContext(MouseEvent event) {
		return new CommentWindowContext(this, commentTable);
	}

	@Override
	public JComponent getComponent() {
		return mainPanel;
	}

	/*
	 * @see ghidra.framework.docking.HelpTopic#getHelpLocation()
	 */
	@Override
	public HelpLocation getHelpLocation() {
		return new HelpLocation(plugin.getName(), plugin.getName());
	}

	void programOpened(Program program) {
		if (isVisible()) {
			commentModel.reload(program);
		}
	}

	void programClosed() {
		commentModel.reload(null);
	}

	void dispose() {
		tool.removeComponentProvider(this);
		threadedTablePanel.dispose();
		filterPanel.dispose();
	}

	private JComponent createWorkPanel() {

		commentModel = new CommentTableModel(plugin);

		threadedTablePanel = new GhidraThreadedTablePanel<>(commentModel, 1000);
		commentTable = threadedTablePanel.getTable();
		commentTable.setName("CommentTable");
		commentTable.setAutoLookupColumn(CommentTableModel.TYPE_COL);
		commentTable.setPreferredScrollableViewportSize(new Dimension(600, 400));
		commentTable.setRowSelectionAllowed(true);
		commentTable.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
		commentTable.getSelectionModel().addListSelectionListener(e -> notifyContextChanged());

		commentModel.addTableModelListener(e -> {
			int rowCount = commentModel.getRowCount();
			int unfilteredCount = commentModel.getUnfilteredRowCount();

			StringBuilder buffy = new StringBuilder();

			buffy.append(rowCount).append(" items");
			if (rowCount != unfilteredCount) {
				buffy.append(" (of ").append(unfilteredCount).append(" )");
			}

			setSubTitle(buffy.toString());
		});

		GoToService goToService = tool.getService(GoToService.class);
		commentTable.installNavigation(goToService, goToService.getDefaultNavigatable());

		JTableHeader commentHeader = commentTable.getTableHeader();
		commentHeader.setUpdateTableInRealTime(true);

		filterPanel = new GhidraTableFilterPanel<>(commentTable, commentModel);
		commentTable.getModel();

		JPanel panel = new JPanel(new BorderLayout());
		panel.add(threadedTablePanel, BorderLayout.CENTER);
		panel.add(filterPanel, BorderLayout.SOUTH);

		return panel;
	}

	private void notifyContextChanged() {
		tool.contextChanged(this);
	}

	ProgramSelection selectComment() {
		return commentTable.getProgramSelection();
	}

	void reload() {
		if (isVisible()) {
			commentModel.reload(plugin.getProgram());
		}
	}

	void commentAdded(Address address, int commentType) {
		if (isVisible()) {
			commentModel.commentAdded(address, commentType);
		}
	}

	void commentRemoved(Address address, int commentType) {
		if (isVisible()) {
			commentModel.commentRemoved(address, commentType);
		}
	}

	public GhidraTable getTable() {
		return commentTable;
	}
}
