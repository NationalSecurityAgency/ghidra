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
package ghidra.framework.main.datatree;

import java.awt.*;
import java.awt.datatransfer.Transferable;
import java.awt.dnd.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import javax.swing.*;
import javax.swing.event.ListSelectionListener;
import javax.swing.table.TableColumn;
import javax.swing.table.TableColumnModel;

import docking.ActionContext;
import docking.action.*;
import docking.dnd.*;
import docking.widgets.OptionDialog;
import docking.widgets.table.*;
import ghidra.app.util.GenericHelpTopics;
import ghidra.framework.client.ClientUtil;
import ghidra.framework.main.GetVersionedObjectTask;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.store.ItemCheckoutStatus;
import ghidra.framework.store.Version;
import ghidra.util.*;
import ghidra.util.task.*;

/**
 * Panel that shows version history in a JTable
 */
public class VersionHistoryPanel extends JPanel implements Draggable {

	private static final HelpLocation HELP =
		new HelpLocation(GenericHelpTopics.VERSION_CONTROL, "Show History");

	private PluginTool tool;
	private DomainFile domainFile;
	private String domainFilePath;
	private VersionHistoryTableModel tableModel;
	private GTable table;

	private DragSource dragSource;
	private DragGestureAdapter dragGestureAdapter;
	private DragSrcAdapter dragSourceAdapter;
	private int dragAction = DnDConstants.ACTION_COPY_OR_MOVE;

	/**
	 * Constructor
	 * @param tool tool
	 * @param domainFile domain file; may be null
	 * @throws IOException if there was a problem accessing the
	 * version history
	 */
	public VersionHistoryPanel(PluginTool tool, DomainFile domainFile) throws IOException {
		this(tool, domainFile, false);
	}

	/**
	 * Constructor
	 * @param tool tool
	 * @param domainFile domain file
	 * @param enableUserInteraction if true Draggable support will be enabled
	 */
	VersionHistoryPanel(PluginTool tool, DomainFile domainFile, boolean enableUserInteraction) {
		super(new BorderLayout());
		this.tool = tool;
		create();
		if (enableUserInteraction) {
			setUpDragSite();
			table.addMouseListener(new MyMouseListener());
		}
		setDomainFile(domainFile);
	}

	/**
	 * Set the domain file to show its history
	 * @param domainFile the file
	 */
	public void setDomainFile(DomainFile domainFile) {
		this.domainFile = domainFile;
		if (domainFile != null) {
			this.domainFilePath = domainFile.getPathname();
		}
		refresh();
	}

	/**
	 * Get current domain file
	 * @return current domain file
	 */
	public DomainFile getDomainFile() {
		return domainFile;
	}

	/**
	 * Get current domain file path or null
	 * @return domain file path
	 */
	public String getDomainFilePath() {
		return domainFilePath;
	}

	/**
	 * Add the list selection listener to the history table
	 * @param selectionListener the listener
	 */
	public void addListSelectionListener(ListSelectionListener selectionListener) {
		table.getSelectionModel().addListSelectionListener(selectionListener);
	}

	/**
	 * Remove the list selection listener from history table.
	 * @param selectionListener the listener
	 */
	public void removeListSelectionListener(ListSelectionListener selectionListener) {
		table.getSelectionModel().removeListSelectionListener(selectionListener);
	}

	/**
	 * Get the domain object for the selected version.
	 * @param consumer the consumer
	 * @param readOnly true if read only
	 * @return null if there is no selection
	 */
	public DomainObject getSelectedVersion(Object consumer, boolean readOnly) {
		int row = table.getSelectedRow();
		if (row >= 0) {
			Version version = tableModel.getVersionAt(row);
			return getVersionedObject(consumer, version.getVersion(), readOnly);
		}
		return null;
	}

	public boolean isVersionSelected() {
		return !table.getSelectionModel().isSelectionEmpty();
	}

	public int getSelectedVersionNumber() {
		int row = table.getSelectedRow();
		if (row >= 0) {
			Version version = tableModel.getVersionAt(row);
			return version.getVersion();
		}
		return -1;
	}

	@Override
	public void dragCanceled(DragSourceDropEvent event) {
		// no-op
	}

	@Override
	public int getDragAction() {
		return dragAction;
	}

	@Override
	public DragSourceListener getDragSourceListener() {
		return dragSourceAdapter;
	}

	@Override
	public Transferable getTransferable(Point p) {
		int row = table.rowAtPoint(p);
		if (row >= 0) {
			Version version = tableModel.getVersionAt(row);
			return new VersionInfoTransferable(domainFile.getPathname(), version.getVersion());
		}
		return null;
	}

	@Override
	public boolean isStartDragOk(DragGestureEvent e) {
		int row = table.rowAtPoint(e.getDragOrigin());
		if (row >= 0) {
			return true;
		}
		return false;
	}

	@Override
	public void move() {
		// no-op
	}

	// For Junit tests
	VersionHistoryTableModel getVersionHistoryTableModel() {
		return tableModel;
	}

	private void create() {

		tableModel = new VersionHistoryTableModel(new Version[0]);

		table = new GTable(tableModel);
		JScrollPane sp = new JScrollPane(table);
		table.setPreferredScrollableViewportSize(new Dimension(600, 120));
		table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		add(sp, BorderLayout.CENTER);

		TableColumnModel columnModel = table.getColumnModel();
		MyCellRenderer cellRenderer = new MyCellRenderer();

		for (int i = 0; i < columnModel.getColumnCount(); i++) {
			TableColumn column = columnModel.getColumn(i);
			GTableHeaderRenderer headRenderer = new GTableHeaderRenderer();
			column.setHeaderRenderer(headRenderer);
			column.setCellRenderer(cellRenderer);
			String name = (String) column.getIdentifier();
			if (name.equals(VersionHistoryTableModel.VERSION)) {
				column.setPreferredWidth(80);
			}
			else if (name.equals(VersionHistoryTableModel.DATE)) {
				column.setPreferredWidth(210);
			}
			else if (name.equals(VersionHistoryTableModel.COMMENTS)) {
				column.setPreferredWidth(250);
			}
			else if (name.equals(VersionHistoryTableModel.USER)) {
				column.setPreferredWidth(125);
			}
		}
	}

	/**
	 * Set up the drag and drop stuff.
	 */
	private void setUpDragSite() {

		// set up drag stuff
		dragSource = DragSource.getDefaultDragSource();
		dragGestureAdapter = new DragGestureAdapter(this);
		dragSourceAdapter = new DragSrcAdapter(this);
		dragSource.createDefaultDragGestureRecognizer(table, dragAction, dragGestureAdapter);
	}

	private DomainObject getVersionedObject(Object consumer, int versionNumber, boolean readOnly) {
		GetVersionedObjectTask task =
			new GetVersionedObjectTask(consumer, domainFile, versionNumber, readOnly);
		tool.execute(task, 1000);
		return task.getVersionedObject();
	}

	private void delete() {
		int row = table.getSelectedRow();
		if (row != 0 && row != tableModel.getRowCount() - 1) {
			Msg.showError(this, this, "Cannot Delete Version",
				"Only first and last version may be deleted.");
			return;
		}
		Version version = tableModel.getVersionAt(row);
		try {
			for (ItemCheckoutStatus status : domainFile.getCheckouts()) {
				if (status.getCheckoutVersion() == version.getVersion()) {
					Msg.showError(this, this, "Cannot Delete Version",
						"File version has one or more checkouts.");
					return;
				}

			}
			if (confirmDelete()) {
				DeleteTask task = new DeleteTask(version.getVersion());
				new TaskLauncher(task, this);
			}
		}
		catch (IOException e) {
			ClientUtil.handleException(tool.getProject().getRepository(), e, "Delete Version",
				this);
		}
	}

	private boolean confirmDelete() {
		String message;
		int messageType;
		if (tableModel.getRowCount() == 1) {
			message = "Deleting the only version will permanently delete the file.\n" +
				"Are you sure you want to continue?";
			messageType = OptionDialog.WARNING_MESSAGE;
		}
		else {
			message = "Are you sure you want to delete the selected version?";
			messageType = OptionDialog.QUESTION_MESSAGE;

		}
		return OptionDialog.showOptionDialog(table, "Delete Version", message, "Delete",
			messageType) == OptionDialog.OPTION_ONE;
	}

	void refresh() {
		try {
			Version[] history = null;
			if (domainFile != null) {
				history = domainFile.getVersionHistory();
			}
			if (history == null) {
				history = new Version[0];
			}
			tableModel.refresh(history);
		}
		catch (IOException e) {
			ClientUtil.handleException(tool.getProject().getRepository(), e, "Get Version History",
				this);
		}
	}

	private void openWith(String toolName) {
		int row = table.getSelectedRow();
		Version version = tableModel.getVersionAt(row);
		DomainObject versionedObj = getVersionedObject(this, version.getVersion(), true);
		if (versionedObj != null) {
			if (toolName != null) {
				tool.getToolServices().launchTool(toolName, versionedObj.getDomainFile());
			}
			else {
				tool.getToolServices().launchDefaultTool(versionedObj.getDomainFile());
			}
			versionedObj.release(this);
		}
	}

	private void open() {
		openWith(null);
	}

	public List<DockingActionIf> createPopupActions() {

		List<DockingActionIf> list = new ArrayList<>();
		list.add(new DeleteAction());

		Project project = tool.getProject();
		ToolChest toolChest = project.getLocalToolChest();
		if (toolChest == null) {
			return list;
		}

		ToolTemplate[] templates = toolChest.getToolTemplates();
		if (templates.length == 0) {
			return list;
		}

		list.add(new OpenDefaultAction());
		for (ToolTemplate toolTemplate : templates) {
			list.add(new OpenWithAction(toolTemplate.getName()));
		}

		return list;
	}

	GTable getTable() {
		return table;
	}

//==================================================================================================
// Inner Classes
//==================================================================================================	

	private class MyCellRenderer extends GTableCellRenderer {

		@Override
		public Component getTableCellRendererComponent(GTableCellRenderingData data) {

			super.getTableCellRendererComponent(data);

			Object value = data.getValue();
			int row = data.getRowViewIndex();
			int col = data.getColumnModelIndex();

			if (value instanceof Date) {
				setText(DateUtils.formatDateTimestamp((Date) value));
			}

			setBorder(BorderFactory.createEmptyBorder(0, 5, 0, 0));

			String toolTipText = null;

			Version version = tableModel.getVersionAt(row);
			if (col == VersionHistoryTableModel.COMMENTS_COL) {
				String comments = version.getComment();
				if (comments != null) {
					toolTipText = HTMLUtilities.toHTML(comments);
				}
			}
			else if (col == VersionHistoryTableModel.DATE_COL) {
				toolTipText = "Date when version was created";
			}
			setToolTipText(toolTipText);
			return this;
		}

	}

	private abstract class HistoryTableAction extends DockingAction {

		HistoryTableAction(String name) {
			super(name, "Version History Panel", false);
			setHelpLocation(HELP);
		}

		@Override
		public boolean isEnabledForContext(ActionContext context) {
			MouseEvent mouseEvent = context.getMouseEvent();
			if (mouseEvent == null) {
				return false;
			}

			if (context.getSourceComponent() != table) {
				return false;
			}

			if (domainFile == null) {
				return false;
			}

			int rowAtPoint = table.rowAtPoint(mouseEvent.getPoint());
			return rowAtPoint >= 0;
		}
	}

	private class DeleteAction extends HistoryTableAction {
		DeleteAction() {
			super("Delete Version");
			setDescription(
				"Deletes the selected version (Only first and last version can be deleted)");
			setPopupMenuData(new MenuData(new String[] { "Delete" }, "AAA"));
		}

		@Override
		public void actionPerformed(ActionContext context) {
			delete();
		}
	}

	private class OpenDefaultAction extends HistoryTableAction {
		OpenDefaultAction() {
			super("Open In Default Tool");
			setDescription("Opens the selected version in the default tool.");
			MenuData data = new MenuData(new String[] { "Open in Default Tool" }, "AAB");
			data.setMenuSubGroup("1"); // before the specific tool 'open' actions
			setPopupMenuData(data);
		}

		@Override
		public void actionPerformed(ActionContext context) {
			open();
		}
	}

	private class OpenWithAction extends HistoryTableAction {
		private String toolName;

		OpenWithAction(String toolName) {
			super("Open With " + toolName);
			this.toolName = toolName;
			setDescription("Opens the version using the " + toolName + " tool.");
			MenuData data = new MenuData(new String[] { "Open With", toolName }, "AAB");
			setPopupMenuData(data);
		}

		@Override
		public void actionPerformed(ActionContext context) {
			openWith(toolName);
		}
	}

	private class MyMouseListener extends MouseAdapter {
		@Override
		public void mouseClicked(MouseEvent e) {
			handleMouseClick(e);
		}

		private void handleMouseClick(MouseEvent e) {
			if (e.getButton() == MouseEvent.BUTTON1 && e.getClickCount() == 2) {
				int row = table.rowAtPoint(e.getPoint());
				if (row < 0) {
					return;
				}
				open();
			}
		}
	}

	private class DeleteTask extends Task {
		private int versionNumber;

		DeleteTask(int versionNumber) {
			super("Delete Version", false, false, true);
			this.versionNumber = versionNumber;
		}

		@Override
		public void run(TaskMonitor monitor) {
			try {
				domainFile.delete(versionNumber);
			}
			catch (IOException e) {
				ClientUtil.handleException(tool.getProject().getRepository(), e, "Delete Version",
					VersionHistoryPanel.this);
			}
		}

	}
}
