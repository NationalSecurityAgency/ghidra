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
package ghidra.framework.main.datatable;

import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.*;
import java.util.List;

import javax.swing.*;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.help.Help;
import docking.help.HelpService;
import docking.widgets.label.GHtmlLabel;
import docking.widgets.table.*;
import docking.widgets.table.threaded.*;
import ghidra.framework.main.FrontEndPlugin;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.*;
import ghidra.util.bean.GGlassPane;
import ghidra.util.bean.GGlassPanePainter;

public class ProjectDataTablePanel extends JPanel {

	private static final String MAX_FILE_COUNT_PROPERTY = "ProjectDataTable.maxFileCount";
	private static final int MAX_FILE_COUNT_DEFAULT = 2000;
	private static int maxFileCount = loadMaxFileCount();

	private FrontEndPlugin plugin;
	private PluginTool tool;
	private ProjectData projectData;
	private ProjectDataTableModel model;
	private boolean capacityExceeded;
	private GFilterTable<DomainFileInfo> table;
	private GTable gTable;
	private DomainFolderChangeListener changeListener;
	public Set<DomainFile> filesPendingSelection;

	private GHtmlLabel capacityExceededText =
		new GHtmlLabel("<HTML><CENTER><I>Table view disabled for very large projects, or<BR>" +
			"if an older project/repository filesystem is in use.<BR>" +
			"View will remain disabled until project is closed.</I></CENTER></HTML>");

	private GGlassPanePainter painter = new TableGlassPanePainter();

	public ProjectDataTablePanel(FrontEndPlugin plugin) {
		this.plugin = plugin;
		tool = plugin.getTool();
		buildContent();
		changeListener = new ProjectDataTableDomainFolderChangeListener();
	}

	private void buildContent() {
		model = new ProjectDataTableModel(tool);
		model.addThreadedTableModelListener(new SelectPendingFilesListener());
		table = new GFilterTable<>(model) {
			@Override
			protected GThreadedTablePanel<DomainFileInfo> createThreadedTablePanel(
					ThreadedTableModel<DomainFileInfo, ?> threadedModel) {

				return new GThreadedTablePanel<>(threadedModel) {
					@Override
					protected GTable createTable(ThreadedTableModel<DomainFileInfo, ?> m) {
						// the table's default actions aren't that useful in the Front End
						return new ProjectDataTable(m);
					}
				};
			}
		};
		setLayout(new BorderLayout());
		add(table, BorderLayout.CENTER);

		gTable = table.getTable();
		gTable.setActionsEnabled(true);
		gTable.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				checkOpen(e);
			}
		});
		gTable.getSelectionModel().addListSelectionListener(
			e -> plugin.getTool().contextChanged(null));
		gTable.setDefaultRenderer(Date.class, new DateCellRenderer());
		gTable.setDefaultRenderer(DomainFileType.class, new TypeCellRenderer());

		new ProjectDataTableDnDHandler(gTable, model);
	}

	public void dispose() {
		table.dispose(); // this will dispose the gTable as well
	}

	public void setHelpLocation(HelpLocation helpLocation) {
		HelpService help = Help.getHelpService();
		help.registerHelp(table, helpLocation);
	}

	public void setSelectedDomainFiles(Set<DomainFile> files) {
		if (model.isBusy()) {
			// we don't want to attempt to find the items to select while we the threaded
			// model is loading the new data
			filesPendingSelection = files;
			return;
		}

		doSetSelectedDomainFiles(files);
	}

	private void doSetSelectedDomainFiles(Set<DomainFile> files) {
		List<Integer> rowList = new ArrayList<>();
		List<DomainFileInfo> selectedRowObjects = new ArrayList<>();
		for (int row = 0; row < model.getRowCount(); row++) {
			DomainFileInfo info = model.getRowObject(row);
			DomainFile domainFile = info.getDomainFile();
			if (files.contains(domainFile)) {
				// it was in the set--add it to our list
				rowList.add(row);
				selectedRowObjects.add(info);
			}
		}

		selectRows(rowList);
	}

	private void selectRows(List<Integer> rowList) {
		ListSelectionModel selectionModel = gTable.getSelectionModel();
		selectionModel.setValueIsAdjusting(true);
		selectionModel.clearSelection();
		for (Integer row : rowList) {
			selectionModel.addSelectionInterval(row, row);
		}
		selectionModel.setValueIsAdjusting(false);
	}

	public void setProjectData(String name, ProjectData projectData) {
		if (this.projectData != null) {
			this.projectData.removeDomainFolderChangeListener(changeListener);
			model.setProjectData(null);
		}

		this.projectData = projectData;
		capacityExceeded = false;

		if (projectData != null) {

			checkCapacity();

			if (!capacityExceeded) {
				model.setProjectData(projectData);
				projectData.addDomainFolderChangeListener(changeListener);
			}
		}
	}

	private void checkCapacity() {

		if (projectData == null) {
			return;
		}

		int fileCount = projectData.getFileCount();

		if (fileCount < 0 || fileCount > maxFileCount) {
			capacityExceeded = true;
			this.projectData.removeDomainFolderChangeListener(changeListener);
			model.setProjectData(null);
			SystemUtilities.runSwingLater(() -> {
				GGlassPane glassPane = (GGlassPane) gTable.getRootPane().getGlassPane();
				glassPane.removePainter(painter);
				glassPane.addPainter(painter);
			});
		}
	}

	public ActionContext getActionContext(ComponentProvider provider, MouseEvent e) {
		int[] selectedRows = gTable.getSelectedRows();
		if (selectedRows.length == 0) {
			return null;
		}

		List<DomainFile> list = new ArrayList<>();
		for (int i : selectedRows) {
			DomainFileInfo info = model.getRowObject(i);
			list.add(info.getDomainFile());
		}

		return new ProjectDataContext(provider, projectData, model.getRowObject(selectedRows[0]),
			null, list, gTable, true);
	}

	private void checkOpen(MouseEvent e) {
		if (tool == null) { // dialog use
			return;
		}
		if (e.getButton() != MouseEvent.BUTTON1 || e.getClickCount() != 2) {
			return;
		}

		e.consume();
		Point point = e.getPoint();
		int rowAtPoint = gTable.rowAtPoint(point);
		if (rowAtPoint < 0) {
			return;
		}
		DomainFileInfo rowObject = model.getRowObject(rowAtPoint);
		DomainFile domainFile = rowObject.getDomainFile();
		plugin.openDomainFile(domainFile);
	}

	private void clearInfo(DomainFile file) {
		List<DomainFileInfo> modelData = model.getModelData();
		for (DomainFileInfo domainFileInfo : modelData) {
			if (domainFileInfo.getDomainFile().equals(file)) {
				domainFileInfo.clearMetaCache();
				break;
			}
		}
	}

	private void reload() {

		checkCapacity();

		if (!capacityExceeded) {
			model.reload();
		}

	}

	// load the max file count system property
	private static int loadMaxFileCount() {

		String property =
			System.getProperty(MAX_FILE_COUNT_PROPERTY, Integer.toString(MAX_FILE_COUNT_DEFAULT));

		Integer intValue = null;
		try {
			intValue = Integer.parseInt(property);
			if (intValue <= 0) {
				intValue = null;
			}
		}
		catch (NumberFormatException e) {
			// handled below
		}

		if (intValue == null) {
			Msg.error(ProjectDataTablePanel.class,
				"Invalid ProjectDataTable.maxFileCount property value: " + property);
			return MAX_FILE_COUNT_DEFAULT;
		}

		return intValue;
	}

//==================================================================================================
// Inner Classes
//==================================================================================================	

	private class ProjectDataTableDomainFolderChangeListener implements DomainFolderChangeListener {

		// TODO: file and subfolder events are only triggered if the parent folder has been
		// "visited" which means a folder added event will NOT be followed by any child
		// folder/file added events.  This is different from the old full-refresh mechanism
		// which sent added events for everything contained within a new sub-tree.

		private boolean ignoreChanges() {
			return model.loadWasCancelled() || capacityExceeded;
		}

		@Override
		public void domainFolderAdded(DomainFolder folder) {
			if (ignoreChanges()) {
				return;
			}
			reload();
		}

		@Override
		public void domainFileAdded(DomainFile file) {
			if (ignoreChanges()) {
				return;
			}
			checkCapacity();
			if (!capacityExceeded) {
				model.addObject(new DomainFileInfo(file));
			}
		}

		@Override
		public void domainFolderRemoved(DomainFolder parent, String name) {
			if (ignoreChanges()) {
				return;
			}
			model.refresh();
		}

		@Override
		public void domainFileRemoved(DomainFolder parent, String name, String fileID) {
			if (ignoreChanges()) {
				return;
			}
			String path = parent.getPathname();
			List<DomainFileInfo> modelData = model.getModelData();
			for (DomainFileInfo domainFileInfo : modelData) {
				if (name.equals(domainFileInfo.getName()) &&
					path.equals(domainFileInfo.getPath())) {
					model.removeObject(domainFileInfo);
					break;
				}
			}
		}

		@Override
		public void domainFolderRenamed(DomainFolder folder, String oldName) {
			if (ignoreChanges()) {
				return;
			}
			reload();
		}

		@Override
		public void domainFileRenamed(DomainFile file, String oldName) {
			if (ignoreChanges()) {
				return;
			}
			reload();
		}

		@Override
		public void domainFolderMoved(DomainFolder folder, DomainFolder oldParent) {
			if (ignoreChanges()) {
				return;
			}
			reload();
		}

		@Override
		public void domainFileMoved(DomainFile file, DomainFolder oldParent, String oldName) {
			if (ignoreChanges()) {
				return;
			}
			reload();
		}

		@Override
		public void domainFolderSetActive(DomainFolder folder) {
			// don't care
		}

		@Override
		public void domainFileStatusChanged(DomainFile file, boolean fileIDset) {
			if (ignoreChanges()) {
				return;
			}
			clearInfo(file);
			table.repaint();
			plugin.getTool().contextChanged(null);
		}

		@Override
		public void domainFileObjectReplaced(DomainFile file, DomainObject oldObject) {
			if (ignoreChanges()) {
				return;
			}
			clearInfo(file);
			table.repaint();
		}

		@Override
		public void domainFileObjectOpenedForUpdate(DomainFile file, DomainObject object) {
			// don't care
		}

		@Override
		public void domainFileObjectClosed(DomainFile file, DomainObject object) {
			// don't care
		}
	}

	/**
	 * A listener that checks for files that need to be selected after each model change.  This is
	 * required due to the asynchronous nature of the table loading and clients that wish to make
	 * selections, potentially before the table has loaded the items whose selection is desired.s
	 */
	private class SelectPendingFilesListener implements ThreadedTableModelListener {

		@Override
		public void loadingFinished(boolean wasCancelled) {
			if (filesPendingSelection != null) {
				// we have files that are the object of selection desire
				doSetSelectedDomainFiles(filesPendingSelection);
				filesPendingSelection = null;
			}
		}

		@Override
		public void loadPending() {
			// don't care
		}

		@Override
		public void loadingStarted() {
			// don't care
		}
	}

	private class ProjectDataTable extends GTable {

		public ProjectDataTable(ThreadedTableModel<DomainFileInfo, ?> m) {
			super(m);
		}

		@Override
		protected boolean supportsPopupActions() {
			return false;
		}
	}

	private class TableGlassPanePainter implements GGlassPanePainter {

		CellRendererPane renderer = new CellRendererPane();

		@Override
		public void paint(GGlassPane glassPane, Graphics graphics) {

			if (!capacityExceeded || !gTable.isShowing()) {
				return;
			}

			Container container = gTable.getParent();
			Rectangle bounds = container.getBounds();

			bounds =
				SwingUtilities.convertRectangle(container, bounds, getRootPane().getContentPane());

			Dimension preferredSize = capacityExceededText.getPreferredSize();

			int width = Math.min(preferredSize.width, bounds.width);
			int height = Math.min(preferredSize.height, bounds.height);

			int x = bounds.x + (bounds.width / 2 - width / 2);
			int y = bounds.y + (bounds.height / 2 - height / 2);

			renderer.paintComponent(graphics, capacityExceededText, container, x, y, width, height);
		}
	}

	private class DateCellRenderer extends GTableCellRenderer {

		@Override
		public Component getTableCellRendererComponent(GTableCellRenderingData data) {

			JLabel renderer = (JLabel) super.getTableCellRendererComponent(data);

			Object value = data.getValue();

			if (value != null) {
				renderer.setText(DateUtils.formatDateTimestamp((Date) value));
			}
			else {
				renderer.setText("");
			}
			return renderer;
		}
	}

	private class TypeCellRenderer extends GTableCellRenderer {

		@Override
		public Component getTableCellRendererComponent(GTableCellRenderingData data) {

			JLabel renderer = (JLabel) super.getTableCellRendererComponent(data);

			Object value = data.getValue();

			renderer.setText("");
			if (value != null) {
				DomainFileType type = (DomainFileType) value;
				setToolTipText(type.getContentType());
				setText("");
				setIcon(type.getIcon());
			}
			return renderer;
		}
	}

}
