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
package ghidra.plugins.importer.batch;

import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.util.ArrayList;
import java.util.EventObject;
import java.util.List;
import java.util.stream.Collectors;

import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.event.ListDataEvent;
import javax.swing.event.ListDataListener;
import javax.swing.table.*;

import docking.DialogComponentProvider;
import docking.widgets.ListSelectionTableDialog;
import docking.widgets.checkbox.GCheckBox;
import docking.widgets.combobox.GComboBox;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import docking.widgets.label.GDLabel;
import docking.widgets.table.*;
import ghidra.app.services.ProgramManager;
import ghidra.formats.gfilesystem.*;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.plugintool.PluginTool;
import ghidra.plugin.importer.ImporterUtilities;
import ghidra.plugins.importer.batch.BatchGroup.BatchLoadConfig;
import ghidra.plugins.importer.tasks.ImportBatchTask;
import ghidra.util.*;
import ghidra.util.filechooser.GhidraFileFilter;
import ghidra.util.task.TaskLauncher;

public class BatchImportDialog extends DialogComponentProvider {

	/**
	 * Shows the batch import dialog (via runSwingLater) and prompts the user to select
	 * a file if the supplied {@code batchInfo} is empty.
	 * <p>
	 * The dialog will chain to the {@link ImportBatchTask} when the user clicks the
	 * OK button.
	 * <p>
	 * @param tool {@link PluginTool} that will be the parent of the dialog
	 * @param batchInfo optional {@link BatchInfo} instance with already discovered applications, or null.
	 * @param initialFiles optional {@link List} of {@link FSRL files} to add to the batch import dialog, or null.
	 * @param defaultFolder optional default destination folder for imported files or null for root folder.
	 * @param programManager optional {@link ProgramManager} that will be used to open the newly imported
	 * binaries.
	 */
	public static void showAndImport(PluginTool tool, BatchInfo batchInfo, List<FSRL> initialFiles,
			DomainFolder defaultFolder, ProgramManager programManager) {
		BatchImportDialog dialog = new BatchImportDialog(batchInfo, defaultFolder);
		dialog.setProgramManager(programManager);
		SystemUtilities.runSwingLater(() -> {
			dialog.build();
			if (initialFiles != null && !initialFiles.isEmpty()) {
				dialog.addSources(initialFiles);
			}
			if (!dialog.setupInitialDefaults()) {
				return;
			}
			tool.showDialog(dialog);
		});
	}

	private BatchInfo batchInfo;
	private DomainFolder destinationFolder;
	private ProgramManager programManager;
	private boolean stripLeading = true;
	private boolean stripContainer = false;
	private boolean openAfterImporting = false;

	private BatchImportTableModel tableModel;
	private GTable table;
	private JButton removeSourceButton;
	private JButton rescanButton;
	private JSpinner maxDepthSpinner;

	private GhidraFileChooser fileChooser;
	private SourcesListModel sourceListModel;

	private BatchImportDialog(BatchInfo batchInfo, DomainFolder defaultFolder) {
		super("Batch Import", true);

		this.batchInfo = (batchInfo != null) ? batchInfo : new BatchInfo();
		this.destinationFolder = defaultFolder != null ? defaultFolder
				: ghidra.framework.main.AppInfo.getActiveProject().getProjectData().getRootFolder();
		setHelpLocation(new HelpLocation("ImporterPlugin", "Batch_Import_Dialog"));

		// a reasonable size that is long enough to show path information and table columns with
		// a height that has enough room to show table rows and import sources
		setPreferredSize(900, 600);
	}

	private void build() {
		tableModel = new BatchImportTableModel(batchInfo) {
			@Override
			public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
				super.setValueAt(aValue, rowIndex, columnIndex);
				refreshButtons();
			}

		};
		table = new GTable(tableModel);

		table.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {

				Point p = e.getPoint();
				int row = table.rowAtPoint(p);
				int col = table.columnAtPoint(p);
				TableColumnModel columnModel = table.getColumnModel();
				TableColumn column = columnModel.getColumn(col);
				int modelIndex = column.getModelIndex();
				if (modelIndex == BatchImportTableModel.COLS.FILES.ordinal()) {
					showFiles(row);
				}
			}
		});

		// Turn off all grid lines - this is a problem on windows.
		table.setShowGrid(false);
		table.setIntercellSpacing(new Dimension(0, 0));

		TableColumn selectedColumn =
			table.getColumnModel().getColumn(BatchImportTableModel.COLS.SELECTED.ordinal());
		selectedColumn.setResizable(false);
		// TODO: automagically get necessary col width
		selectedColumn.setMaxWidth(50);

		TableColumn filesColumn =
			table.getColumnModel().getColumn(BatchImportTableModel.COLS.FILES.ordinal());

		filesColumn.setCellEditor(createFilesColumnCellEditor());
		filesColumn.setCellRenderer(createFilesColumnCellRenderer());

		TableColumn langColumn =
			table.getColumnModel().getColumn(BatchImportTableModel.COLS.LANG.ordinal());
		langColumn.setCellEditor(createLangColumnCellEditor());
		langColumn.setCellRenderer(createLangColumnCellRenderer());

		JScrollPane scrollPane = new JScrollPane(table);

		JPanel filesPanel = new JPanel();
		filesPanel.setLayout(new BorderLayout());
		filesPanel.add(scrollPane, BorderLayout.CENTER);
		filesPanel.setBorder(createTitledBorder("Files to Import", true));

		JPanel sourceListPanel = new JPanel();
		sourceListPanel.setLayout(new BorderLayout());
		sourceListPanel.setBorder(createTitledBorder("Import Sources", false));

		sourceListModel = new SourcesListModel();

		JList<String> sourceList = new JList<>(sourceListModel);
		sourceList.setName("batch.import.source.list");
		sourceList.addListSelectionListener(e -> {
			if (!e.getValueIsAdjusting()) {
				boolean hasSelection = sourceList.getSelectedIndices().length > 0;
				removeSourceButton.setEnabled(hasSelection);
			}
		});
		JScrollPane sourceListScrollPane = new JScrollPane(sourceList);
		sourceListPanel.add(sourceListScrollPane, BorderLayout.CENTER);

		JPanel sourceOptionsPanel = new JPanel();

		// some padding before the files table
		sourceOptionsPanel.setBorder(BorderFactory.createEmptyBorder(0, 0, 10, 0));
		sourceListPanel.add(sourceOptionsPanel, BorderLayout.SOUTH);

		JPanel maxDepthPanel = new JPanel();
		JLabel maxDepthLabel = new GDLabel("Depth limit:");
		String maxDepthTip = "Maximum container (ie. nested zip, tar, etc) depth in the " +
			"source file to recursively descend into";
		maxDepthLabel.setToolTipText(maxDepthTip);
		maxDepthPanel.add(maxDepthLabel);

		SpinnerNumberModel spinnerNumberModel =
			new SpinnerNumberModel(batchInfo.getMaxDepth(), 0, 99, 1);
		maxDepthSpinner = new JSpinner(spinnerNumberModel);
		maxDepthSpinner.setToolTipText(maxDepthTip);
		rescanButton = new JButton("Rescan");
		rescanButton.setToolTipText(
			"Clear Files to Import list and rescan Import Sources for applications to import");

		spinnerNumberModel.addChangeListener(e -> {
			rescanButton.setEnabled(
				spinnerNumberModel.getNumber().intValue() != batchInfo.getMaxDepth());
		});
		rescanButton.addActionListener(e -> {
			// NOTE: using invokeLater to avoid event handling issues where
			// the spinner model gets updated several times (ie. multi-decrement when
			// it should be just 1 dec) if we do anything modal.
			SystemUtilities.runSwingLater(() -> {
				setMaxDepth(spinnerNumberModel.getNumber().intValue());
			});
		});
		maxDepthPanel.add(maxDepthSpinner);
		maxDepthPanel.add(rescanButton);
		sourceOptionsPanel.add(maxDepthPanel);

		JPanel sourceListButtonsPanel = new JPanel();
		sourceListButtonsPanel.setLayout(new BorderLayout());

		JButton addSourceButton = new JButton("Add");
		this.removeSourceButton = new JButton("Remove");
		removeSourceButton.setEnabled(false);

		addSourceButton.addActionListener(e -> {
			addSources();
		});

		removeSourceButton.addActionListener(e -> {
			List<FSRL> sourcesToRemove = new ArrayList<>();
			for (int index : sourceList.getSelectedIndices()) {
				if (index >= 0 && index < batchInfo.getUserAddedSources().size()) {
					UserAddedSourceInfo uasi = batchInfo.getUserAddedSources().get(index);
					sourcesToRemove.add(uasi.getFSRL());
				}
			}
			for (FSRL fsrl : sourcesToRemove) {
				batchInfo.remove(fsrl);
			}
			refreshData();
		});

		sourceListButtonsPanel.add(addSourceButton, BorderLayout.NORTH);
		sourceListButtonsPanel.add(removeSourceButton, BorderLayout.SOUTH);

		// another wrapping panel so the borderlayout'd sourceListButtonsPanel doesn't
		// get forced to take up the full EAST cell of the containing panel.
		JPanel buttonWrapperPanel = new JPanel();
		buttonWrapperPanel.add(sourceListButtonsPanel);
		sourceListPanel.add(buttonWrapperPanel, BorderLayout.EAST);

		sourceListModel.addListDataListener(new ListDataListener() {
			@Override
			public void intervalRemoved(ListDataEvent e) {
				contentsChanged(e);
			}

			@Override
			public void intervalAdded(ListDataEvent e) {
				contentsChanged(e);
			}

			@Override
			public void contentsChanged(ListDataEvent e) {
				boolean hasSelection = sourceList.getSelectedIndices().length > 0;
				removeSourceButton.setEnabled(hasSelection);
			}
		});

		JPanel outputOptionsPanel = buildOutputOptionsPanel();

		Box box = Box.createVerticalBox();
		box.add(sourceListPanel);
		box.add(filesPanel);
		box.add(outputOptionsPanel);

		addOKButton();
		addCancelButton();

		addWorkPanel(box);
	}

	private Border createTitledBorder(String title, boolean drawLine) {
		// a bit of padding to separate the sections
		return BorderFactory.createCompoundBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5),
			BorderFactory.createTitledBorder(' ' + title + ' '));
	}

	private JPanel buildOutputOptionsPanel() {

		JPanel outputChoicesPanel = new JPanel();
		outputChoicesPanel.setLayout(new BoxLayout(outputChoicesPanel, BoxLayout.LINE_AXIS));

		GCheckBox stripLeadingCb = new GCheckBox("Strip leading path", stripLeading);
		stripLeadingCb.addChangeListener(e -> setStripLeading(stripLeadingCb.isSelected()));
		stripLeadingCb.setToolTipText("The destination folder for imported files will not " +
			"include the source file's leading path");

		GCheckBox stripContainerCb = new GCheckBox("Strip container paths", stripContainer);
		stripContainerCb.addChangeListener(e -> setStripContainer(stripContainerCb.isSelected()));
		stripContainerCb.setToolTipText(
			"The destination folder for imported files will not include any source path names");

		GCheckBox openAfterImportCb = new GCheckBox("Open after import", openAfterImporting);
		openAfterImportCb.addChangeListener(
			e -> setOpenAfterImporting(openAfterImportCb.isSelected()));
		openAfterImportCb.setToolTipText("Open imported binaries in Code Browser");

		outputChoicesPanel.add(stripLeadingCb);
		outputChoicesPanel.add(stripContainerCb);
		if (programManager != null) {
			outputChoicesPanel.add(openAfterImportCb);
		}

		// add some spacing between this panel and the one below it
		outputChoicesPanel.setBorder(BorderFactory.createEmptyBorder(0, 0, 10, 0));

		BatchProjectDestinationPanel destPanel =
			new BatchProjectDestinationPanel(getComponent(), destinationFolder) {
				@Override
				public void onProjectDestinationChange(DomainFolder newFolder) {
					destinationFolder = newFolder;
				}
			};

		JPanel outputOptionsPanel = new JPanel(new BorderLayout());
		outputOptionsPanel.setBorder(createTitledBorder("Import Options", true));
		outputOptionsPanel.add(outputChoicesPanel, BorderLayout.NORTH);
		outputOptionsPanel.add(destPanel, BorderLayout.SOUTH);
		return outputOptionsPanel;
	}

	private void showFiles(int row) {

		BatchGroup group = tableModel.getRowObject(row);
		List<BatchLoadConfig> batchLoadConfigs = group.getBatchLoadConfig();

		//@formatter:off		
		List<String> names = batchLoadConfigs.stream()
			.map(batchLoadConfig -> batchLoadConfig.getPreferredFileName())
			.sorted()
			.collect(Collectors.toList())
			;
		//@formatter:on

		ListSelectionTableDialog<String> dialog =
			new ListSelectionTableDialog<>("Application Files", names);
		dialog.hideOkButton();
		dialog.showSelectMultiple(table);
	}

	private void setOpenAfterImporting(boolean b) {
		this.openAfterImporting = b;
	}

	private void refreshData() {
		sourceListModel.refresh();
		tableModel.refreshData();
		maxDepthSpinner.setValue(batchInfo.getMaxDepth());
		refreshButtons();
	}

	private void refreshButtons() {
		setOkEnabled(batchInfo.getEnabledCount() > 0);
		rescanButton.setEnabled(
			((Number) maxDepthSpinner.getValue()).intValue() != batchInfo.getMaxDepth());

	}

	public boolean setupInitialDefaults() {
		if (batchInfo.getUserAddedSources().isEmpty()) {
			if (!addSources()) {
				return false;
			}
		}

		if (batchInfo.getMaxDepth() < BatchInfo.MAXDEPTH_DEFAULT) {
			setMaxDepth(BatchInfo.MAXDEPTH_DEFAULT);
		}
		return true;
	}

	private boolean addSources() {
		if (fileChooser == null) {
			fileChooser = new GhidraFileChooser(getComponent());
			fileChooser.setMultiSelectionEnabled(true);
			fileChooser.setTitle("Choose File to Batch Import");
			fileChooser.setApproveButtonText("Select files");
			fileChooser.setFileSelectionMode(GhidraFileChooserMode.FILES_AND_DIRECTORIES);
			fileChooser.addFileFilter(ImporterUtilities.LOADABLE_FILES_FILTER);
			fileChooser.addFileFilter(ImporterUtilities.CONTAINER_FILES_FILTER);
			fileChooser.setSelectedFileFilter(GhidraFileFilter.ALL);
		}

		List<File> selectedFiles = fileChooser.getSelectedFiles();
		if (selectedFiles.isEmpty()) {
			return !fileChooser.wasCancelled();
		}

		List<FSRL> filesToAdd = new ArrayList<>();
		for (File selectedFile : selectedFiles) {
			filesToAdd.add(FileSystemService.getInstance().getLocalFSRL(selectedFile));
		}

		return addSources(filesToAdd);
	}

	private boolean addSources(List<FSRL> filesToAdd) {

		//@formatter:off
		List<FSRL> updatedFiles = filesToAdd
			.stream()
			.map(fsrl -> {
				if (fsrl instanceof FSRLRoot && fsrl.getFS().hasContainer()) {
					fsrl = fsrl.getFS().getContainer();
				}
				return fsrl; 
			})
			.collect(Collectors.toList())
			;
		//@formatter:on

		List<FSRL> badFiles = batchInfo.addFiles(updatedFiles);
		if (!badFiles.isEmpty()) {
			StringBuilder sb = new StringBuilder();
			for (FSRL fsrl : badFiles) {
				if (sb.length() > 0) {
					sb.append(",\n");
				}
				sb.append(fsrl.getPath());
			}

			Msg.showWarn(this, getComponent(), "Skipping " + badFiles.size() + " file(s)",
				"Program encountered while adding files to batch: " + sb.toString());

		}

		refreshData();

		return true;
	}

	@Override
	protected void okCallback() {
		new TaskLauncher(
			new ImportBatchTask(batchInfo, destinationFolder,
				openAfterImporting ? programManager : null, stripLeading, stripContainer),
			getComponent());
		close();
	}

	private TableCellEditor createFilesColumnCellEditor() {
		JComboBox<Object> comboBox = new GComboBox<>();
		DefaultCellEditor cellEditor = new DefaultCellEditor(comboBox) {
			@Override
			public boolean shouldSelectCell(EventObject anEvent) {
				return true;
			}

			@Override
			public Component getTableCellEditorComponent(JTable jtable, Object value,
					boolean isSelected, int row, int column) {
				comboBox.setSelectedItem("");
				comboBox.removeAllItems();

				BatchGroup rowVal = tableModel.getRowObject(row);
				comboBox.addItem("" + rowVal.size() + " files...");

				for (BatchLoadConfig batchLoadConfig : rowVal.getBatchLoadConfig()) {
					comboBox.addItem(batchLoadConfig.getPreferredFileName());
				}

				return super.getTableCellEditorComponent(table, value, isSelected, row, column);
			}
		};
		cellEditor.setClickCountToStart(2);
		return cellEditor;
	}

	private TableCellRenderer createFilesColumnCellRenderer() {
		TableCellRenderer cellRenderer = new GTableCellRenderer() {
			@Override
			public Component getTableCellRendererComponent(GTableCellRenderingData data) {

				JLabel renderer = (JLabel) super.getTableCellRendererComponent(data);
				renderer.setToolTipText("Click to view the files");
				return renderer;
			}

			@Override
			protected String getText(Object value) {
				BatchGroup batchGroup = (BatchGroup) value;
				if (batchGroup != null) {
					return batchGroup.size() + " files...";
				}
				return "";
			}
		};

		return cellRenderer;
	}

	private TableCellEditor createLangColumnCellEditor() {
		JComboBox<Object> comboBox = new GComboBox<>();
		DefaultCellEditor cellEditor = new DefaultCellEditor(comboBox) {
			@Override
			public boolean shouldSelectCell(EventObject anEvent) {
				return false;
			}

			@Override
			public Component getTableCellEditorComponent(JTable jtable, Object value,
					boolean isSelected, int row, int column) {
				comboBox.removeAllItems();
				BatchGroup batchGroup = tableModel.getRowObject(row);
				for (BatchGroupLoadSpec bo : batchGroup.getCriteria().getBatchGroupLoadSpecs()) {
					comboBox.addItem(bo);
				}

				return super.getTableCellEditorComponent(jtable, value, isSelected, row, column);
			}
		};

		return cellEditor;
	}

	private TableCellRenderer createLangColumnCellRenderer() {
		TableCellRenderer cellRenderer = new GTableCellRenderer() {
			{
				setHTMLRenderingEnabled(true);
			}

			@Override
			public Component getTableCellRendererComponent(GTableCellRenderingData data) {
				JLabel renderer = (JLabel) super.getTableCellRendererComponent(data);
				renderer.setToolTipText("Click to set language");
				return renderer;
			}

			@Override
			protected String getText(Object value) {
				BatchGroupLoadSpec bgls = (BatchGroupLoadSpec) value;
				return (bgls != null) ? bgls.toString()
						: "<html><font size=\"-2\" color=\"gray\">Click to set language</font>";
			}
		};

		return cellRenderer;
	}

	private class SourcesListModel extends AbstractListModel<String> {

		int prevSize = batchInfo.getUserAddedSources().size();

		@Override
		public int getSize() {
			return prevSize;
		}

		@Override
		public String getElementAt(int index) {
			List<UserAddedSourceInfo> list = batchInfo.getUserAddedSources();
			if (index >= list.size()) {
				return "Missing";
			}

			UserAddedSourceInfo uasi = list.get(index);
			String info = String.format("%s [%d files/%d apps/%d containers/%d%s levels]",
				uasi.getFSRL().getPath(), uasi.getRawFileCount(), uasi.getFileCount(),
				uasi.getContainerCount(),
				uasi.getMaxNestLevel() - uasi.getFSRL().getNestingDepth() + 1,
				uasi.wasRecurseTerminatedEarly() ? "+" : "");
			return info;
		}

		public void refresh() {
			if (prevSize > 0) {
				fireIntervalRemoved(this, 0, prevSize - 1);
			}
			prevSize = batchInfo.getUserAddedSources().size();
			if (prevSize > 0) {
				fireIntervalAdded(this, 0, prevSize - 1);
			}
		}

	}

	private void setStripLeading(boolean stripLeading) {
		this.stripLeading = stripLeading;
	}

	private void setStripContainer(boolean stripContainer) {
		this.stripContainer = stripContainer;
	}

	private void setMaxDepth(int newMaxDepth) {
		if (newMaxDepth == batchInfo.getMaxDepth()) {
			return;
		}

		batchInfo.setMaxDepth(newMaxDepth); // this runs a task
		refreshData();
	}

	private void setProgramManager(ProgramManager programManager) {
		this.programManager = programManager;
	}
}
