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
package ghidra.app.plugin.core.sourcefilestable;

import java.awt.*;
import java.awt.event.MouseEvent;
import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.function.IntSupplier;

import javax.swing.*;

import docking.*;
import docking.action.builder.ActionBuilder;
import docking.widgets.table.RowObjectTableModel;
import docking.widgets.values.GValuesMap;
import docking.widgets.values.ValuesMapDialog;
import generic.theme.GIcon;
import ghidra.app.plugin.core.table.TableComponentProvider;
import ghidra.app.util.SearchConstants;
import ghidra.app.util.query.TableService;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.program.database.sourcemap.SourceFile;
import ghidra.program.database.sourcemap.UserDataPathTransformer;
import ghidra.program.model.listing.Program;
import ghidra.program.model.sourcemap.*;
import ghidra.program.util.ProgramChangeRecord;
import ghidra.program.util.ProgramEvent;
import ghidra.util.*;
import ghidra.util.table.GhidraFilterTable;
import ghidra.util.task.TaskMonitor;
import resources.Icons;

/**
 * A {@link ComponentProviderAdapter} for displaying source file information about a program.
 * This includes the {@link SourceFile}s added to the program's {@link SourceFileManager} as
 * well as source file path transformations.
 */
public class SourceFilesTableProvider extends ComponentProviderAdapter {

	private JSplitPane splitPane;
	private SourceFilesTablePlugin sourceFilesTablePlugin;
	private SourceFilesTableModel sourceFilesTableModel;
	private GhidraFilterTable<SourceFileRowObject> sourceFilesTable;
	private TransformerTableModel transformsModel;
	private GhidraFilterTable<SourcePathTransformRecord> transformsTable;
	private boolean isStale;

	private static final String DESTINATION = "Dest";
	private static final String SOURCE = "Src";

	/**
	 * Constructor
	 * @param sourceFilesPlugin plugin
	 */
	public SourceFilesTableProvider(SourceFilesTablePlugin sourceFilesPlugin) {
		super(sourceFilesPlugin.getTool(), "Source Files and Transforms",
			sourceFilesPlugin.getName());
		this.sourceFilesTablePlugin = sourceFilesPlugin;
		tool.addComponentProvider(this, false);
		buildMainPanel();
		createActions();
		setHelpLocation(
			new HelpLocation(sourceFilesTablePlugin.getName(), "Source_Files_Table_Plugin"));
		setIsStale(false);
	}

	@Override
	public JComponent getComponent() {
		return splitPane;
	}

	@Override
	public ActionContext getActionContext(MouseEvent event) {
		if (event != null) {
			return getActionContext(event.getSource());
		}
		KeyboardFocusManager kfm = KeyboardFocusManager.getCurrentKeyboardFocusManager();
		return getActionContext(kfm.getFocusOwner());
	}

	@Override
	public void componentShown() {
		reloadModels(sourceFilesTablePlugin.getCurrentProgram());
	}

	@Override
	public void componentHidden() {
		reloadModels(null);
	}

	/**
	 * Reloads the model with {@code program} if the provider is showing.
	 * @param program activated program
	 */
	void programActivated(Program program) {
		if (isVisible()) {
			reloadModels(program);
		}
	}

	/**
	 * Clears the models.
	 */
	void clearTableModels() {
		reloadModels(null);
	}

	/**
	 * Sets the value of isStale and invokes {@link ComponentProvider#contextChanged()}
	 * @param b value
	 */
	void setIsStale(boolean b) {
		isStale = b;
		contextChanged();
	}

	/**
	 * Sets isStale to {@code true} when {@code rec} has an event type relevant to the source
	 * file table.  If the event type is {@link ProgramEvent#SOURCE_FILE_REMOVED}, any associated
	 * file transform is also removed.
	 * 
	 * @param rec program change record
	 */
	void handleProgramChange(ProgramChangeRecord rec) {
		// if a source file is removed, remove the associated file transform
		// note: if the removal of the file is undone, the file transform will not be restored
		switch (rec.getEventType()) {
			case ProgramEvent.SOURCE_FILE_REMOVED:
				SourceFile removed = (SourceFile) rec.getOldValue();
				SourcePathTransformer pathTransformer =
					UserDataPathTransformer.getPathTransformer(sourceFilesTableModel.getProgram());
				pathTransformer.removeFileTransform(removed);
				transformsModel.reload();
				// fall through intentional
			case ProgramEvent.SOURCE_FILE_ADDED:
			case ProgramEvent.SOURCE_MAP_CHANGED:
				setIsStale(true);
				break;
			default:
				break;
		}
		return;
	}

	private void reloadModels(Program program) {
		sourceFilesTableModel.reloadProgram(program);
		transformsModel.reloadProgram(program);
		setIsStale(false);
	}

	// we want different actions depending on which table you right-click in
	private ActionContext getActionContext(Object source) {
		if (source == sourceFilesTable.getTable()) {
			return new SourceFilesTableActionContext();
		}
		if (source == transformsTable.getTable()) {
			return new TransformTableActionContext();
		}
		return null;
	}

	private void buildMainPanel() {
		sourceFilesTableModel = new SourceFilesTableModel(sourceFilesTablePlugin);
		sourceFilesTable = new GhidraFilterTable<>(sourceFilesTableModel);
		sourceFilesTable.setAccessibleNamePrefix("Source Files");

		JPanel sourceFilesPanel = buildTitledTablePanel("Source Files", sourceFilesTable,
			() -> sourceFilesTableModel.getUnfilteredRowCount());

		transformsModel = new TransformerTableModel(sourceFilesTablePlugin);
		transformsTable = new GhidraFilterTable<>(transformsModel);
		transformsTable.setAccessibleNamePrefix("Transformations");

		JPanel transformsPanel = buildTitledTablePanel("Transforms", transformsTable,
			() -> transformsModel.getUnfilteredRowCount());

		splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
		splitPane.setResizeWeight(0.5);
		splitPane.setDividerSize(10);
		splitPane.setLeftComponent(sourceFilesPanel);
		splitPane.setRightComponent(transformsPanel);
		splitPane.setPreferredSize(new Dimension(1000, 800));
	}

	private JPanel buildTitledTablePanel(String title, GhidraFilterTable<?> table,
			IntSupplier nonFilteredRowCount) {
		JPanel panel = new JPanel(new BorderLayout());
		panel.setBorder(BorderFactory.createEmptyBorder(10, 2, 10, 2));
		JLabel titleLabel = new JLabel(title);
		panel.add(titleLabel, BorderLayout.NORTH);
		panel.add(table, BorderLayout.CENTER);

		RowObjectTableModel<?> model = table.getModel();
		model.addTableModelListener((e) -> {
			int rowCount = model.getRowCount();
			String text = title + "  - " + rowCount + " rows";
			int nonFilteredSize = nonFilteredRowCount.getAsInt();
			if (nonFilteredSize != rowCount) {
				text += "   (Filtered from " + nonFilteredSize + " rows)";
			}
			titleLabel.setText(text);
		});
		return panel;
	}

	private void createActions() {

		new ActionBuilder("Show Source Map Entries", getName())
				.popupMenuPath("Show Source Map Entries")
				.description("Show a table of the source map entries associated with a SourceFile")
				.helpLocation(
					new HelpLocation(sourceFilesTablePlugin.getName(), "Show_Source_Map_Entries"))
				.withContext(SourceFilesTableActionContext.class)
				.enabledWhen(c -> c.getSelectedRowCount() == 1)
				.onAction(this::showSourceMapEntries)
				.buildAndInstallLocal(this);

		new ActionBuilder("View Source File", getName())
				.popupMenuPath("View Source File")
				.description("View the Source File")
				.helpLocation(
					new HelpLocation(sourceFilesTablePlugin.getName(), "View_Source_File"))
				.withContext(SourceFilesTableActionContext.class)
				.enabledWhen(c -> c.getSelectedRowCount() == 1)
				.onAction(this::viewSourceFile)
				.buildAndInstallLocal(this);

		new ActionBuilder("Transform File", getName()).popupMenuPath("Tranform File")
				.description("Enter a file transform for a SourceFile")
				.helpLocation(new HelpLocation(sourceFilesTablePlugin.getName(), "Transform_File"))
				.withContext(SourceFilesTableActionContext.class)
				.enabledWhen(c -> c.getSelectedRowCount() == 1)
				.onAction(this::transformSourceFileAction)
				.buildAndInstallLocal(this);

		new ActionBuilder("Transform Directory", getName())
				.popupMenuPath("Transform Directory")
				.description("Add a directory transform based on this file's path")
				.helpLocation(
					new HelpLocation(sourceFilesTablePlugin.getName(), "Transform_Directory"))
				.withContext(SourceFilesTableActionContext.class)
				.enabledWhen(c -> c.getSelectedRowCount() == 1)
				.onAction(this::transformPath)
				.buildAndInstallLocal(this);

		new ActionBuilder("Remove Transform", getName()).popupMenuPath("Remove Transform")
				.description("Remove a transform")
				.helpLocation(
					new HelpLocation(sourceFilesTablePlugin.getName(), "Remove_Transform"))
				.withContext(TransformTableActionContext.class)
				.enabledWhen(c -> c.getSelectedRowCount() == 1)
				.onAction(this::removeTransform)
				.buildAndInstallLocal(this);

		new ActionBuilder("Edit Transform", getName()).popupMenuPath("Edit Transform")
				.description("Edit the transform")
				.helpLocation(new HelpLocation(sourceFilesTablePlugin.getName(), "Edit_Transform"))
				.withContext(TransformTableActionContext.class)
				.onAction(c -> editTransform())
				.buildAndInstallLocal(this);

		new ActionBuilder("Reload Source File Table", getName()).toolBarIcon(Icons.REFRESH_ICON)
				.description("Reloads the Source File Table")
				.helpLocation(
					new HelpLocation(sourceFilesTablePlugin.getName(), "Reload_Source_Files_Model"))
				.enabledWhen(c -> isStale)
				.onAction(c -> reloadModels(sourceFilesTablePlugin.getCurrentProgram()))
				.buildAndInstallLocal(this);

	}

	private void removeTransform(TransformTableActionContext actionContext) {
		SourcePathTransformRecord rowObject = transformsTable.getSelectedRowObject();
		SourcePathTransformer pathTransformer =
			UserDataPathTransformer.getPathTransformer(transformsModel.getProgram());
		String source = rowObject.source();
		if (rowObject.isDirectoryTransform()) {
			pathTransformer.removeDirectoryTransform(source);
		}
		else {
			pathTransformer.removeFileTransform(rowObject.sourceFile());
		}
		transformsModel.reload();
		sourceFilesTableModel.refresh();
	}

	private void editTransform() {
		SourcePathTransformRecord transformRecord = transformsTable.getSelectedRowObject();
		if (transformRecord.isDirectoryTransform()) {
			editDirectoryTransform(transformRecord);
		}
		else {
			SourceFile sourceFile = transformRecord.sourceFile();
			transformSourceFile(sourceFile);
		}
		return;
	}

	private void editDirectoryTransform(SourcePathTransformRecord transformRecord) {
		SourcePathTransformer pathTransformer =
			UserDataPathTransformer.getPathTransformer(sourceFilesTableModel.getProgram());
		String source = transformRecord.source();
		GValuesMap valueMap = new GValuesMap();
		valueMap.defineDirectory(DESTINATION, new File(transformRecord.target()));
		valueMap.setValidator((map, status) -> {
			File directory = valueMap.getFile(DESTINATION);
			if (directory == null || !directory.exists()) {
				status.setStatusText("Directory does not exist", MessageType.ERROR);
				return false;
			}
			if (!directory.isDirectory()) {
				status.setStatusText("Must select a directory", MessageType.ERROR);
				return false;
			}
			return true;
		});
		ValuesMapDialog mapDialog =
			new ValuesMapDialog("Enter Directory Transform", "Transform for " + source, valueMap);
		tool.showDialog(mapDialog, this);
		GValuesMap results = mapDialog.getValues();
		if (results == null) {
			return;
		}
		try {
			String canonical = results.getFile(DESTINATION).getCanonicalPath();
			URI uri = new File(canonical).toURI().normalize();
			String transformedPath = uri.getPath();
			if (!transformedPath.endsWith("/")) {
				transformedPath = transformedPath + "/";
			}
			pathTransformer.addDirectoryTransform(source, transformedPath);
		}
		catch (IOException e) {
			Msg.showError(this, sourceFilesTable, "IOException getting canonical path",
				e.getMessage());
		}

		sourceFilesTableModel.refresh();
		transformsModel.reload();

	}

	private void transformPath(SourceFilesTableActionContext actionContext) {
		SourceFile sourceFile = sourceFilesTable.getSelectedRowObject().getSourceFile();
		String path = sourceFile.getPath();
		GValuesMap valueMap = new GValuesMap();
		List<String> parentDirs = new ArrayList<>();
		String[] directories = path.split("/");
		parentDirs.add("/");
		for (int i = 1; i < directories.length - 1; ++i) {
			String latest = parentDirs.get(i - 1);
			parentDirs.add(latest + directories[i] + "/");
		}
		valueMap.defineChoice(SOURCE, parentDirs.getLast(), parentDirs.toArray(new String[0]));
		valueMap.defineDirectory(DESTINATION, null);
		valueMap.setValidator((map, status) -> {
			File directory = valueMap.getFile(DESTINATION);
			if (directory == null || !directory.exists()) {
				status.setStatusText("Directory does not exist", MessageType.ERROR);
				return false;
			}
			if (!directory.isDirectory()) {
				status.setStatusText("Must select a directory", MessageType.ERROR);
				return false;
			}
			return true;
		});
		ValuesMapDialog mapDialog =
			new ValuesMapDialog("Enter Directory Transform", null, valueMap);
		tool.showDialog(mapDialog, this);
		GValuesMap results = mapDialog.getValues();
		if (results == null) {
			return;
		}
		SourcePathTransformer pathTransformer =
			UserDataPathTransformer.getPathTransformer(sourceFilesTableModel.getProgram());
		String source = results.getChoice(SOURCE);
		try {
			String canonical = results.getFile(DESTINATION).getCanonicalPath();
			URI uri = new File(canonical).toURI().normalize();
			String transformedPath = uri.getPath();
			if (!transformedPath.endsWith("/")) {
				transformedPath = transformedPath + "/";
			}
			pathTransformer.addDirectoryTransform(source, transformedPath);
		}
		catch (IOException e) {
			Msg.showError(this, sourceFilesTable, "IOException getting canonical path",
				e.getMessage());
		}

		sourceFilesTableModel.refresh();
		transformsModel.reload();
	}

	private void transformSourceFileAction(SourceFilesTableActionContext actionContext) {
		SourceFile sourceFile = sourceFilesTable.getSelectedRowObject().getSourceFile();
		transformSourceFile(sourceFile);
	}

	private void transformSourceFile(SourceFile sourceFile) {
		SourcePathTransformer pathTransformer =
			UserDataPathTransformer.getPathTransformer(sourceFilesTableModel.getProgram());
		String existing = pathTransformer.getTransformedPath(sourceFile, true);
		GValuesMap valueMap = new GValuesMap();
		valueMap.defineFile(DESTINATION, new File(existing));
		valueMap.setValidator((map, status) -> {
			File targetFile = valueMap.getFile(DESTINATION);
			if (targetFile == null || !targetFile.exists()) {
				status.setStatusText("File does not exist", MessageType.ERROR);
				return false;
			}
			if (targetFile.isDirectory()) {
				status.setStatusText("Must specify a file", MessageType.ERROR);
				return false;
			}
			return true;
		});
		ValuesMapDialog mapDialog = new ValuesMapDialog("Enter File Tranform",
			"Transform for " + sourceFile.toString(), valueMap);
		tool.showDialog(mapDialog, this);
		GValuesMap results = mapDialog.getValues();
		if (results == null) {
			return;
		}

		try {
			String path = results.getFile(DESTINATION).getCanonicalPath();
			URI uri = new File(path).toURI().normalize();
			pathTransformer.addFileTransform(sourceFile, uri.getPath());
		}
		catch (IOException e) {
			Msg.showError(this, sourceFilesTable, "IOException getting canonical path",
				e.getMessage());
		}

		sourceFilesTableModel.refresh();
		transformsModel.reload();
	}

	private void showSourceMapEntries(SourceFilesTableActionContext actionContext) {
		TableService tableService = sourceFilesTablePlugin.getTool().getService(TableService.class);
		if (tableService == null) {
			Msg.showWarn(this, null, "No Table Service", "Please add the TableServicePlugin.");
			return;
		}
		SourceFileRowObject sourceFileRow = sourceFilesTable.getSelectedRowObject();
		Icon markerIcon = new GIcon("icon.plugin.codebrowser.cursor.marker");
		SourceFile sourceFile = sourceFileRow.getSourceFile();
		String title = "Source Map Entries for " + sourceFile.getFilename();
		SourceMapEntryTableModel tableModel =
			new SourceMapEntryTableModel(sourceFilesTablePlugin.getTool(),
				sourceFilesTablePlugin.getCurrentProgram(), TaskMonitor.DUMMY, sourceFile);
		TableComponentProvider<SourceMapEntryRowObject> provider =
			tableService.showTableWithMarkers(title, "SourceMapEntries", tableModel,
				SearchConstants.SEARCH_HIGHLIGHT_COLOR, markerIcon, title, null);
		provider.setTabText(sourceFile.getFilename());
		provider.setHelpLocation(
			new HelpLocation(sourceFilesTablePlugin.getName(), "Show_Source_Map_Entries"));
	}

	private void viewSourceFile(SourceFilesTableActionContext actionContext) {
		TableService tableService = sourceFilesTablePlugin.getTool().getService(TableService.class);
		if (tableService == null) {
			Msg.showWarn(this, null, "No Table Service", "Please add the TableServicePlugin.");
			return;
		}
		SourceFileRowObject sourceFileRow = sourceFilesTable.getSelectedRowObject();
		SourceFile sourceFile = sourceFileRow.getSourceFile();
		sourceFilesTablePlugin.openInViewer(sourceFile, 1);
	}

	private class SourceFilesTableActionContext extends DefaultActionContext {

		SourceFilesTableActionContext() {
			super(SourceFilesTableProvider.this);
		}

		public int getSelectedRowCount() {
			return sourceFilesTable.getTable().getSelectedRowCount();
		}
	}

	private class TransformTableActionContext extends DefaultActionContext {

		TransformTableActionContext() {
			super(SourceFilesTableProvider.this);
		}

		public int getSelectedRowCount() {
			return transformsTable.getTable().getSelectedRowCount();
		}
	}

}
