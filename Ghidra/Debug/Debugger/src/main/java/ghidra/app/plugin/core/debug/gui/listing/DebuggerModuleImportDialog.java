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
package ghidra.app.plugin.core.debug.gui.listing;

import java.awt.BorderLayout;
import java.io.File;
import java.util.*;
import java.util.function.BiConsumer;
import java.util.function.Function;

import javax.swing.*;
import javax.swing.table.TableColumn;
import javax.swing.table.TableColumnModel;

import docking.DialogComponentProvider;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.table.CellEditorUtils;
import docking.widgets.table.DefaultEnumeratedColumnTableModel;
import docking.widgets.table.DefaultEnumeratedColumnTableModel.EnumeratedTableColumn;
import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.app.services.FileImporterService;
import ghidra.framework.main.AppInfo;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.Project;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.MessageType;
import ghidra.util.table.GhidraTable;
import ghidra.util.table.GhidraTableFilterPanel;

public class DebuggerModuleImportDialog extends DialogComponentProvider {
	static final String BLANK = "";
	static final int BUTTON_SIZE = 32;

	protected static class FileRow {
		private final File file;
		private boolean isIgnored;

		public FileRow(File file) {
			this.file = file;
		}

		public File getFile() {
			return file;
		}

		public boolean isIgnored() {
			return isIgnored;
		}

		public void setIgnored(boolean isIgnored) {
			this.isIgnored = isIgnored;
		}
	}

	protected static enum FileTableColumns
		implements EnumeratedTableColumn<FileTableColumns, FileRow> {
		REMOVE("Remove", String.class, m -> BLANK, (m, v) -> nop()),
		IGNORE("Ignore", Boolean.class, FileRow::isIgnored, FileRow::setIgnored),
		PATH("Path", File.class, FileRow::getFile),
		IMPORT("Import", String.class, m -> BLANK, (m, v) -> nop());

		private String header;
		private Class<?> cls;
		private Function<FileRow, ?> getter;
		private BiConsumer<FileRow, Object> setter;

		private static void nop() {
		}

		@SuppressWarnings("unchecked")
		<T> FileTableColumns(String header, Class<T> cls,
				Function<FileRow, T> getter, BiConsumer<FileRow, T> setter) {
			this.header = header;
			this.cls = cls;
			this.getter = getter;
			this.setter = (BiConsumer<FileRow, Object>) setter;
		}

		<T> FileTableColumns(String header, Class<T> cls,
				Function<FileRow, T> getter) {
			this(header, cls, getter, null);
		}

		@Override
		public String getHeader() {
			return header;
		}

		@Override
		public Class<?> getValueClass() {
			return cls;
		}

		@Override
		public Object getValueOf(FileRow row) {
			return getter.apply(row);
		}

		@Override
		public boolean isEditable(FileRow row) {
			return setter != null;
		}

		@Override
		public void setValueOf(FileRow row, Object value) {
			setter.accept(row, value);
		}
	}

	protected static class FileTableModel
			extends DefaultEnumeratedColumnTableModel<FileTableColumns, FileRow> {
		public FileTableModel() {
			super("Suggested Files to Import", FileTableColumns.class);
		}
	}

	private final PluginTool tool;

	final FileTableModel fileTableModel = new FileTableModel();
	private final Map<File, FileRow> map = new HashMap<>();

	private GhidraTable fileTable;
	private GhidraTableFilterPanel<FileRow> fileFilterPanel;

	protected DebuggerModuleImportDialog(PluginTool tool) {
		super("Suggested Modules to Import", false, true, false, false);
		this.tool = tool;

		populateComponents();
	}

	protected void populateComponents() {
		JPanel panel = new JPanel(new BorderLayout());

		fileTable = new GhidraTable(fileTableModel);
		fileTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		panel.add(new JScrollPane(fileTable));

		fileFilterPanel = new GhidraTableFilterPanel<>(fileTable, fileTableModel);
		panel.add(fileFilterPanel, BorderLayout.SOUTH);

		TableColumnModel columnModel = fileTable.getColumnModel();

		TableColumn removeCol = columnModel.getColumn(FileTableColumns.REMOVE.ordinal());
		CellEditorUtils.installButton(fileTable, fileFilterPanel, removeCol,
			DebuggerResources.ICON_DELETE, BUTTON_SIZE, this::removeFile);

		TableColumn ignoreCol = columnModel.getColumn(FileTableColumns.IGNORE.ordinal());
		ignoreCol.setPreferredWidth(30);

		TableColumn importCol = columnModel.getColumn(FileTableColumns.IMPORT.ordinal());
		CellEditorUtils.installButton(fileTable, fileFilterPanel, importCol,
			DebuggerResources.ICON_IMPORT, BUTTON_SIZE, this::importFile);

		addWorkPanel(panel);
	}

	private void importFile(FileRow mod) {
		FileImporterService importerService = tool.getService(FileImporterService.class);
		if (importerService == null) {
			setStatusText("No FileImporterService!", MessageType.ERROR);
			return;
		}
		GhidraFileChooser chooser = new GhidraFileChooser(getComponent());
		chooser.setSelectedFile(mod.getFile());
		File file = chooser.getSelectedFile(); // Shows modal
		if (file == null) { // Includes cancelled case
			return;
		}
		Project activeProject = Objects.requireNonNull(AppInfo.getActiveProject());
		DomainFolder root = activeProject.getProjectData().getRootFolder();
		importerService.importFile(root, file);
		removeFile(mod);
	}

	private void removeFile(FileRow mod) {
		removeFiles(Set.of(mod.getFile()));
	}

	public void show() {
		tool.showDialog(this);
	}

	/**
	 * Suggest files to import.
	 * 
	 * <p>
	 * If this causes a change to the suggested file list, or the list is not currently showing, the
	 * dialog will be shown. The user may leave the list in the background to avoid being pestered
	 * again.
	 * 
	 * @param files the collection of files to suggest importing
	 */
	public void addFiles(Collection<File> files) {
		synchronized (map) {
			List<FileRow> mods = new ArrayList<>();
			for (File file : files) {
				map.computeIfAbsent(file, f -> {
					FileRow mod = new FileRow(f);
					mods.add(mod);
					return mod;
				});
			}
			fileTableModel.addAll(mods);
			// Do not steal focus if suggested files are already on screen, or ignored
			boolean anyNotIgnored =
				fileTableModel.getModelData().stream().anyMatch(r -> !r.isIgnored());
			if (!mods.isEmpty() || (!isShowing() && anyNotIgnored)) {
				show();
			}
		}
	}

	/**
	 * Remove suggested files from the dialog.
	 * 
	 * <p>
	 * If this causes the list to become empty, the dialog is automatically hidden.
	 * 
	 * @param files the collection of files to no longer suggest
	 */
	public void removeFiles(Collection<File> files) {
		synchronized (map) {
			Set<FileRow> mods = new HashSet<>();
			for (File file : files) {
				FileRow mod = map.remove(file);
				if (mod != null) {
					mods.add(mod);
				}
			}
			fileTableModel.deleteWith(mods::contains);

			if (fileTableModel.getModelData().isEmpty()) {
				close();
			}
		}
	}
}
