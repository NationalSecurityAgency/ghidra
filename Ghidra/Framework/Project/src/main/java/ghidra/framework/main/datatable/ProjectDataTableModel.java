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

import java.io.IOException;
import java.util.*;

import docking.widgets.table.*;
import docking.widgets.table.threaded.ThreadedTableModel;
import ghidra.docking.settings.Settings;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.util.InvalidNameException;
import ghidra.util.Msg;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateFileException;
import ghidra.util.task.TaskMonitor;

public class ProjectDataTableModel extends ThreadedTableModel<DomainFileInfo, ProjectData> {

	private ProjectData projectData;
	private boolean editingOn;

	private boolean loadWasCancelled;

	protected ProjectDataTableModel(ServiceProvider serviceProvider) {
		super("Project Data Table", serviceProvider);
	}

	boolean loadWasCancelled() {
		return loadWasCancelled;
	}

	@Override
	protected void doLoad(Accumulator<DomainFileInfo> accumulator, TaskMonitor monitor)
			throws CancelledException {
		loadWasCancelled = false;
		if (projectData != null) {
			loadWasCancelled = true;
			DomainFolder rootFolder = projectData.getRootFolder();
			addFiles(accumulator, rootFolder, monitor);
			loadWasCancelled = false;
		}
	}

	private void addFiles(Accumulator<DomainFileInfo> accumulator, DomainFolder folder,
			TaskMonitor monitor) throws CancelledException {
		DomainFile[] files = folder.getFiles();
		for (DomainFile domainFile : files) {
			monitor.checkCanceled();
			accumulator.add(new DomainFileInfo(domainFile));
		}
		DomainFolder[] folders = folder.getFolders();
		for (DomainFolder domainFolder : folders) {
			monitor.checkCanceled();
			addFiles(accumulator, domainFolder, monitor);
		}
	}

	@Override
	protected TableColumnDescriptor<DomainFileInfo> createTableColumnDescriptor() {
		TableColumnDescriptor<DomainFileInfo> descriptor = new TableColumnDescriptor<>();

		descriptor.addVisibleColumn(new DomainFileTypeColumn());
		descriptor.addVisibleColumn(new DomainFileNameColumn());
		descriptor.addVisibleColumn(new DomainFilePathColumn());
		descriptor.addVisibleColumn(new ModificationDateColumn());

		List<ProjectDataColumn<?>> appSpecificColumns = findAppSpecificColumns();
		for (ProjectDataColumn<?> projectDataColumn : appSpecificColumns) {
			if (projectDataColumn.isDefaultColumn()) {
				descriptor.addVisibleColumn(projectDataColumn);
			}
			else {
				descriptor.addHiddenColumn(projectDataColumn);
			}
		}

		return descriptor;
	}

	@SuppressWarnings("rawtypes")
	private List<ProjectDataColumn<?>> findAppSpecificColumns() {
		List<ProjectDataColumn> instances = ClassSearcher.getInstances(ProjectDataColumn.class);
		List<ProjectDataColumn<?>> columns = new ArrayList<>();

		for (ProjectDataColumn projectDataColumn : instances) {
			columns.add(projectDataColumn);
		}
		Collections.sort(columns);
		return columns;
	}

	@Override
	public ProjectData getDataSource() {
		return projectData;
	}

	@Override
	public void refresh() {
		List<DomainFileInfo> modelData = getModelData();
		for (DomainFileInfo domainFileInfo : modelData) {
			domainFileInfo.refresh();
		}
		super.refresh();
	}

	public void setProjectData(ProjectData projectData) {
		this.projectData = projectData;
		reload();
	}

	@Override
	public boolean isCellEditable(int rowIndex, int columnIndex) {
		if (editingOn) {
			DynamicTableColumn<DomainFileInfo, ?, ?> column = getColumn(columnIndex);
			return column instanceof DomainFileNameColumn;
		}
		return false;
	}

	@Override
	public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
		DomainFileInfo info = getRowObject(rowIndex);
		try {
			String newName = aValue.toString();
			DomainFile domainFile = info.getDomainFile();
			if (!domainFile.getName().equals(newName)) {
				domainFile.setName(newName);
			}
		}
		catch (InvalidNameException | DuplicateFileException e) {
			Msg.showError(this, null, "Rename Failed", "Invalid name: " + e.getMessage());
		}
		catch (IOException e) {
			Msg.showError(this, null, "Rename Failed",
				"There was a problem renaming the file:\n" + e.getMessage(), e);
		}
	}

	public void setEditing(boolean on) {
		editingOn = on;
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private class DomainFileTypeColumn
	extends AbstractDynamicTableColumn<DomainFileInfo, DomainFileType, ProjectData> {

		@Override
		public String getColumnName() {
			return "Type";
		}

		@Override
		public DomainFileType getValue(DomainFileInfo rowObject, Settings settings,
				ProjectData data, ServiceProvider services) throws IllegalArgumentException {
			return rowObject.getDomainFileType();
		}

		@Override
		public int getColumnPreferredWidth() {
			return 25;
		}
	}

	private class DomainFileNameColumn
	extends AbstractDynamicTableColumn<DomainFileInfo, String, ProjectData> {

		@Override
		public String getColumnName() {
			return "Name";
		}

		@Override
		public String getValue(DomainFileInfo info, Settings settings, ProjectData data,
				ServiceProvider services) throws IllegalArgumentException {

			return info.getDisplayName();
		}

		@Override
		public int getColumnPreferredWidth() {
			return 200;
		}
	}

	private class ModificationDateColumn
	extends AbstractDynamicTableColumn<DomainFileInfo, Date, ProjectData> {

		@Override
		public String getColumnName() {
			return "Modified";
		}

		@Override
		public Date getValue(DomainFileInfo info, Settings settings, ProjectData data,
				ServiceProvider services) throws IllegalArgumentException {

			return info.getModificationDate();
		}

		@Override
		public int getColumnPreferredWidth() {
			return 200;
		}
	}

	private class DomainFilePathColumn
	extends AbstractDynamicTableColumn<DomainFileInfo, String, ProjectData> {

		@Override
		public String getColumnName() {
			return "Path";
		}

		@Override
		public String getValue(DomainFileInfo info, Settings settings, ProjectData data,
				ServiceProvider services) throws IllegalArgumentException {

			return info.getPath();
		}

		@Override
		public int getColumnPreferredWidth() {
			return 200;
		}

	}

}
