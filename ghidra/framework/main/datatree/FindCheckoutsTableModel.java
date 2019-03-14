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
/**
 * 
 */
package ghidra.framework.main.datatree;

import java.io.IOException;
import java.util.Date;

import docking.widgets.table.AbstractDynamicTableColumnStub;
import docking.widgets.table.TableColumnDescriptor;
import docking.widgets.table.threaded.ThreadedTableModelStub;
import ghidra.docking.settings.Settings;
import ghidra.framework.client.NotConnectedException;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.util.Msg;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Table model for find checkouts for the user logged in.
 */
class FindCheckoutsTableModel extends ThreadedTableModelStub<CheckoutInfo> {

	public static final String CHECKOUT_DATE = "Checkout Date";

	private DomainFolder parent;
	private ProjectData projectData;
	DomainFolderChangeListener folderListener;

	private String failedStatusMessage = null;

	public FindCheckoutsTableModel(DomainFolder parent, PluginTool pluginTool) {
		super("Find Checkouts", pluginTool);
		this.parent = parent;

		folderListener = new DomainFolderListenerAdapter() {
			@Override
			public void domainFileStatusChanged(DomainFile file, boolean fileIDset) {
				reload();
			}
		};
		projectData = parent.getProjectData();
		projectData.addDomainFolderChangeListener(folderListener);
	}

	@Override
	public void dispose() {
		super.dispose();
		projectData.removeDomainFolderChangeListener(folderListener);
		projectData = null;
	}

	@Override
	protected void doLoad(Accumulator<CheckoutInfo> accumulator, TaskMonitor monitor)
			throws CancelledException {
		failedStatusMessage = null;
		try {
			findCheckouts(parent, accumulator, monitor);
		}
		catch (CancelledException e) {
			// don't care
		}
		catch (IOException e) {
			throw new RuntimeException("Failed to get check out status");
		}
	}

	String getFailedStatusMessage() {
		return failedStatusMessage;
	}

	DomainFile getDomainFile(int row) {
		CheckoutInfo info = filteredData.get(row);
		return info.getFile();
	}

	private void findCheckouts(DomainFolder parentFolder, Accumulator<CheckoutInfo> accumulator,
			TaskMonitor monitor) throws IOException, CancelledException {

		DomainFile[] files = parentFolder.getFiles();
		for (DomainFile file : files) {
			if (monitor.isCancelled()) {
				throw new CancelledException();
			}
			if (file.isCheckedOut()) {
				try {
					CheckoutInfo info = new CheckoutInfo(file);
					accumulator.add(info);
				}
				catch (NotConnectedException nce) {
					failedStatusMessage = nce.getMessage();
					return;
				}
				catch (IOException e) {
					Msg.showError(this, null, "Error Getting Checkout Info",
						"Failed to get checkout information for\n" + file.getName(), e);
					throw e;
				}
			}
		}
		DomainFolder[] folders = parentFolder.getFolders();
		for (DomainFolder folder : folders) {
			if (monitor.isCancelled()) {
				throw new CancelledException();
			}
			findCheckouts(folder, accumulator, monitor);
		}
	}

	@Override
	protected TableColumnDescriptor<CheckoutInfo> createTableColumnDescriptor() {
		TableColumnDescriptor<CheckoutInfo> descriptor = new TableColumnDescriptor<CheckoutInfo>();

		descriptor.addVisibleColumn(new NameTableColumn());
		descriptor.addVisibleColumn(new PathTableColumn());
		descriptor.addVisibleColumn(new CheckoutDateTableColumn());
		descriptor.addVisibleColumn(new VersionTableColumn());

		return descriptor;
	}

//==================================================================================================
// Inner Classes
//==================================================================================================	

	private class NameTableColumn extends AbstractDynamicTableColumnStub<CheckoutInfo, String> {

		@Override
		public String getColumnName() {
			return "Name";
		}

		@Override
		public String getValue(CheckoutInfo rowObject, Settings settings, ServiceProvider sp)
				throws IllegalArgumentException {
			return rowObject.getFile().getName();
		}

		@Override
		public int getColumnPreferredWidth() {
			return 150;
		}
	}

	private class PathTableColumn extends AbstractDynamicTableColumnStub<CheckoutInfo, String> {

		@Override
		public String getColumnName() {
			return "Pathname";
		}

		@Override
		public String getValue(CheckoutInfo rowObject, Settings settings, ServiceProvider sp)
				throws IllegalArgumentException {
			return rowObject.getFile().getParent().getPathname();
		}

		@Override
		public int getColumnPreferredWidth() {
			return 100;
		}
	}

	private class CheckoutDateTableColumn
			extends AbstractDynamicTableColumnStub<CheckoutInfo, Date> {

		@Override
		public String getColumnName() {
			return CHECKOUT_DATE;
		}

		@Override
		public Date getValue(CheckoutInfo rowObject, Settings settings, ServiceProvider sp)
				throws IllegalArgumentException {
			return new Date(rowObject.getStatus().getCheckoutTime());
		}

		@Override
		public int getColumnPreferredWidth() {
			return 150;
		}
	}

	private class VersionTableColumn extends AbstractDynamicTableColumnStub<CheckoutInfo, Integer> {

		@Override
		public String getColumnName() {
			return "Version";
		}

		@Override
		public Integer getValue(CheckoutInfo rowObject, Settings settings, ServiceProvider sp)
				throws IllegalArgumentException {
			return rowObject.getStatus().getCheckoutVersion();
		}

		@Override
		public int getColumnPreferredWidth() {
			return 70;
		}
	}
}
