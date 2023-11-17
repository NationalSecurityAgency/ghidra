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
package ghidra.features.bsim.gui.search.dialog;

import java.awt.Component;
import java.util.ArrayList;
import java.util.List;

import javax.swing.JLabel;

import docking.widgets.table.*;
import ghidra.docking.settings.Settings;
import ghidra.features.bsim.query.BSimServerInfo;
import ghidra.features.bsim.query.BSimServerInfo.DBType;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.framework.plugintool.ServiceProviderStub;
import ghidra.program.model.listing.Program;
import ghidra.util.table.column.AbstractGColumnRenderer;
import ghidra.util.table.column.GColumnRenderer;
import ghidra.util.table.field.AbstractProgramBasedDynamicTableColumn;

/**
 * Table model for BSim database server definitions
 */
public class BSimServerTableModel extends GDynamicColumnTableModel<BSimServerInfo, Object> {
	private List<BSimServerInfo> servers;
	private BSimServerManager serverManager;
	private BSimServerManagerListener listener = new BSimServerManagerListener() {
		@Override
		public void serverListChanged() {
			updateServers();
		}
	};

	public BSimServerTableModel(BSimServerManager serverManager) {
		super(new ServiceProviderStub());
		this.serverManager = serverManager;
		serverManager.addListener(listener);
		servers = new ArrayList<>(serverManager.getServerInfos());
	}

	@Override
	public String getName() {
		return "BSim Servers";
	}

	@Override
	public List<BSimServerInfo> getModelData() {
		return servers;
	}

	@Override
	public boolean isSortable(int columnIndex) {
		return columnIndex != 0;
	}

	@Override
	protected TableColumnDescriptor<BSimServerInfo> createTableColumnDescriptor() {
		TableColumnDescriptor<BSimServerInfo> descriptor = new TableColumnDescriptor<>();
		descriptor.addVisibleColumn(new DatabaseNameColumn(), 1, true);
		descriptor.addVisibleColumn(new TypeColumn());
		descriptor.addVisibleColumn(new HostColumn());
		descriptor.addVisibleColumn(new PortColumn());
		descriptor.addVisibleColumn(new ActiveConnectionColumn());
		return descriptor;
	}

	@Override
	public Object getDataSource() {
		return null;
	}

	private class DatabaseNameColumn
		extends AbstractProgramBasedDynamicTableColumn<BSimServerInfo, String> {
		private GColumnRenderer<String> renderer = new AbstractGColumnRenderer<>() {
			@Override
			public Component getTableCellRendererComponent(GTableCellRenderingData data) {
				JLabel label = (JLabel) super.getTableCellRendererComponent(data);
				BSimServerInfo info = (BSimServerInfo) data.getRowObject();
				if (info.getDBType() == DBType.file) {
					label.setToolTipText(info.getDBName());
				}
				else {
					label.setToolTipText("");
				}
				return label;
			}

			@Override
			public String getFilterString(String value, Settings settings) {
				return value;
			}

		};

		@Override
		public String getColumnName() {
			return "Name";
		}

		@Override
		public String getValue(BSimServerInfo serverInfo, Settings settings, Program data,
			ServiceProvider provider) throws IllegalArgumentException {

			// FIXME: Get cell tooltip to show full getDBName which includes file path

			return serverInfo.getShortDBName();
		}

		@Override
		public int getColumnPreferredWidth() {
			return 200;
		}

		@Override
		public GColumnRenderer<String> getColumnRenderer() {
			return renderer;
		}
	}

	private class HostColumn
		extends AbstractProgramBasedDynamicTableColumn<BSimServerInfo, String> {

		@Override
		public String getColumnName() {
			return "Host";
		}

		@Override
		public String getValue(BSimServerInfo serverInfo, Settings settings, Program data,
			ServiceProvider provider) throws IllegalArgumentException {

			return serverInfo.getServerName();
		}

		@Override
		public int getColumnPreferredWidth() {
			return 150;
		}
	}

	private class PortColumn
		extends AbstractProgramBasedDynamicTableColumn<BSimServerInfo, Integer> {

		@Override
		public String getColumnName() {
			return "Port";
		}

		@Override
		public Integer getValue(BSimServerInfo serverInfo, Settings settings, Program data,
			ServiceProvider provider) throws IllegalArgumentException {

			int port = serverInfo.getPort();
			if (port <= 0) {
				return null;
			}
			return port;
		}

		@Override
		public int getColumnPreferredWidth() {
			return 80;
		}
	}

	private class ActiveConnectionColumn
		extends AbstractProgramBasedDynamicTableColumn<BSimServerInfo, Integer> {

		@Override
		public String getColumnName() {
			return "Active Connections";
		}

		@Override
		public Integer getValue(BSimServerInfo serverInfo, Settings settings, Program data,
			ServiceProvider provider) throws IllegalArgumentException {
			int activeConnections = BSimServerManager.getActiveConnections(serverInfo);
			if (activeConnections < 0) {
				return null;
			}
			return activeConnections;
		}

		@Override
		public int getColumnPreferredWidth() {
			return 80;
		}
	}

	private class TypeColumn
		extends AbstractProgramBasedDynamicTableColumn<BSimServerInfo, String> {

		@Override
		public String getColumnName() {
			return "Type";
		}

		@Override
		public String getValue(BSimServerInfo serverInfo, Settings settings, Program data,
			ServiceProvider provider) throws IllegalArgumentException {

			return serverInfo.getDBType().toString();
		}

		@Override
		public int getColumnPreferredWidth() {
			return 80;
		}
	}

	private void updateServers() {
		servers = new ArrayList<>(serverManager.getServerInfos());
		fireTableDataChanged();
	}

	@Override
	public void dispose() {
		serverManager.removeListener(listener);
		super.dispose();
	}
}
