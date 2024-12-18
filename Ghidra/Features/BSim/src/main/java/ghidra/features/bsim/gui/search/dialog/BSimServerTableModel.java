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
import java.util.*;

import javax.swing.Icon;
import javax.swing.JLabel;

import org.apache.commons.lang3.StringUtils;

import docking.widgets.table.*;
import ghidra.docking.settings.Settings;
import ghidra.features.bsim.gui.BSimServerManager;
import ghidra.features.bsim.query.*;
import ghidra.features.bsim.query.BSimPostgresDBConnectionManager.BSimPostgresDataSource;
import ghidra.features.bsim.query.BSimServerInfo.DBType;
import ghidra.framework.client.ClientUtil;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.framework.plugintool.ServiceProviderStub;
import ghidra.util.table.column.AbstractGColumnRenderer;
import ghidra.util.table.column.GColumnRenderer;

/**
 * Table model for BSim database server definitions.
 * 
 * NOTE: This implementation assumes modal dialog use and non-changing connection state
 * while instance is in-use.  This was done to avoid adding a conection listener which could
 * introduce excessive overhead into the connection pool use.
 */
public class BSimServerTableModel extends GDynamicColumnTableModel<BSimServerInfo, Object> {

	private List<BSimServerInfo> servers;
	private Map<BSimServerInfo, ConnectionPoolStatus> statusCache = new HashMap<>();

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
	public void fireTableDataChanged() {
		statusCache.clear();
		super.fireTableDataChanged();
	}

	/**
	 * Get DB connection pool status for a specified server
	 * @param serverInfo server info
	 * @return connection pool status
	 */
	ConnectionPoolStatus getConnectionPoolStatus(BSimServerInfo serverInfo) {
		return statusCache.computeIfAbsent(serverInfo, s -> new ConnectionPoolStatus(s));
	}

	@Override
	protected TableColumnDescriptor<BSimServerInfo> createTableColumnDescriptor() {
		TableColumnDescriptor<BSimServerInfo> descriptor = new TableColumnDescriptor<>();
		descriptor.addVisibleColumn(new DatabaseNameColumn(), 1, true);
		descriptor.addVisibleColumn(new TypeColumn());
		descriptor.addVisibleColumn(new HostColumn());
		descriptor.addVisibleColumn(new PortColumn());
		descriptor.addVisibleColumn(new UserInfoColumn());
		descriptor.addVisibleColumn(new ConnectionStatusColumn());
		return descriptor;
	}

	@Override
	public Object getDataSource() {
		return null;
	}

	private class DatabaseNameColumn
			extends AbstractDynamicTableColumn<BSimServerInfo, String, Object> {
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
		public String getValue(BSimServerInfo serverInfo, Settings settings, Object data,
				ServiceProvider provider) throws IllegalArgumentException {
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

	private static class TypeColumn
			extends AbstractDynamicTableColumn<BSimServerInfo, String, Object> {

		@Override
		public String getColumnName() {
			return "Type";
		}

		@Override
		public String getValue(BSimServerInfo serverInfo, Settings settings, Object data,
				ServiceProvider provider) throws IllegalArgumentException {

			return serverInfo.getDBType().toString();
		}

		@Override
		public int getColumnPreferredWidth() {
			return 80;
		}
	}

	private static class UserInfoColumn
			extends AbstractDynamicTableColumn<BSimServerInfo, String, Object> {

		@Override
		public String getColumnName() {
			return "User";
		}

		@Override
		public String getValue(BSimServerInfo serverInfo, Settings settings, Object data,
				ServiceProvider provider) throws IllegalArgumentException {
			if (serverInfo.hasDefaultLogin()) {
				if (serverInfo.getDBType() == DBType.postgres) {
					BSimPostgresDataSource ds =
						BSimPostgresDBConnectionManager.getDataSourceIfExists(serverInfo);
					if (ds != null) {
						return ds.getUserName();
					}
				}
				// TODO: how can we determine elastic username?
				return "";
			}
			String info = serverInfo.getUserName();
			boolean hasPassword = serverInfo.hasPassword();
			if (hasPassword) {
				info = info + ":****"; // show w/masked password
			}
			return info;
		}

		@Override
		public int getColumnPreferredWidth() {
			return 100;
		}
	}

	private static class HostColumn
			extends AbstractDynamicTableColumn<BSimServerInfo, String, Object> {

		@Override
		public String getColumnName() {
			return "Host";
		}

		@Override
		public String getValue(BSimServerInfo serverInfo, Settings settings, Object data,
				ServiceProvider provider) throws IllegalArgumentException {
			return serverInfo.getServerName();
		}

		@Override
		public int getColumnPreferredWidth() {
			return 150;
		}
	}

	private static class PortColumn
			extends AbstractDynamicTableColumn<BSimServerInfo, String, Object> {

		@Override
		public String getColumnName() {
			return "Port";
		}

		@Override
		public String getValue(BSimServerInfo serverInfo, Settings settings, Object data,
				ServiceProvider provider) throws IllegalArgumentException {

			int port = serverInfo.getPort();
			if (port <= 0) {
				return null;
			}
			return Integer.toString(port);
		}

		@Override
		public int getColumnPreferredWidth() {
			return 60;
		}
	}

	private static class ConnectionStatusColumnRenderer
			extends AbstractGColumnRenderer<ConnectionPoolStatus> {

		private static final ConnectionStatusColumnRenderer INSTANCE =
			new ConnectionStatusColumnRenderer();

		@Override
		public Component getTableCellRendererComponent(GTableCellRenderingData data) {

			JLabel c = (JLabel) super.getTableCellRendererComponent(data);

			ConnectionPoolStatus status = (ConnectionPoolStatus) data.getValue();

			// NOTE: Custom column renderer has neem established with future use of
			// status icon in mind (e.g., H2 mixed-mode server enabled)

			Icon icon = null; // NOTE: may need default filler icon
			String text = null;
			if (status.isActive) {
				text = Integer.toString(status.activeCount) + " / " +
					Integer.toString(status.idleCount);
			}
			c.setText(text);
			c.setIcon(icon);
			return c;
		}

		@Override
		public String getFilterString(ConnectionPoolStatus t, Settings settings) {
			return null; // Filtering not supported
		}

	}

	private class ConnectionStatusColumn
			extends AbstractDynamicTableColumn<BSimServerInfo, ConnectionPoolStatus, Object> {

		@Override
		public String getColumnName() {
			return "Active/Idle Connections";
		}

		@Override
		public ConnectionPoolStatus getValue(BSimServerInfo serverInfo, Settings settings,
				Object data, ServiceProvider provider) throws IllegalArgumentException {
			return getConnectionPoolStatus(serverInfo);
		}

		@Override
		public int getColumnPreferredWidth() {
			return 150;
		}

		@Override
		public GColumnRenderer<ConnectionPoolStatus> getColumnRenderer() {
			return ConnectionStatusColumnRenderer.INSTANCE;
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
