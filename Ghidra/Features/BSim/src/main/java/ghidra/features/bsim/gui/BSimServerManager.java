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
package ghidra.features.bsim.gui;

import java.io.File;
import java.io.IOException;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;

import ghidra.features.bsim.gui.search.dialog.BSimServerManagerListener;
import ghidra.features.bsim.query.*;
import ghidra.features.bsim.query.BSimPostgresDBConnectionManager.BSimPostgresDataSource;
import ghidra.features.bsim.query.BSimServerInfo.DBType;
import ghidra.features.bsim.query.file.BSimH2FileDBConnectionManager;
import ghidra.features.bsim.query.file.BSimH2FileDBConnectionManager.BSimH2FileDataSource;
import ghidra.framework.Application;
import ghidra.framework.options.GProperties;
import ghidra.framework.options.JSonProperties;
import ghidra.util.Msg;
import ghidra.util.Swing;

/**
 * Managers BSim database server definitions and connections
 */
public class BSimServerManager {

	private static BSimServerManager instance;

	/**
	 * Get static singleton instance for BSimServerManager
	 * @return BSimServerManager instance
	 */
	static synchronized BSimServerManager getBSimServerManager() {
		if (instance == null) {
			instance = new BSimServerManager();
		}
		return instance;
	}

	private Set<BSimServerInfo> serverInfos = new HashSet<>();
	private List<BSimServerManagerListener> listeners = new CopyOnWriteArrayList<>();

	private BSimServerManager() {
		List<File> files = Application.getUserSettingsFiles("bsim", ".server.properties");
		for (File file : files) {
			BSimServerInfo info = readBsimServerInfoFile(file);
			if (info != null) {
				serverInfos.add(info);
			}
		}
	}

	/**
	 * Get list of defined servers.  Method must be invoked from swing thread only.
	 * @return list of defined servers
	 */
	public Set<BSimServerInfo> getServerInfos() {
		return new HashSet<>(serverInfos);
	}

	private BSimServerInfo readBsimServerInfoFile(File file) {
		try {
			GProperties properties = new JSonProperties(file);
			String dbTypeName = properties.getString("DBType", null);
			DBType dbType = DBType.valueOf(dbTypeName);
			String name = properties.getString("Name", null);
			String user = properties.getString("User", null);
			String host = properties.getString("Host", null);
			int port = properties.getInt("Port", 0);
			if (dbType != null && name != null) {
				BSimServerInfo info = new BSimServerInfo(dbType, user, host, port, name);
				return info;
			}
			Msg.showError(this, null, "Error reading Bsim Server File",
				"Bad BSim Server Info in file " + file.toString());
		}
		catch (IOException e) {
			Msg.showError(this, null, "Error Reading BSim Server File",
				"Error processing Bsim Server info file: " + file.toString());
		}
		return null;
	}

	private boolean saveBSimServerInfo(BSimServerInfo info) {
		GProperties properties = new GProperties("BSimServerInfo");
		properties.putString("DBType", info.getDBType().name());
		properties.putString("Name", info.getDBName());
		if (!info.hasDefaultLogin()) {
			// save specified username - but not password
			properties.putString("User", info.getUserName());
		}
		properties.putString("Host", info.getServerName());
		properties.putInt("Port", info.getPort());

		File settingsDir = Application.getUserSettingsDirectory();
		File serversDir = new File(settingsDir, "bsim");
		int hash = info.hashCode();
		File serverFile = new File(serversDir, "bsim" + hash + ".server.properties");
		try {
			properties.saveToJsonFile(serverFile);
			return true;
		}
		catch (IOException e) {
			Msg.showError(this, null, "Error Saving",
				"Error saving Bsim Server Info to file " + serverFile.getAbsolutePath(), e);
			return false;
		}

	}

	private boolean removeServerFileFromSettings(BSimServerInfo info) {
		File settingsDir = Application.getUserSettingsDirectory();
		File serversDir = new File(settingsDir, "bsim");
		int hash = info.hashCode();
		File serverFile = new File(serversDir, "bsim" + hash + ".server.properties");
		return serverFile.delete();
	}

	/**
	 * Add server to list.  Method must be invoked from swing thread only.
	 * @param newServerInfo new BSim DB server
	 */
	public void addServer(BSimServerInfo newServerInfo) {
		if (saveBSimServerInfo(newServerInfo)) {
			serverInfos.add(newServerInfo);
			notifyServerListChanged();
		}
	}

	private static boolean disposeServer(BSimServerInfo info, boolean force) {
		DBType dbType = info.getDBType();
		if (dbType == DBType.file) {
			BSimH2FileDataSource ds = BSimH2FileDBConnectionManager.getDataSourceIfExists(info);
			if (ds != null) {
				int active = ds.getActiveConnections();
				if (active != 0 && !force) {
					return false;
				}
				ds.dispose();
			}
		}
		else if (dbType == DBType.postgres) {
			BSimPostgresDataSource ds = BSimPostgresDBConnectionManager.getDataSourceIfExists(info);
			if (ds != null) {
				int active = ds.getActiveConnections();
				if (active != 0 && !force) {
					return false;
				}
				ds.dispose();
			}
		}
		return true;
	}

	/**
	 * Remove BSim DB server from list.  Method must be invoked from swing thread only.
	 * Specified server datasource will be dispose unless it is active or force is true.
	 * @param info BSim DB server to be removed
	 * @param force true if server datasource should be disposed even when active.
	 * @return true if server disposed and removed from list
	 */
	public boolean removeServer(BSimServerInfo info, boolean force) {
		if (!disposeServer(info, force)) {
			return false;
		}
		if (serverInfos.remove(info)) {
			removeServerFileFromSettings(info);
			notifyServerListChanged();
		}
		return true;
	}

	public void addListener(BSimServerManagerListener listener) {
		listeners.add(listener);
	}

	public void removeListener(BSimServerManagerListener listener) {
		listeners.remove(listener);
	}

	private void notifyServerListChanged() {
		Swing.runLater(() -> {
			for (BSimServerManagerListener listener : listeners) {
				listener.serverListChanged();
			}
		});
	}

	/**
	 * Convenience method to get existing BSim JDBC datasource
	 * @param serverInfo BSim DB server info
	 * @return BSim DB datasource or null if not instantiated or server does not support a
	 * {@link BSimJDBCDataSource}.
	 */
	public static BSimJDBCDataSource getDataSourceIfExists(BSimServerInfo serverInfo) {
		switch (serverInfo.getDBType()) {
			case postgres:
				return BSimPostgresDBConnectionManager.getDataSourceIfExists(serverInfo);
			case file:
				return BSimH2FileDBConnectionManager.getDataSourceIfExists(serverInfo);
			default:
				return null;
		}
	}

	/**
	 * Convenience method to get a new or existing BSim JDBC datasource
	 * @param serverInfo BSim DB server info
	 * @return BSim DB datasource or null if server does not support a
	 * {@link BSimJDBCDataSource}.
	 */
	public static BSimJDBCDataSource getDataSource(BSimServerInfo serverInfo) {
		switch (serverInfo.getDBType()) {
			case postgres:
				return BSimPostgresDBConnectionManager.getDataSource(serverInfo);
			case file:
				return BSimH2FileDBConnectionManager.getDataSource(serverInfo);
			default:
				return null;
		}
	}

}
