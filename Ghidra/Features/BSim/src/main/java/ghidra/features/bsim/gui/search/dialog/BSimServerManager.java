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

import java.io.File;
import java.io.IOException;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;

import ghidra.features.bsim.query.BSimPostgresDBConnectionManager;
import ghidra.features.bsim.query.BSimPostgresDBConnectionManager.BSimPostgresDataSource;
import ghidra.features.bsim.query.BSimServerInfo;
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
	// TODO: Do not allow removal of active server.  Dispose data source when removed.

	private Set<BSimServerInfo> serverInfos = new HashSet<>();
	private List<BSimServerManagerListener> listeners = new CopyOnWriteArrayList<>();

	public BSimServerManager() {
		List<File> files = Application.getUserSettingsFiles("bsim", ".server.properties");
		for (File file : files) {
			BSimServerInfo info = readBsimServerInfoFile(file);
			if (info != null) {
				serverInfos.add(info);
			}
		}
	}

	public Set<BSimServerInfo> getServerInfos() {
		return new HashSet<>(serverInfos);
	}

	private BSimServerInfo readBsimServerInfoFile(File file) {
		try {
			GProperties properties = new JSonProperties(file);
			String dbTypeName = properties.getString("DBType", null);
			DBType dbType = DBType.valueOf(dbTypeName);
			String name = properties.getString("Name", null);
			String host = properties.getString("Host", null);
			int port = properties.getInt("Port", 0);
			if (dbType != null && name != null) {
				BSimServerInfo info = new BSimServerInfo(dbType, host, port, name);
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

	public void addServer(BSimServerInfo newServerInfo) {
		if (saveBSimServerInfo(newServerInfo)) {
			serverInfos.add(newServerInfo);
			notifyServerListChanged();
		}
	}

	public boolean removeServer(BSimServerInfo info, boolean force) {
		DBType dbType = info.getDBType();
		if (dbType == DBType.file) {
			BSimH2FileDataSource ds = BSimH2FileDBConnectionManager.getDataSource(info);
			int active = ds.getActiveConnections();
			if (active != 0) {
				if (!force) {
					return false;
				}
				ds.dispose();
			}
		}
		else if (dbType == DBType.postgres) {
			BSimPostgresDataSource ds = BSimPostgresDBConnectionManager.getDataSource(info);
			int active = ds.getActiveConnections();
			if (active != 0) {
				if (!force) {
					return false;
				}
				ds.dispose();
			}
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

	public static int getActiveConnections(BSimServerInfo serverInfo) {
		switch (serverInfo.getDBType()) {
			case postgres:
				BSimPostgresDataSource postgresDs =
					BSimPostgresDBConnectionManager.getDataSourceIfExists(serverInfo);
				if (postgresDs != null) {
					return postgresDs.getActiveConnections();
				}
				break;
			case file:
				BSimH2FileDataSource h2FileDs =
					BSimH2FileDBConnectionManager.getDataSourceIfExists(serverInfo);
				if (h2FileDs != null) {
					return h2FileDs.getActiveConnections();
				}
				break;
			default:
				break;
		}
		return -1;
	}

}
