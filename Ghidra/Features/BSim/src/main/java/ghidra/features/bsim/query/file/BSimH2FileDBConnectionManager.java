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
package ghidra.features.bsim.query.file;

import java.io.File;
import java.net.URL;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.*;

import org.apache.commons.dbcp2.BasicDataSource;
import org.h2.tools.DeleteDbFiles;

import ghidra.features.bsim.query.*;
import ghidra.features.bsim.query.BSimServerInfo.DBType;
import ghidra.features.bsim.query.FunctionDatabase.ConnectionType;
import ghidra.features.bsim.query.FunctionDatabase.Status;
import ghidra.util.Msg;

public class BSimH2FileDBConnectionManager {

	private static final String DRIVER_CLASS_NAME = "org.h2.Driver";
	private static final int CONN_POOL_SIZE = 1;
	private static final int CONN_POOL_MAX_IDLE = 2;

	/**
	 * Data source map keyed by absolute DB file path
	 */
	private static HashMap<BSimServerInfo, BSimH2FileDataSource> dataSourceMap = new HashMap<>();
	private static boolean shutdownHookInstalled = false;

	/**
	 * Get all H2 File DB data sorces which exist in the JVM.
	 * @return all H2 File DB data sorces
	 */
	public static synchronized Collection<BSimH2FileDataSource> getAllDataSources() {
		// Create copy to avoid potential concurrent modification
		return Collections.unmodifiableCollection(new ArrayList<>(dataSourceMap.values()));
	}

	/**
	 * Get an existing or new H2 File DB data source for the specified H2 File
	 * specified by {@code fileServerInfo}.
	 * @param fileServerInfo H2 File DB info
	 * @return new or existing H2 File DB data source
	 * @throws IllegalArgumentException if {@code fileServerInfo} does not specify an
	 * H2 File DB type.
	 */
	public static synchronized BSimH2FileDataSource getDataSource(BSimServerInfo fileServerInfo) {
		if (fileServerInfo.getDBType() != DBType.file) {
			throw new IllegalArgumentException("expected file info");
		}
		enableShutdownHook();
		return dataSourceMap.computeIfAbsent(fileServerInfo,
			info -> new BSimH2FileDataSource(info));
	}

	@Deprecated
	public static BSimH2FileDataSource getDataSource(URL h2FileUrl) {
		return getDataSource(new BSimServerInfo(h2FileUrl));
	}

	/**
	 * Get the existing H2 File DB data source for the specified BSim DB server info.
	 * This may return null if the H2 File DB exists but a 
	 * {@link #getDataSource(BSimServerInfo) data source}
	 * has not yet been established within the running JVM.  
	 * @param serverInfo BSim DB server info
	 * @return existing H2 File data source or null if server info does not correspond to an
	 * H2 File or has not be established as an H2 File data source.  
	 */
	public static synchronized BSimH2FileDataSource getDataSourceIfExists(
			BSimServerInfo serverInfo) {
		return dataSourceMap.get(serverInfo);
	}

	private static synchronized boolean remove(BSimServerInfo serverInfo, boolean force) {
		BSimH2FileDataSource ds = dataSourceMap.get(serverInfo);
		if (ds == null) {
			return true;
		}
		int n = ds.bds.getNumActive();
		if (n != 0 && !force) {
			Msg.error(BSimH2FileDBConnectionManager.class,
				"Unable to remove data source which has " + n + " active connections");
			return false;
		}
		ds.close();
		dataSourceMap.remove(serverInfo);
		BSimVectorStoreManager.remove(serverInfo);
		return true;
	}

	private static synchronized void enableShutdownHook() {
		if (shutdownHookInstalled) {
			return;
		}
		Runtime.getRuntime().addShutdownHook(new Thread() {
			@Override
			public void run() {
				Collection<BSimH2FileDataSource> dataSources = dataSourceMap.values();
				for (BSimH2FileDataSource ds : dataSources) {
					int activeConnections = ds.getActiveConnections();
					if (activeConnections != 0) {
						Msg.error(BSimH2FileDBConnectionManager.class,
							activeConnections +
								" BSim active H2 File connections were not properly closed: " +
								ds.serverInfo);
					}
					ds.close();
				}
				dataSourceMap.clear();
			}
		});
		shutdownHookInstalled = true;
	}

	/**
	 * {@link BSimH2FileDataSource} provides a pooled DB data source for a specific H2 File DB. 
	 */
	public static class BSimH2FileDataSource implements BSimJDBCDataSource {

		private final BSimServerInfo serverInfo;

		private boolean successfulConnection = false;

		private BasicDataSource bds = new BasicDataSource();
		private BSimDBConnectTaskCoordinator taskCoordinator;

		private BSimH2FileDataSource(BSimServerInfo serverInfo) {
			this.serverInfo = serverInfo;
			this.taskCoordinator = new BSimDBConnectTaskCoordinator(serverInfo);
		}

		@Override
		public BSimServerInfo getServerInfo() {
			return serverInfo;
		}

		@Override
		public void dispose() {
			BSimH2FileDBConnectionManager.remove(serverInfo, true);
		}

		/**
		 * Delete the database files associated with this H2 File DB.  This will fail immediately 
		 * if active connections exist.  Otherwise removal will be attempted and this data source 
		 * will no longer be valid.
		 * @return true if DB sucessfully removed
		 */
		public synchronized boolean delete() {

			File dbf = new File(serverInfo.getDBName());

			if (getActiveConnections() != 0) {
				Msg.error(this, "Failed to delete active database: " + dbf);
				return false;
			}

			dispose();

			if (dbf.isFile()) {
				return true;
			}

			String name = dbf.getName();
			int ix = name.lastIndexOf(BSimServerInfo.H2_FILE_EXTENSION);
			if (ix > 0) {
				name = name.substring(0, ix);
			}

			DeleteDbFiles.execute(dbf.getParent(), name, true);

			if (!dbf.isFile()) {
				return true;
			}

			Msg.error(this, "Failed to delete database: " + dbf);
			return false;
		}

		/**
		 * Determine if the stored DB file exists.
		 * @return true if the stored DB file exists
		 */
		public boolean exists() {
			File dbf = new File(serverInfo.getDBName());
			return dbf.isFile();
		}

		private void close() {
			try {
				bds.close();
			}
			catch (SQLException e) {
				// ignore
			}
		}

		@Override
		public Status getStatus() {
			if (bds.isClosed()) {
				return Status.Unconnected;
			}
			if (successfulConnection) {
				return Status.Ready;
			}
			return Status.Error;
		}

		@Override
		public int getActiveConnections() {
			return bds.getNumActive();
		}

		@Override
		public int getIdleConnections() {
			return bds.getNumIdle();
		}

		private String getH2FileUrl() {

			// Remove H2 db file extension if present
			String dbName = serverInfo.getDBName();
			int ix = dbName.lastIndexOf(BSimServerInfo.H2_FILE_EXTENSION);
			if (ix > 0) {
				dbName = dbName.substring(0, ix);
			}

			// On Windows we must remove the leading separator before the drive letter
			if (File.separatorChar == '\\' && dbName.length() > 3 && dbName.charAt(0) == '/' &&
				Character.isLetter(dbName.charAt(1)) && dbName.charAt(2) == ':') {
				// Remove leading '/' before drive letter
				dbName = dbName.substring(1);
			}

			return "jdbc:h2:" + dbName;
		}

		private void setDefaultProperties() {

			// Set database driver name
			bds.setDriverClassName(DRIVER_CLASS_NAME);

			// Set database URL
			// NOTE: keywords 'key' and 'value' are used by KeyValueTable as column names
			bds.setUrl(getH2FileUrl() +
				";MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE;DEFAULT_NULL_ORDERING=HIGH;NON_KEYWORDS=key,value");

			// Set the connection pool size
			bds.setInitialSize(CONN_POOL_SIZE);

			// Set maximum number of idle connections
			bds.setMaxIdle(CONN_POOL_MAX_IDLE);

			// Validate connection borrowed from pool
			//bds.setValidationQuery("SELECT 1");
			//bds.setTestOnBorrow(true);

			// bds.setLogAbandoned(true);
			// bds.setAbandonedUsageTracking(true);
		}

		/**
		 * Get a connection to the H2 file database.
		 * It is important to note that if the database does not exist and empty one will
		 * be created.  The {@link #exists()} method should be used to check for the database
		 * existance prior to connecting the first time.
		 * @return database connection
		 * @throws SQLException if a database error occurs
		 */
		@Override
		public synchronized Connection getConnection() throws SQLException {

			if (successfulConnection) {
				return bds.getConnection();
			}

			setDefaultProperties();

			return taskCoordinator.getConnection(() -> connect());
		}

		@Override
		public ConnectionType getConnectionType() {
			return ConnectionType.Unencrypted_No_Authentication;
		}

		@Override
		public boolean equals(Object obj) {
			if (obj instanceof BSimH2FileDataSource ds) {
				return bds.getUrl().equals(ds.bds.getUrl());
			}
			return false;
		}

		@Override
		public int hashCode() {
			return bds.getUrl().hashCode();
		}

		/**
		 * Establish H2 File DB {@link Connection} performing any required authentication. 
		 * @throws SQLException if connection or authentication error occurs 
		 */
		private Connection connect() throws SQLException {
			Connection c = bds.getConnection();
			successfulConnection = true;
			return c;
		}
	}
}
