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
package ghidra.features.bsim.query;

import java.net.URL;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.HashMap;

import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;

import org.apache.commons.dbcp2.BasicDataSource;
import org.apache.commons.lang3.StringUtils;

import ghidra.features.bsim.query.BSimServerInfo.DBType;
import ghidra.features.bsim.query.FunctionDatabase.ConnectionType;
import ghidra.features.bsim.query.FunctionDatabase.Status;
import ghidra.framework.client.*;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;

public class BSimPostgresDBConnectionManager {

	private static final String DRIVER_CLASS_NAME = "org.postgresql.Driver";
	private static final int CONN_POOL_SIZE = 2;
	private static final int CONN_POOL_MAX_IDLE = 2;

	private static HashMap<BSimServerInfo, BSimPostgresDataSource> dataSourceMap = new HashMap<>();

	public static BSimPostgresDataSource getDataSource(BSimServerInfo postgresServerInfo) {
		if (postgresServerInfo.getDBType() != DBType.postgres) {
			throw new IllegalArgumentException("expected postgres server info");
		}
		return dataSourceMap.computeIfAbsent(postgresServerInfo,
			info -> new BSimPostgresDataSource(info));
	}

	@Deprecated
	public static BSimPostgresDataSource getDataSource(URL postgresUrl) {
		return getDataSource(new BSimServerInfo(postgresUrl));
	}

	public static BSimPostgresDataSource getDataSourceIfExists(BSimServerInfo serverInfo) {
		return dataSourceMap.get(serverInfo);
	}

	private static synchronized void remove(BSimServerInfo serverInfo) {
		BSimPostgresDataSource ds = dataSourceMap.get(serverInfo);
		if (ds == null) {
			return;
		}
		int n = ds.bds.getNumActive();
		if (n != 0) {
			System.out
					.println("Unable to remove data source which has " + n + " active connections");
			return;
		}
		ds.close();
		dataSourceMap.remove(serverInfo);
	}

	public static class BSimPostgresDataSource implements BSimJDBCDataSource { // NOTE: can be renamed

		private final BSimServerInfo serverInfo;

		private ConnectionType connectionType = ConnectionType.SSL_No_Authentication;
		private boolean successfulConnection = false;

		private BasicDataSource bds = new BasicDataSource();
		private BSimDBConnectTaskCoordinator taskCoordinator;

		private BSimPostgresDataSource(BSimServerInfo serverInfo) {
			this.serverInfo = serverInfo;
			this.taskCoordinator = new BSimDBConnectTaskCoordinator(serverInfo);
		}

		@Override
		public BSimServerInfo getServerInfo() {
			return serverInfo;
		}

		public void initializeFrom(BSimPostgresDataSource otherDs) {
			if (!otherDs.successfulConnection ||
				otherDs.connectionType != ConnectionType.SSL_Password_Authentication) {
				return;
			}
			setDefaultProperties();
			setSSLProperties();
			bds.setUsername(otherDs.getUserName());
			bds.setPassword(otherDs.bds.getPassword());
			successfulConnection = true;
		}

		public String getUserName() {
			return bds.getUsername();
		}

		public void setPreferredUserName(String userName) {
			bds.setUsername(userName);
		}

		public void dispose() {
			remove(serverInfo);
		}

		private void close() {
			try {
				bds.close();
			}
			catch (SQLException e) {
				// ignore
			}
			bds.setPassword(null);
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

		/**
		 * Update password on {@link BasicDataSource} for use with future connect attempts.
		 * Has no affect if username does not match username on data source.
		 * @param username username
		 * @param newPassword updated password
		 */
		public void setPassword(String username, char[] newPassword) {
			if (username.equals(bds.getUsername())) {
				bds.setPassword(String.valueOf(newPassword));
			}
		}

		private void setDefaultProperties() {
			//Set database driver name
			bds.setDriverClassName(DRIVER_CLASS_NAME);

			//Set database url
			int port = serverInfo.getPort();
			bds.setUrl("jdbc:postgresql://" + serverInfo.getServerName() +
				(port > 0 ? (":" + Integer.toString(port)) : "") + "/" + serverInfo.getDBName());

			//Set the connection pool size
			bds.setInitialSize(CONN_POOL_SIZE);

			// Set maximum number of idle connections
			bds.setMaxIdle(CONN_POOL_MAX_IDLE);

			// Validate connection borrowed from pool
			bds.setValidationQuery("SELECT 1");
			bds.setTestOnBorrow(true);

			// bds.setLogAbandoned(true);
			// bds.setAbandonedUsageTracking(true);

			// PGStatement.setPrepareThreshold(2)
			bds.addConnectionProperty("prepareThreshold", "2");
		}

		private void setSSLProperties() {
			bds.addConnectionProperty("sslmode", "require");
			bds.addConnectionProperty("sslfactory", "ghidra.net.ApplicationSSLSocketFactory");
		}

		@Override
		public synchronized Connection getConnection() throws SQLException {

			if (successfulConnection) {
				try {
					// attempt to reuse pooled connection or current settings
					try {
						return bds.getConnection();
					}
					catch (SQLException e) {
						// ignore
					}

					// Give one restart attempt (possible password change)
					bds.restart();
					return bds.getConnection();
				}
				catch (SQLException e) {
					successfulConnection = false;
					bds.close();
					BasicDataSource newBds = new BasicDataSource();
					newBds.setUsername(bds.getUsername());
					bds.setPassword(null); // sanitize old instance
					bds = newBds;
					// fall-through for clean start
				}
				finally {
					Msg.debug(this, serverInfo + " getConnection: active=" + bds.getNumActive() +
						" idle=" + bds.getNumIdle());
				}
			}

			setDefaultProperties();

			return taskCoordinator.getConnection(() -> connect());
		}

		@Override
		public ConnectionType getConnectionType() {
			return connectionType;
		}

		@Override
		public boolean equals(Object obj) {
			if (obj instanceof BSimPostgresDataSource ds) {
				return bds.getUrl().equals(ds.bds.getUrl());
			}
			return false;
		}

		@Override
		public int hashCode() {
			return bds.getUrl().hashCode();
		}

		/**
		 * Establish Postgres DB {@link Connection} performing any required authentication. 
		 * @throws SQLException if connection or authentication error occurs 
		 * @throws CancelledException if connection cancelled by user
		 */
		private Connection connect() throws SQLException, CancelledException {

			String userName = bds.getUsername();
			bds.setUsername(StringUtils.isBlank(userName) ? ClientUtil.getUserName() : userName);
			bds.setPassword(null);
			connectionType = ConnectionType.SSL_No_Authentication;
			try {
				// Specify SSL connection properties
				setSSLProperties();
				Connection c = bds.getConnection();
				successfulConnection = true;
				return c;
			}
			catch (SQLException e) {
				// TODO: Need to verify these
				if (e.getMessage().contains("password-based authentication") ||
					e.getMessage().contains("SCRAM-based") ||
					e.getMessage().contains("password authentication failed")) {
					// Use Ghidra's authentication infrastructure
					connectionType = ConnectionType.SSL_Password_Authentication; // Try again with a password
					// fallthru to second attempt at getConnection
				}
				else if (e.getMessage().contains("SSL on") &&
					e.getMessage().contains("no pg_hba.conf entry")) {
					connectionType = ConnectionType.Unencrypted_No_Authentication; // Try again without any SSL
					bds.removeConnectionProperty("sslmode");
					bds.removeConnectionProperty("sslfactory");
					// fallthru to second attempt at getConnection
				}
				else {
					throw e;
				}
			}
			finally {
				Msg.debug(this, serverInfo + " getConnection: active=" + bds.getNumActive() +
					" idle=" + bds.getNumIdle());
			}

			String loginError = null;
			while (true) {
				ClientAuthenticator clientAuthenticator = null;
				if (connectionType == ConnectionType.SSL_Password_Authentication) {
					clientAuthenticator = ClientUtil.getClientAuthenticator();
					if (clientAuthenticator == null) { // Make sure authenticator is registered
						throw new SQLException("No registered authenticator");
					}
					NameCallback nameCb = new NameCallback("User ID:");
					nameCb.setName(bds.getUsername());
					PasswordCallback passCb = new PasswordCallback("Password:", false);
					try {
						if (!clientAuthenticator.processPasswordCallbacks(
							"BSim Database Authentication", "BSim Database Server",
							serverInfo.toString(), nameCb, passCb, null, null, loginError)) {
							throw new CancelledException();
						}
						bds.setPassword(new String(passCb.getPassword()));
						// User may have specified new username, or this may return NULL
						userName = nameCb.getName();
						if (!StringUtils.isBlank(userName)) {
							bds.setUsername(userName);
						}
					}
					finally {
						passCb.clearPassword();
					}
				}
				try {
					Connection c = bds.getConnection();
					successfulConnection = true;
					return c;
				}
				catch (SQLException e) {
					if ((clientAuthenticator instanceof DefaultClientAuthenticator) &&
						e.getMessage().contains("password authentication failed")) {
						// wrong password provided via popup dialog - try again
						loginError = "Access denied: " + serverInfo;
						continue;
					}
					connectionType = ConnectionType.SSL_No_Authentication;
					throw e;
				}
				finally {
					Msg.debug(this, serverInfo + " getConnection: active=" + bds.getNumActive() +
						" idle=" + bds.getNumIdle());
				}
			}
		}

	}

}
