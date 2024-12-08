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

import java.sql.Connection;
import java.sql.SQLException;

import ghidra.features.bsim.query.client.CancelledSQLException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.*;

/**
 * Provides the ability to synchronize concurrent connection task
 * instances within the same thread.  This can occur within the swing thread due to the presence
 * of a modal task dialog event queue.  It also allows password cancelation to be propogated to the
 * other tasks(s).
 */
public class BSimDBConnectTaskCoordinator {

	private final BSimServerInfo serverInfo;

	private Exception exc = null;
	private boolean isCancelled = false;
	private int count = 0;

	public BSimDBConnectTaskCoordinator(BSimServerInfo serverInfo) {
		this.serverInfo = serverInfo;
	}

	private void clear() {
		exc = null;
		isCancelled = false;
		count = 0;
	}

	/**
	 * Initiate a DB connection.
	 * @param connectionSupplier DB connection supplier
	 * @return DB connection
	 * @throws SQLException if a database connection error occured
	 * @throws CancelledSQLException if task was cancelled (password entry cancelled)
	 */
	public Connection getConnection(DBConnectionSupplier connectionSupplier) throws SQLException {

		// Use task to establish initial connection
		DBConnectTask connectTask = new DBConnectTask(connectionSupplier);
		try {
			//@formatter:off
            TaskBuilder.withTask(connectTask)
                .setTitle("BSim DB Connection...")
                .setCanCancel(false)
                .setHasProgress(false)
                .launchModal();
            //@formatter:on    

			synchronized (BSimDBConnectTaskCoordinator.this) {
				Connection c = connectTask.getConnection();
				if (c != null) {
					return c;
				}

				if (isCancelled) {
					throw new CancelledSQLException("Password entry was cancelled");
				}
				if (exc instanceof SQLException e) {
					throw e;
				}
				if (exc instanceof RuntimeException e) {
					throw e;
				}
				throw new RuntimeException(exc);
			}
		}
		finally {
			synchronized (BSimDBConnectTaskCoordinator.this) {
				if (--count == 0) {
					clear();
				}
			}
		}
	}

	/**
	 * DB connection supplier
	 */
	public interface DBConnectionSupplier {

		/**
		 * Get a database connection.
		 * @return database connection
		 * @throws CancelledException if connection attempt cancelled
		 * @throws SQLException if a database connection error occurs
		 */
		public Connection get() throws CancelledException, SQLException;
	}

	/**
	 * Task for connecting to Postgres DB server with Swing thread.
	 */
	private class DBConnectTask extends Task {

		private Connection c;
		private DBConnectionSupplier connectionSupplier;

		/**
		 * Server Connect Task constructor
		 * @param connectionSupplier DB connection supplier
		 */
		DBConnectTask(DBConnectionSupplier connectionSupplier) {
			super("BSim Connecting to " + serverInfo, false, false, true);
			this.connectionSupplier = connectionSupplier;
		}

		Connection getConnection() {
			return c;
		}

		/**
		 * Completes and necessary authentication and obtains a DB connection.
		 * If a connection error occurs, an exception will be stored.
		 * @throws CancelledException if task cancelled
		 * @see ghidra.util.task.Task#run(ghidra.util.task.TaskMonitor)
		 */
		@Override
		public void run(TaskMonitor monitor) throws CancelledException {
			synchronized (BSimDBConnectTaskCoordinator.this) {
				monitor.setMessage("Connecting...");
				++count;
				if (isCancelled) {
					throw new CancelledException();
				}
				if (exc != null) {
					return;
				}
				try {
					c = connectionSupplier.get();
				}
				catch (CancelledException e) {
					isCancelled = true;
					throw e;
				}
				catch (Exception e) {
					exc = e;
				}
			}
		}

	}
}
