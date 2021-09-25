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
package ghidra.framework.data;

import java.io.IOException;

import db.DBHandle;
import generic.depends.DependentServiceResolver;
import generic.depends.err.*;
import ghidra.util.database.DBOpenMode;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

public abstract class DBDomainObjectSupport extends DomainObjectAdapterDB {
	private DBOpenMode openMode;
	private TaskMonitor monitor;

	private VersionException versionExc;

	protected static interface ManagerSupplier<T> {
		T create(DBOpenMode openMode, TaskMonitor monitor)
				throws IOException, VersionException, CancelledException;
	}

	protected DBDomainObjectSupport(DBHandle dbh, DBOpenMode openMode, TaskMonitor monitor,
			String name, int timeInterval, int bufSize, Object consumer) {
		super(dbh, name, timeInterval, bufSize, consumer);
		this.openMode = openMode;
		this.monitor = monitor;
	}

	public void init()
			throws CancelledException, IOException, VersionException, ServiceConstructionException {
		this.versionExc = null;
		try {
			DependentServiceResolver.inject(this);
		}
		catch (ServiceConstructionException e) {
			Throwable cause = e.getCause();
			if (cause instanceof VersionException) {
				throw (VersionException) cause;
			}
			if (cause instanceof CancelledException) {
				throw (CancelledException) cause;
			}
			if (cause instanceof IOException) {
				throw (IOException) cause;
			}
			throw e;
		}
		catch (UnsatisfiedParameterException | UnsatisfiedFieldsException e) {
			throw new AssertionError(e);
		}
		if (versionExc != null) {
			throw versionExc;
		}
		finishedCreatingManagers();
		this.monitor = null;
	}

	protected void finishedCreatingManagers() {
		// Extension point
	}

	protected <T> T createManager(String managerName, ManagerSupplier<T> supplier)
			throws CancelledException, IOException {
		monitor.checkCanceled();
		monitor.setMessage("Creating " + managerName);
		try {
			return supplier.create(openMode, monitor);
		}
		catch (VersionException e) {
			versionExc = e.combine(versionExc);

			// TODO: (see GP-1238) Consider properly supporting VersionException and upgrades.  
			// Returning a null manager will likely induce an NPE down the line.

			return null;
		}
	}
}
