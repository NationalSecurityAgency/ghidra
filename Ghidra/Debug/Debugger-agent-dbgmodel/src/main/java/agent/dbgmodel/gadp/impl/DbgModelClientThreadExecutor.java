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
package agent.dbgmodel.gadp.impl;

import java.util.function.Supplier;

import agent.dbgeng.gadp.impl.AbstractClientThreadExecutor;
import agent.dbgeng.manager.DbgManager;
import agent.dbgmodel.dbgmodel.bridge.HostDataModelAccess;

/**
 * A single-threaded executor which creates and exclusively accesses the {@code dbgeng.dll} client.
 * 
 * The executor also has a priority mechanism, so that callbacks may register follow-on handlers
 * which take precedence over other tasks in the queue (which could trigger additional callbacks).
 * This is required since certain operation are not allowed during normal callback processing. For
 * example, changing the current process is typically not allowed, but it is necessary to retrieve a
 * thread's context.
 */
public class DbgModelClientThreadExecutor extends AbstractClientThreadExecutor {

	private final Supplier<HostDataModelAccess> makeAccess;
	private WrappedDbgModel dbgmodel;
	private DbgManager manager;

	/**
	 * Instantiate a new executor, providing a means of creating the client
	 * 
	 * @param makeClient the callback to create the client
	 */
	public DbgModelClientThreadExecutor(Supplier<HostDataModelAccess> makeClient) {
		this.makeAccess = makeClient;
		thread.setDaemon(true);
		thread.start();
	}

	/**
	 * Obtain a reference to the client, only if the calling thread is this executor's thread.
	 * 
	 * @return the client
	 */
	public WrappedDbgModel getAccess() {
		if (thread != Thread.currentThread()) {
			throw new AssertionError("Cannot get client outside owning thread");
		}
		return dbgmodel;
	}

	@Override
	protected void init() {
		dbgmodel = new WrappedDbgModel(makeAccess.get());
		client = dbgmodel.getClient();
	}

	@Override
	public DbgManager getManager() {
		return manager;
	}

	@Override
	public void setManager(DbgManager manager) {
		this.manager = manager;
	}

}
