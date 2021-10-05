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
package agent.lldb.gadp.impl;

import java.util.function.Supplier;

import agent.lldb.lldb.DebugClient;
import agent.lldb.manager.LldbManager;

/**
 * A single-threaded executor which creates and exclusively accesses the {@code lldb} client.
 * 
 * The executor also has a priority mechanism, so that callbacks may register follow-on handlers
 * which take precedence over other tasks in the queue (which could trigger additional callbacks).
 * This is required since certain operation are not allowed during normal callback processing. For
 * example, changing the current process is typically not allowed, but it is necessary to retrieve a
 * thread's context.
 */
public class LldbClientThreadExecutor extends AbstractClientThreadExecutor {

	private final Supplier<DebugClient> makeClient;
	private LldbManager manager;

	/**
	 * Instantiate a new executor, providing a means of creating the client
	 * 
	 * @param makeClient the callback to create the client
	 */
	public LldbClientThreadExecutor(Supplier<DebugClient> makeClient) {
		this.makeClient = makeClient;
		thread.setDaemon(true);
		thread.start();
	}

	@Override
	protected void init() {
		this.client = makeClient.get();
		client.setManager(manager);
	}

	@Override
	public LldbManager getManager() {
		return manager;
	}

	@Override
	public void setManager(LldbManager manager) {
		this.manager = manager;
	}

}
