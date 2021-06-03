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
package agent.dbgeng.manager.impl;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

import agent.dbgeng.dbgeng.DebugInputCallbacks;

public class DbgDebugInputCallbacks implements DebugInputCallbacks {
	private DbgManagerImpl manager;

	public DbgDebugInputCallbacks(DbgManagerImpl manager) {
		this.manager = manager;
	}

	@Override
	public void startInput(long bufsize) {
		manager.getEventListeners().fire.promptChanged(">>>");
		CompletableFuture<String> cf = new CompletableFuture<String>();
		try {
			manager.setContinuation(cf);
			manager.getControl().returnInput(cf.get());
		}
		catch (InterruptedException | ExecutionException e) {
			e.printStackTrace();
		}
	}

}
