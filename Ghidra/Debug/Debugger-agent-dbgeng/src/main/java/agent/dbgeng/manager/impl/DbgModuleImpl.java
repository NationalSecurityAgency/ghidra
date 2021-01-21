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

import java.util.Map;
import java.util.concurrent.CompletableFuture;

import agent.dbgeng.dbgeng.DebugModuleInfo;
import agent.dbgeng.manager.DbgCause.Causes;
import agent.dbgeng.manager.DbgModule;
import ghidra.async.AsyncLazyValue;

public class DbgModuleImpl implements DbgModule {

	DbgManagerImpl manager;
	protected final DbgProcessImpl process;
	protected final String name;
	private DebugModuleInfo info;

	protected final AsyncLazyValue<Map<String, DbgMinimalSymbol>> minimalSymbols =
		new AsyncLazyValue<>(this::doGetMinimalSymbols);

	/**
	 * Construct a new module
	 * 
	 * @param manager the manager creating the module
	 * @param process the process to which the module belongs
	 * @param id the dbgeng-assigned module ID
	 */
	public DbgModuleImpl(DbgManagerImpl manager, DbgProcessImpl process, String name) {
		this.manager = manager;
		this.process = process;
		this.name = name;
	}

	@Override
	public String getName() {
		return name;
	}

	/**
	 * Add this thread to the inferior and manager
	 */
	public void add() {
		process.addModule(this);
		manager.getEventListeners().fire.moduleLoaded(process, name, Causes.UNCLAIMED);
	}

	/**
	 * Remove this thread from the inferior and manager
	 */
	public void remove() {
		process.removeModule(name);
		manager.getEventListeners().fire.moduleUnloaded(process, name, Causes.UNCLAIMED);
	}

	@Override
	public String getImageName() {
		return info == null ? getName() : info.imageName;
	}

	@Override
	public String getModuleName() {
		return info == null ? getName() : info.moduleName;
	}

	@Override
	public Long getKnownBase() {
		return info == null ? 0L : info.baseOffset;
	}

	@Override
	public Integer getSize() {
		return info == null ? 0 : info.moduleSize;
	}

	@Override
	public Integer getTimeStamp() {
		return info == null ? 0 : info.timeDateStamp;
	}

	protected CompletableFuture<Map<String, DbgMinimalSymbol>> doGetMinimalSymbols() {
		// TODO: Apparently, this is using internal GDB-debugging commands....
		// TODO: Also make methods for "full" symbols (DWARF?)
		return null;
	}

	@Override
	public CompletableFuture<Map<String, DbgMinimalSymbol>> listMinimalSymbols() {
		return minimalSymbols.request();
	}

	public void setInfo(DebugModuleInfo info) {
		this.info = info;
	}

}
