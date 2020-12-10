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
package agent.dbgeng.model.impl;

import java.util.*;
import java.util.concurrent.CompletableFuture;

import agent.dbgeng.manager.DbgModule;
import agent.dbgeng.manager.DbgProcess;
import agent.dbgeng.model.iface2.DbgModelTargetModule;
import agent.dbgeng.model.iface2.DbgModelTargetModuleContainer;
import ghidra.async.AsyncFence;
import ghidra.async.AsyncLazyMap;
import ghidra.dbg.target.TargetModule;
import ghidra.dbg.target.TargetObject;
import ghidra.lifecycle.Internal;
import ghidra.util.Msg;

public class DbgModelTargetModuleContainerImpl extends DbgModelTargetObjectImpl
		implements DbgModelTargetModuleContainer {
	// NOTE: -file-list-shared-libraries omits the main module and system-supplied DSO.

	protected final DbgProcess process;

	// TODO: Is it possible to load the same object twice?
	protected final AsyncLazyMap<String, DbgModelTargetModule> modulesByName =
		new AsyncLazyMap<String, DbgModelTargetModule>(new HashMap<>(), this::doGetTargetModule);

	public DbgModelTargetModuleContainerImpl(DbgModelTargetProcessImpl process) {
		super(process.getModel(), process, "Modules", "ModuleContainer");
		this.process = process.process;
	}

	@Override
	@Internal
	public void libraryLoaded(String name) {
		CompletableFuture<DbgModelTargetModule> module;
		synchronized (this) {
			/**
			 * It's not a good idea to remove "stale" entries. If the entry's already present, it's
			 * probably because several modules were loaded at once, at it has already had its
			 * sections loaded. Removing it will cause it to load all module sections again!
			 */
			//modulesByName.remove(name);
			module = doGetTargetModule(name);
		}
		module.thenAccept(mod -> {
			changeElements(List.of(), List.of(mod), Map.of(), "Loaded");
			getListeners().fire(TargetEventScopeListener.class)
					.event(this, null, TargetEventType.MODULE_LOADED, "Library " + name + " loaded",
						List.of(mod));
		}).exceptionally(e -> {
			Msg.error(this, "Problem getting module for library load: " + name, e);
			return null;
		});
	}

	@Override
	@Internal
	public void libraryUnloaded(String name) {
		modulesByName.get(name).thenAccept(mod -> {
			getListeners().fire(TargetEventScopeListener.class)
					.event(this, null, TargetEventType.MODULE_UNLOADED,
						"Library " + name + " unloaded", List.of(mod));
		});
		synchronized (this) {
			modulesByName.remove(name);
		}
		changeElements(List.of(name), List.of(), Map.of(), "Unloaded");
	}

	@Override
	public boolean supportsSyntheticModules() {
		return false;
	}

	@Override
	public CompletableFuture<? extends TargetModule<?>> addSyntheticModule(String name) {
		throw new UnsupportedOperationException("GDB Does not support synthetic modules");
	}

	@Override
	public CompletableFuture<Void> requestElements(boolean refresh) {
		List<TargetObject> result = new ArrayList<>();
		return process.listModules().thenCompose(byName -> {
			AsyncFence fence = new AsyncFence();
			synchronized (this) {
				modulesByName.retainKeys(byName.keySet());
				for (Map.Entry<String, DbgModule> ent : byName.entrySet()) {
					fence.include(getTargetModule(ent.getKey()).thenAccept(module -> {
						result.add(module);
					}));
				}
			}
			return fence.ready();
		}).thenAccept(__ -> {
			changeElements(List.of(), result, Map.of(), "Refreshed");
		});
	}

	protected CompletableFuture<DbgModelTargetModule> doGetTargetModule(String name) {
		// Only get here from libraryLoaded or getElements. The known list should be fresh.
		DbgModule module = process.getKnownModules().get(name);
		if (module == null) {
			return CompletableFuture.completedFuture(null);
		}
		return CompletableFuture.completedFuture(new DbgModelTargetModuleImpl(this, module));
		//TODO: return module.listSections().thenApply(__ -> new DbgModelTargetModule(this, module));
	}

	@Override
	public CompletableFuture<DbgModelTargetModule> getTargetModule(String name) {
		return modulesByName.get(name);
	}
}
