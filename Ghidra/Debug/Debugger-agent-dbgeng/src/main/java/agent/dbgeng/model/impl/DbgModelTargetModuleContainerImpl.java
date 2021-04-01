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
import ghidra.dbg.target.*;
import ghidra.dbg.target.schema.*;
import ghidra.dbg.target.schema.TargetObjectSchema.ResyncMode;
import ghidra.lifecycle.Internal;

@TargetObjectSchemaInfo(name = "ModuleContainer", elements = { //
	@TargetElementType(type = DbgModelTargetModuleImpl.class) //
}, //
		elementResync = ResyncMode.ONCE, //
		attributes = { //
			@TargetAttributeType(type = Void.class) //
		}, canonicalContainer = true)
public class DbgModelTargetModuleContainerImpl extends DbgModelTargetObjectImpl
		implements DbgModelTargetModuleContainer {
	// NOTE: -file-list-shared-libraries omits the main module and system-supplied DSO.

	protected final DbgModelTargetProcessImpl targetProcess;
	protected final DbgProcess process;

	public DbgModelTargetModuleContainerImpl(DbgModelTargetProcessImpl process) {
		super(process.getModel(), process, "Modules", "ModuleContainer");
		this.targetProcess = process;
		this.process = process.process;
		requestElements(false);
	}

	@Override
	@Internal
	public void libraryLoaded(String name) {
		DbgModelTargetModule module;
		synchronized (this) {
			/**
			 * It's not a good idea to remove "stale" entries. If the entry's already present, it's
			 * probably because several modules were loaded at once, at it has already had its
			 * sections loaded. Removing it will cause it to load all module sections again!
			 */
			//modulesByName.remove(name);
			module = getTargetModule(name);
		}
		TargetThread eventThread =
			(TargetThread) getModel().getModelObject(getManager().getEventThread());
		changeElements(List.of(), List.of(module), Map.of(), "Loaded");
		getListeners().fire.event(getProxy(), eventThread, TargetEventType.MODULE_LOADED,
			"Library " + name + " loaded", List.of(module));
	}

	@Override
	@Internal
	public void libraryUnloaded(String name) {
		DbgModelTargetModule targetModule = getTargetModule(name);
		if (targetModule != null) {
			TargetThread eventThread =
				(TargetThread) getModel().getModelObject(getManager().getEventThread());
			getListeners().fire.event(getProxy(), eventThread, TargetEventType.MODULE_UNLOADED,
				"Library " + name + " unloaded", List.of(targetModule));
			DbgModelImpl impl = (DbgModelImpl) model;
			impl.deleteModelObject(targetModule.getDbgModule());
		}
		changeElements(List.of(name), List.of(), Map.of(), "Unloaded");
	}

	@Override
	public boolean supportsSyntheticModules() {
		return false;
	}

	@Override
	public CompletableFuture<? extends TargetModule> addSyntheticModule(String name) {
		throw new UnsupportedOperationException("Dbgeng Does not support synthetic modules");
	}

	@Override
	public CompletableFuture<Void> requestElements(boolean refresh) {
		List<TargetObject> result = new ArrayList<>();
		return process.listModules().thenAccept(byName -> {
			synchronized (this) {
				for (Map.Entry<String, DbgModule> ent : byName.entrySet()) {
					result.add(getTargetModule(ent.getKey()));
				}
			}
			changeElements(List.of(), result, Map.of(), "Refreshed");
		});
	}

	public DbgModelTargetModule getTargetModule(String name) {
		// Only get here from libraryLoaded or getElements. The known list should be fresh.
		DbgModule module = process.getKnownModules().get(name);
		if (module == null) {
			return null;
		}
		DbgModelImpl impl = (DbgModelImpl) model;
		TargetObject modelObject = impl.getModelObject(module);
		if (modelObject != null) {
			return (DbgModelTargetModule) modelObject;
		}
		return new DbgModelTargetModuleImpl(this, module);
	}

}
