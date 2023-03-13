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
package agent.frida.model.impl;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

import agent.frida.frida.FridaModuleInfo;
import agent.frida.manager.*;
import agent.frida.model.iface2.*;
import agent.frida.model.methods.*;
import ghidra.dbg.DebuggerObjectModel.RefreshBehavior;
import ghidra.dbg.target.*;
import ghidra.dbg.target.schema.*;
import ghidra.dbg.target.schema.TargetObjectSchema.ResyncMode;
import ghidra.util.Msg;

@TargetObjectSchemaInfo(
	name = "ModuleContainer",
	elements = { //
		@TargetElementType(type = FridaModelTargetModuleImpl.class) //
	}, //
	elementResync = ResyncMode.ONCE, //
	attributes = { //
		@TargetAttributeType(type = Object.class) //
	},
	canonicalContainer = true)
public class FridaModelTargetModuleContainerImpl extends FridaModelTargetObjectImpl
		implements FridaModelTargetModuleContainer {

	protected final FridaModelTargetSession targetSession;
	protected final FridaSession session;
	private FridaModelTargetModuleLoadImpl load;
	private FridaModelTargetModuleInitImpl init;
	private FridaModelTargetModuleInterceptorImpl intercept;
	private FridaModelTargetUnloadScriptImpl unload;

	public FridaModelTargetModuleContainerImpl(FridaModelTargetSession session) {
		super(session.getModel(), session, "Modules", "ModuleContainer");
		this.targetSession = session;
		this.session = (FridaSession) session.getModelObject();

		this.load = new FridaModelTargetModuleLoadImpl(this);
		this.init = new FridaModelTargetModuleInitImpl(this);
		this.intercept = new FridaModelTargetModuleInterceptorImpl(this);
		this.unload = new FridaModelTargetUnloadScriptImpl(this, intercept.getName());
		this.changeAttributes(List.of(), List.of( //
			load, //
			init, //
			intercept, //
			unload //
		), Map.of( //
		), "Initialized");

		getManager().addEventsListener(this);
		requestElements(RefreshBehavior.REFRESH_ALWAYS);
	}

	@Override
	public void moduleLoaded(FridaProcess proc, FridaModuleInfo info, int index, FridaCause cause) {
		FridaModelTargetModule targetModule;
		FridaModule module = info.getModule(index);
		synchronized (this) {
			/**
			 * It's not a good idea to remove "stale" entries. If the entry's already present, it's
			 * probably because several modules were loaded at once, at it has already had its
			 * sections loaded. Removing it will cause it to load all module sections again!
			 */
			//modulesByName.remove(name);
			targetModule = getTargetModule(module);
		}
		if (targetModule == null) {
			Msg.error(this, "Module " + info.getModuleName(index) + " not found!");
			return;
		}
		FridaThread thread = getManager().getCurrentThread();
		TargetThread eventThread =
			(TargetThread) getModel().getModelObject(thread);
		changeElements(List.of(), List.of(targetModule), Map.of(), "Loaded");
		broadcast().event(getProxy(), eventThread, TargetEventType.MODULE_LOADED,
			"Library " + info.getModuleName(index) + " loaded", List.of(targetModule));
	}

	@Override
	public void moduleReplaced(FridaProcess proc, FridaModuleInfo info, int index,
			FridaCause cause) {
		FridaModule module = info.getModule(index);
		changeElements(List.of(), List.of(getTargetModule(module)), Map.of(), "Replaced");
		FridaModelTargetModule targetModule = getTargetModule(module);
		changeElements(List.of(), List.of(targetModule), Map.of(), "Replaced");
	}

	@Override
	public void moduleUnloaded(FridaProcess proc, FridaModuleInfo info, int index,
			FridaCause cause) {
		FridaModelTargetModule targetModule = getTargetModule(info.getModule(index));
		if (targetModule != null) {
			FridaThread thread = getManager().getCurrentThread();
			TargetThread eventThread =
				(TargetThread) getModel().getModelObject(thread);
			broadcast().event(getProxy(), eventThread, TargetEventType.MODULE_UNLOADED,
				"Library " + info.getModuleName(index) + " unloaded", List.of(targetModule));
			FridaModelImpl impl = (FridaModelImpl) model;
			impl.deleteModelObject(targetModule.getModule());
		}
		changeElements(List.of(info.getModuleName(index)), List.of(), Map.of(), "Unloaded");
	}

	@Override
	public boolean supportsSyntheticModules() {
		return false;
	}

	@Override
	public CompletableFuture<? extends TargetModule> addSyntheticModule(String name) {
		throw new UnsupportedOperationException("frida does not support synthetic modules");
	}

	@Override
	public CompletableFuture<Void> requestElements(RefreshBehavior refresh) {
		if (refresh.equals(RefreshBehavior.REFRESH_ALWAYS)) {
			broadcast().invalidateCacheRequested(this);
		}
		return getManager().listModules(session.getProcess());
	}

	@Override
	public FridaModelTargetModule getTargetModule(FridaModule module) {
		TargetObject targetObject = getMapObject(module);
		if (targetObject != null) {
			FridaModelTargetModule targetModule = (FridaModelTargetModule) targetObject;
			targetModule.setModelObject(module);
			return targetModule;
		}
		return new FridaModelTargetModuleImpl(this, module);
	}

}
