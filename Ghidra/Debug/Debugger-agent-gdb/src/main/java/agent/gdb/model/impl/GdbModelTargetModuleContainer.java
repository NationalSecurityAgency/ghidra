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
package agent.gdb.model.impl;

import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

import agent.gdb.manager.GdbInferior;
import agent.gdb.manager.GdbModule;
import ghidra.async.AsyncFence;
import ghidra.dbg.agent.DefaultTargetObject;
import ghidra.dbg.error.DebuggerUserException;
import ghidra.dbg.target.*;
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.dbg.target.schema.TargetObjectSchema.ResyncMode;
import ghidra.dbg.target.schema.TargetObjectSchemaInfo;
import ghidra.lifecycle.Internal;

@TargetObjectSchemaInfo(
	name = "ModuleContainer",
	elementResync = ResyncMode.ONCE, // TODO: Should this be NEVER?
	attributes = { @TargetAttributeType(type = Void.class) },
	canonicalContainer = true)
public class GdbModelTargetModuleContainer
		extends DefaultTargetObject<GdbModelTargetModule, GdbModelTargetInferior>
		implements TargetModuleContainer {
	// NOTE: -file-list-shared-libraries omits the main module and system-supplied DSO.
	public static final String NAME = "Modules";

	protected final GdbModelImpl impl;
	protected final GdbInferior inferior;

	public GdbModelTargetModuleContainer(GdbModelTargetInferior inferior) {
		super(inferior.impl, inferior, NAME, "ModuleContainer");
		this.impl = inferior.impl;
		this.inferior = inferior.inferior;
	}

	@Internal
	public GdbModelTargetModule libraryLoaded(String name) {
		GdbModule mod = Objects.requireNonNull(inferior.getKnownModules().get(name));
		GdbModelTargetModule module = getTargetModule(mod);
		changeElements(List.of(), List.of(module), "Loaded");
		return module;
	}

	@Internal
	public void libraryUnloaded(String name) {
		synchronized (this) {
			impl.deleteModelObject(name);
		}
		changeElements(List.of(name), List.of(), "Unloaded");
	}

	@Override
	public boolean supportsSyntheticModules() {
		return false;
	}

	@Override
	public CompletableFuture<? extends TargetModule> addSyntheticModule(String name) {
		throw new DebuggerUserException("GDB Does not support synthetic modules");
	}

	protected CompletableFuture<Void> updateUsingModules(Map<String, GdbModule> byName) {
		List<GdbModelTargetModule> modules;
		synchronized (this) {
			modules =
				byName.values().stream().map(this::getTargetModule).collect(Collectors.toList());
		}
		AsyncFence fence = new AsyncFence();
		for (GdbModelTargetModule mod : modules) {
			fence.include(mod.init());
		}

		/**
		 * NB. Modules may have changed by the time the fence completes. We'll just remove invalid
		 * modules, since any additions should cause a follow-on update.
		 */
		return fence.ready().thenAccept(__ -> {
			List<GdbModelTargetModule> validOnly =
				modules.stream().filter(m -> m.isValid()).collect(Collectors.toList());
			changeElements(List.of(), validOnly, "Refreshed");
		});
	}

	@Override
	protected CompletableFuture<Void> requestElements(boolean refresh) {
		// Ignore 'refresh' because inferior.getKnownModules may exclude executable
		return doRefresh();
	}

	protected CompletableFuture<Void> doRefresh() {
		return inferior.listModules().thenCompose(byName -> {
			for (String modName : inferior.getKnownModules().keySet()) {
				if (!byName.keySet().contains(modName)) {
					impl.deleteModelObject(byName.get(modName));
				}
			}
			return updateUsingModules(byName);
		});
	}

	protected synchronized GdbModelTargetModule getTargetModule(GdbModule module) {
		TargetObject modelObject = impl.getModelObject(module);
		if (modelObject != null) {
			return (GdbModelTargetModule) modelObject;
		}
		return new GdbModelTargetModule(this, module);
	}

	public synchronized GdbModelTargetModule getTargetModuleIfPresent(String name) {
		return (GdbModelTargetModule) impl.getModelObject(name);
	}

	protected CompletableFuture<?> refreshInternal() {
		return doRefresh().exceptionally(ex -> {
			impl.reportError(this, "Problem refreshing inferior's modules", ex);
			return null;
		});
	}
}
