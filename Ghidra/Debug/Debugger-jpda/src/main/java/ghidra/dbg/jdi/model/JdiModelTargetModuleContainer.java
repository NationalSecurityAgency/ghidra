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
package ghidra.dbg.jdi.model;

import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

import com.sun.jdi.ModuleReference;

import ghidra.async.AsyncFence;
import ghidra.async.AsyncUtils;
import ghidra.dbg.error.DebuggerUserException;
import ghidra.dbg.target.TargetModule;
import ghidra.dbg.target.TargetModuleContainer;
import ghidra.dbg.target.schema.*;
import ghidra.dbg.target.schema.TargetObjectSchema.ResyncMode;
import ghidra.lifecycle.Internal;
import ghidra.util.Msg;

@TargetObjectSchemaInfo(
	name = "TargetModuleContainer",
	elements = {
		@TargetElementType(type = JdiModelTargetModule.class)
	},
	elementResync = ResyncMode.ONCE,
	attributes = {
		@TargetAttributeType(type = Void.class)
	},
	canonicalContainer = true)
public class JdiModelTargetModuleContainer extends JdiModelTargetObjectImpl
		implements TargetModuleContainer {

	protected final JdiModelTargetVM vm;

	// TODO: Is it possible to load the same object twice?
	protected final Map<String, JdiModelTargetModule> modulesByName = new HashMap<>();

	public JdiModelTargetModuleContainer(JdiModelTargetVM vm) {
		super(vm, "Modules");
		this.vm = vm;
	}

	@Internal
	public JdiModelTargetModule libraryLoaded(String name) {
		List<ModuleReference> allModules = vm.vm.allModules();
		for (ModuleReference ref : allModules) {
			if (JdiModelTargetModule.getUniqueId(ref).equals(name)) {
				JdiModelTargetModule module = getTargetModule(ref);
				changeElements(List.of(), List.of(module), Map.of(), "Loaded");
				return module;
			}
		}
		return null;
	}

	@Internal
	public void libraryUnloaded(String name) {
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
	public CompletableFuture<? extends TargetModule> addSyntheticModule(String name) {
		throw new DebuggerUserException("GDB Does not support synthetic modules");
	}

	protected CompletableFuture<Void> updateUsingModules(Map<String, ModuleReference> byName) {
		List<JdiModelTargetModule> modules;
		synchronized (this) {
			modules =
				byName.values().stream().map(this::getTargetModule).collect(Collectors.toList());
		}
		AsyncFence fence = new AsyncFence();
		for (JdiModelTargetModule mod : modules) {
			fence.include(mod.init());
		}
		return fence.ready().thenAccept(__ -> {
			changeElements(List.of(), modules, Map.of(), "Refreshed");
		});
	}

	@Override
	protected CompletableFuture<Void> requestElements(boolean refresh) {
		return doRefresh();
	}

	protected CompletableFuture<Void> doRefresh() {
		Map<String, ModuleReference> map = new HashMap<>();
		List<ModuleReference> allModules = vm.vm.allModules();
		for (ModuleReference ref : allModules) {
			map.put(JdiModelTargetModule.getUniqueId(ref), ref);
		}
		modulesByName.keySet().retainAll(map.keySet());
		return updateUsingModules(map);
	}

	protected synchronized JdiModelTargetModule getTargetModule(ModuleReference module) {
		return modulesByName.computeIfAbsent(JdiModelTargetModule.getUniqueId(module),
			n -> new JdiModelTargetModule(this, module, true));
	}

	public synchronized JdiModelTargetModule getTargetModuleIfPresent(String name) {
		return modulesByName.get(name);
	}

	public CompletableFuture<?> refreshInternal() {
		if (!isObserved()) {
			return AsyncUtils.NIL;
		}
		return doRefresh().exceptionally(ex -> {
			Msg.error(this, "Problem refreshing inferior's modules", ex);
			return null;
		});
	}
}
