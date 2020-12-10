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
package ghidra.dbg.sctl.client;

import java.util.*;
import java.util.concurrent.CompletableFuture;

import ghidra.async.AsyncLazyValue;
import ghidra.async.AsyncUtils;
import ghidra.dbg.agent.DefaultTargetObject;
import ghidra.dbg.sctl.protocol.common.AbstractSctlContext;
import ghidra.dbg.sctl.protocol.common.SctlRegisterDefinition;
import ghidra.dbg.target.*;
import ghidra.dbg.util.CollectionUtils.Delta;

public class SctlTargetRegisters
		extends DefaultTargetObject<SctlTargetRegisterDescription, SctlTargetThread> implements
		TargetRegisterBank<SctlTargetRegisters>, TargetRegisterContainer<SctlTargetRegisters> {

	protected final SctlClient client;

	protected final AsyncLazyValue<Map<String, SctlRegisterDefinition>> lazyRegDefs =
		new AsyncLazyValue<>(this::doGetRegDefs);
	protected final AsyncLazyValue<Map<Long, SctlRegisterDefinition>> lazyRegDefsById =
		new AsyncLazyValue<>(this::doGetRegDefsById);
	protected final AsyncLazyValue<Map<String, SctlTargetRegisterDescription>> lazyRegDescs =
		new AsyncLazyValue<>(this::doGetRegDescs);

	private final List<SctlRegisterDefinition> selectedRegisters = new ArrayList<>();

	private Map<String, byte[]> ctx = new LinkedHashMap<>();
	private boolean hasCtx = false;

	public SctlTargetRegisters(SctlTargetThread thread) {
		super(thread.client, thread, "Registers", "RegisterBank");
		this.client = thread.client;

		changeAttributes(List.of(), Map.of( //
			// TODO: Probably have one container for the whole client
			DESCRIPTIONS_ATTRIBUTE_NAME, this //
		), "Initialized");
	}

	@Override
	public CompletableFuture<Void> requestElements(boolean refresh) {
		if (refresh) {
			lazyRegDescs.forget();
			lazyRegDefsById.forget();
			lazyRegDefs.forget();
		}
		return lazyRegDescs.request().thenApply(__ -> null);
	}

	@Override
	public CompletableFuture<? extends Map<String, byte[]>> readRegistersNamed(
			Collection<String> names) {
		parent.checkValid();
		return client.readRegisters(parent.ctlid);
	}

	@Override
	public CompletableFuture<Void> writeRegistersNamed(Map<String, byte[]> values) {
		parent.checkValid();
		return client.writeRegisters(parent.ctlid, values);
	}

	protected CompletableFuture<Void> selectRegisters(Set<SctlTargetRegisterDescription> descs) {
		// TODO: What if one of these is already executing?
		Set<String> curNames = new HashSet<>();
		Set<String> newNames = new HashSet<>();
		for (SctlRegisterDefinition def : selectedRegisters) {
			curNames.add(def.name.str);
		}
		for (TargetRegister<?> reg : descs) {
			newNames.add(reg.getName());
		}
		if (curNames.equals(newNames)) {
			return AsyncUtils.NIL;
		}
		return parent.process.client.chooseContext(parent.ctlid, descs);
	}

	protected CompletableFuture<Map<String, SctlRegisterDefinition>> doGetRegDefs() {
		return client.enumerateContext(parent.ctlid);
	}

	protected CompletableFuture<Map<Long, SctlRegisterDefinition>> doGetRegDefsById() {
		return lazyRegDefs.request().thenApply(this::reKeyDefsById);
	}

	protected Map<Long, SctlRegisterDefinition> reKeyDefsById(
			Map<String, SctlRegisterDefinition> defsByName) {
		Map<Long, SctlRegisterDefinition> result = new HashMap<>();
		for (SctlRegisterDefinition def : defsByName.values()) {
			result.put(def.regid, def);
		}
		return result;
	}

	protected CompletableFuture<Map<String, SctlTargetRegisterDescription>> doGetRegDescs() {
		return lazyRegDefs.request().thenApply(this::convertDefsToDescs);
	}

	protected Map<String, SctlTargetRegisterDescription> convertDefsToDescs(
			Map<String, SctlRegisterDefinition> defs) {
		Map<String, SctlTargetRegisterDescription> result = new LinkedHashMap<>();
		for (SctlRegisterDefinition def : defs.values()) {
			result.put(def.name.str,
				new SctlTargetRegisterDescription(this, def.name.str, (int) def.nbits));
		}
		changeElements(List.of(), result.values(), "Fetched");
		return result;
	}

	protected void updateContextIfPresent(AbstractSctlContext newCtx) {
		if (newCtx == null) {
			return;
		}
		newCtx.setSelectedRegisters(selectedRegisters);
		Map<String, byte[]> newAsMap = newCtx.toMap();
		Delta<byte[], byte[]> delta;
		synchronized (ctx) {
			delta = Delta.computeAndSet(ctx, newAsMap, Arrays::equals);
		}
		if (delta.added.isEmpty()) {
			return;
		}
		listeners.fire(TargetRegisterBankListener.class).registersUpdated(this, delta.added);
	}

	protected boolean hasContextSinceStop() {
		return hasCtx;
	}

	protected Map<String, byte[]> getContext() {
		synchronized (ctx) {
			return Map.copyOf(ctx);
		}
	}

	protected List<SctlRegisterDefinition> getSelectedRegisters() {
		return selectedRegisters;
	}

	protected void setSelectedRegisters(Collection<SctlRegisterDefinition> selectedRegisters) {
		if (!this.selectedRegisters.containsAll(selectedRegisters)) {
			this.hasCtx = false;
		}
		this.selectedRegisters.clear();
		this.selectedRegisters.addAll(selectedRegisters);
	}

	@Override
	public Map<String, byte[]> getCachedRegisters() {
		return getContext();
	}

	@Override
	public CompletableFuture<Void> invalidateCaches() {
		synchronized (ctx) {
			hasCtx = false;
			ctx.clear();
		}
		return super.invalidateCaches();
	}

	protected void invalidateCtx() {
		synchronized (ctx) {
			hasCtx = false;
			ctx.clear();
		}
		listeners.fire.invalidateCacheRequested(this);
	}
}
