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
import java.util.stream.Collectors;

import org.apache.commons.lang3.tuple.Pair;

import agent.frida.model.iface1.FridaModelTargetConfigurable;
import agent.frida.model.iface2.*;
import ghidra.async.AsyncUtils;
import ghidra.dbg.DebuggerObjectModel.RefreshBehavior;
import ghidra.dbg.error.DebuggerIllegalArgumentException;
import ghidra.dbg.target.TargetConfigurable;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.schema.*;
import ghidra.dbg.target.schema.TargetObjectSchema.ResyncMode;
import ghidra.util.datastruct.WeakValueHashMap;

@TargetObjectSchemaInfo(
	name = "AvailableProcessesContainer",
	elements = {
		@TargetElementType(type = FridaModelTargetAvailableProcessImpl.class) //
	},
	elementResync = ResyncMode.ALWAYS,
	attributes = { //
		@TargetAttributeType(name = TargetConfigurable.BASE_ATTRIBUTE_NAME, type = Integer.class), //
		@TargetAttributeType(type = Void.class)  //
	},
	canonicalContainer = true)
public class FridaModelTargetAvailableProcessesContainerImpl extends FridaModelTargetObjectImpl
		implements FridaModelTargetAvailableProcessesContainer, FridaModelTargetConfigurable {

	protected final Map<String, FridaModelTargetAvailableProcess> attachablesById =
		new WeakValueHashMap<>();

	public FridaModelTargetAvailableProcessesContainerImpl(FridaModelTargetRoot root) {
		super(root.getModel(), root, "AvailableProcesses", "AvailableProcessContainer");
		this.changeAttributes(List.of(), Map.of(BASE_ATTRIBUTE_NAME, 16), "Initialized");
	}

	@Override
	public CompletableFuture<Void> requestElements(RefreshBehavior refresh) {
		return getManager().listAvailableProcesses().thenAccept(list -> {
			List<TargetObject> available;
			synchronized (this) {
				// NOTE: If more details added to entries, should clear attachablesById
				available =
					list.stream().map(this::getTargetAttachableEx).collect(Collectors.toList());
			}
			setElements(available, Map.of(), "Refreshed");
		});
	}

	public synchronized FridaModelTargetAvailableProcess getTargetAttachableEx(
			Pair<String, String> pair) {
		return attachablesById.computeIfAbsent(pair.getLeft(),
			i -> new FridaModelTargetAvailableProcessImpl(this, pair.getLeft(), pair.getRight()));
	}

	@Override
	public synchronized FridaModelTargetAvailableProcess getTargetAttachable(String pid) {
		return attachablesById.computeIfAbsent(pid,
			i -> new FridaModelTargetAvailableProcessImpl(this, pid));
	}

	@Override
	public CompletableFuture<Void> writeConfigurationOption(String key, Object value) {
		switch (key) {
			case BASE_ATTRIBUTE_NAME:
				if (value instanceof Integer) {
					this.changeAttributes(List.of(), Map.of(BASE_ATTRIBUTE_NAME, value),
						"Modified");
					for (FridaModelTargetAvailableProcess child : attachablesById.values()) {
						child.setBase(value);
					}
				}
				else {
					throw new DebuggerIllegalArgumentException("Base should be numeric");
				}
			default:
		}
		return AsyncUtils.NIL;
	}

}
