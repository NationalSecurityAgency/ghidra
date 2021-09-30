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
package agent.lldb.model.impl;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

import org.apache.commons.lang3.tuple.Pair;

import agent.lldb.model.iface1.LldbModelTargetConfigurable;
import agent.lldb.model.iface2.LldbModelTargetAvailable;
import agent.lldb.model.iface2.LldbModelTargetAvailableContainer;
import agent.lldb.model.iface2.LldbModelTargetRoot;
import ghidra.async.AsyncUtils;
import ghidra.dbg.error.DebuggerIllegalArgumentException;
import ghidra.dbg.target.TargetConfigurable;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.dbg.target.schema.TargetElementType;
import ghidra.dbg.target.schema.TargetObjectSchema.ResyncMode;
import ghidra.dbg.target.schema.TargetObjectSchemaInfo;
import ghidra.util.datastruct.WeakValueHashMap;

@TargetObjectSchemaInfo(
	name = "AvailableContainer",
	elements = {
		@TargetElementType(type = LldbModelTargetAvailableImpl.class) //
	},
	elementResync = ResyncMode.ALWAYS,
	attributes = { //
		@TargetAttributeType(name = TargetConfigurable.BASE_ATTRIBUTE_NAME, type = Integer.class), //
		@TargetAttributeType(type = Void.class)  //
	},
	canonicalContainer = true)
public class LldbModelTargetAvailableContainerImpl extends LldbModelTargetObjectImpl
		implements LldbModelTargetAvailableContainer, LldbModelTargetConfigurable {

	protected final Map<String, LldbModelTargetAvailable> attachablesById =
		new WeakValueHashMap<>();

	public LldbModelTargetAvailableContainerImpl(LldbModelTargetRoot root) {
		super(root.getModel(), root, "Available", "AvailableContainer");
		this.changeAttributes(List.of(), Map.of(BASE_ATTRIBUTE_NAME, 16), "Initialized");
	}

	@Override
	public CompletableFuture<Void> requestElements(boolean refresh) {
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

	public synchronized LldbModelTargetAvailable getTargetAttachableEx(Pair<String, String> pair) {
		return attachablesById.computeIfAbsent(pair.getLeft(),
			i -> new LldbModelTargetAvailableImpl(this, pair.getLeft(), pair.getRight()));
	}

	@Override
	public synchronized LldbModelTargetAvailable getTargetAttachable(String pid) {
		return attachablesById.computeIfAbsent(pid,
			i -> new LldbModelTargetAvailableImpl(this, pid));
	}

	@Override
	public CompletableFuture<Void> writeConfigurationOption(String key, Object value) {
		switch (key) {
			case BASE_ATTRIBUTE_NAME:
				if (value instanceof Integer) {
					this.changeAttributes(List.of(), Map.of(BASE_ATTRIBUTE_NAME, value),
						"Modified");
					for (LldbModelTargetAvailable child : attachablesById.values()) {
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
