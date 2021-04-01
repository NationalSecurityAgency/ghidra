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
package agent.dbgmodel.model.impl;

import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

import org.apache.commons.lang3.tuple.Pair;

import agent.dbgeng.model.iface2.*;
import ghidra.dbg.target.TargetObject;
import ghidra.util.datastruct.WeakValueHashMap;

public class DbgModel2TargetAvailableContainerImpl extends DbgModel2TargetObjectImpl
		implements DbgModelTargetAvailableContainer {

	protected final Map<Integer, DbgModelTargetAvailable> attachablesById =
		new WeakValueHashMap<>();

	public DbgModel2TargetAvailableContainerImpl(DbgModelTargetObject obj) {
		super(obj.getModel(), obj, "Available", "AvailableContainer");
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

	@Override
	public CompletableFuture<Void> requestAttributes(boolean refresh) {
		Map<String, Object> nmap = new HashMap<>();
		return addModelObjectAttributes(nmap);
	}

	public synchronized DbgModelTargetAvailable getTargetAttachableEx(Pair<Integer, String> pair) {
		return attachablesById.computeIfAbsent(pair.getLeft(),
			i -> new DbgModel2TargetAvailableImpl(this, pair.getLeft(), pair.getRight()));
	}

	@Override
	public synchronized DbgModelTargetAvailable getTargetAttachable(int pid) {
		return attachablesById.computeIfAbsent(pid,
			i -> new DbgModel2TargetAvailableImpl(this, pid));
	}

}
