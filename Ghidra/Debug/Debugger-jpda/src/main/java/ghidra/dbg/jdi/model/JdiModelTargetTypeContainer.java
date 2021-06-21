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

import com.sun.jdi.Type;

import ghidra.async.AsyncFence;
import ghidra.dbg.jdi.model.iface2.JdiModelTargetObject;
import ghidra.dbg.target.schema.*;
import ghidra.dbg.target.schema.TargetObjectSchema.ResyncMode;

@TargetObjectSchemaInfo(
	name = "TargetTypeContainer",
	elements = {
		@TargetElementType(type = JdiModelTargetType.class)
	},
	elementResync = ResyncMode.ONCE,
	attributes = {
		@TargetAttributeType(type = Void.class)
	},
	canonicalContainer = true)
public class JdiModelTargetTypeContainer extends JdiModelTargetObjectImpl {

	private List<Type> types;

	// TODO: Is it possible to load the same object twice?
	protected final Map<String, JdiModelTargetType> typesByName = new HashMap<>();

	public JdiModelTargetTypeContainer(JdiModelTargetObject parent, String name,
			List<Type> typeList) {
		super(parent, name);
		this.types = typeList;
	}

	protected CompletableFuture<Void> updateUsingTypes(Map<String, Type> byName) {
		List<JdiModelTargetType> vals;
		synchronized (this) {
			vals = byName.values().stream().map(this::getTargetType).collect(Collectors.toList());
		}
		AsyncFence fence = new AsyncFence();
		for (JdiModelTargetType val : vals) {
			fence.include(val.init());
		}
		return fence.ready().thenAccept(__ -> {
			changeElements(List.of(), vals, Map.of(), "Refreshed");
		});
	}

	@Override
	public CompletableFuture<Void> requestElements(boolean refresh) {
		Map<String, Type> map = new HashMap<>();
		try {
			for (Type type : types) {
				map.put(type.name(), type);
			}
			typesByName.keySet().retainAll(map.keySet());
		}
		catch (Exception e) {
			e.printStackTrace();
		}
		return updateUsingTypes(map);
	}

	protected synchronized JdiModelTargetType getTargetType(Type type) {
		return typesByName.computeIfAbsent(type.name(),
			n -> (JdiModelTargetType) getInstance(type));
	}

	public synchronized JdiModelTargetType getTargetTypeIfPresent(String name) {
		return typesByName.get(name);
	}
}
