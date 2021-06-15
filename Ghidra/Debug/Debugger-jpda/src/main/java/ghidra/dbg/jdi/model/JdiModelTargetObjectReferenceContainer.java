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

import com.sun.jdi.ObjectReference;

import ghidra.async.AsyncFence;
import ghidra.dbg.jdi.model.iface2.JdiModelTargetObject;
import ghidra.dbg.target.schema.*;
import ghidra.dbg.target.schema.TargetObjectSchema.ResyncMode;

@TargetObjectSchemaInfo(
	name = "TargetObjectReferenceContainer",
	elements = {
		@TargetElementType(type = JdiModelTargetObjectReference.class)
	},
	elementResync = ResyncMode.ONCE,
	attributes = {
		@TargetAttributeType(type = Void.class)
	},
	canonicalContainer = true)
public class JdiModelTargetObjectReferenceContainer extends JdiModelTargetObjectImpl {

	protected final List<ObjectReference> refs;

	// TODO: Is it possible to load the same object twice?
	protected final Map<String, JdiModelTargetObjectReference> objectsByName = new HashMap<>();

	public JdiModelTargetObjectReferenceContainer(JdiModelTargetObject parent, String name,
			List<ObjectReference> refs) {
		super(parent, name);
		this.refs = refs;
	}

	protected CompletableFuture<Void> updateUsingReferences(Map<String, ObjectReference> byName) {
		Map<String, JdiModelTargetObjectReference> objects;
		synchronized (this) {
			objects = byName.entrySet()
					.stream()
					.collect(Collectors.toMap(e -> e.getKey(), e -> getTargetObject(e.getValue())));
		}
		AsyncFence fence = new AsyncFence();
		for (JdiModelTargetObjectReference m : objects.values()) {
			fence.include(m.init());
		}
		return fence.ready().thenAccept(__ -> {
			changeElements(List.of(), List.of(), objects, "Refreshed");
		});
	}

	@Override
	public CompletableFuture<Void> requestElements(boolean refresh) {
		Map<String, ObjectReference> map = new HashMap<>();
		for (ObjectReference ref : refs) {
			map.put(ref.toString(), ref);
		}
		objectsByName.keySet().retainAll(map.keySet());
		return updateUsingReferences(map);
	}

	protected synchronized JdiModelTargetObjectReference getTargetObject(ObjectReference ref) {
		return objectsByName.computeIfAbsent(ref.toString(),
			n -> (JdiModelTargetObjectReference) getInstance(ref));
	}

	public synchronized JdiModelTargetObjectReference getTargetObjectIfPresent(String name) {
		return objectsByName.get(name);
	}
}
