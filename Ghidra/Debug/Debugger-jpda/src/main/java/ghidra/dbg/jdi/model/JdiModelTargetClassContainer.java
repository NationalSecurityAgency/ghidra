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

import com.sun.jdi.ReferenceType;

import ghidra.async.AsyncFence;
import ghidra.async.AsyncUtils;
import ghidra.dbg.target.schema.*;
import ghidra.util.Msg;

@TargetObjectSchemaInfo(
	name = "ClassContainer",
	elements = {
		@TargetElementType(type = JdiModelTargetReferenceType.class)
	},
	attributes = {
		@TargetAttributeType(type = Void.class)
	},
	canonicalContainer = true)
public class JdiModelTargetClassContainer extends JdiModelTargetObjectImpl {

	protected final JdiModelTargetVM vm;

	// TODO: Is it possible to load the same object twice?
	private final Map<String, JdiModelTargetReferenceType> classesByName = new HashMap<>();

	public JdiModelTargetClassContainer(JdiModelTargetVM vm) {
		super(vm, "Classes");
		this.vm = vm;

		requestElements(true);
	}

	protected CompletableFuture<Void> updateUsingClasses(Map<String, ReferenceType> byName) {
		List<JdiModelTargetReferenceType> classes;
		synchronized (this) {
			classes =
				byName.values().stream().map(this::getTargetClass).collect(Collectors.toList());
		}
		AsyncFence fence = new AsyncFence();
		for (JdiModelTargetReferenceType c : classes) {
			fence.include(c.init());
		}
		return fence.ready().thenAccept(__ -> {
			changeElements(List.of(), classes, Map.of(), "Refreshed");
		});
	}

	@Override
	protected CompletableFuture<Void> requestElements(boolean refresh) {
		// Ignore 'refresh' because inferior.getKnownModules may exclude executable
		return doRefresh();
	}

	protected CompletableFuture<Void> doRefresh() {
		Map<String, ReferenceType> map = new HashMap<>();
		List<ReferenceType> allClasses = vm.vm.allClasses();
		for (ReferenceType ref : allClasses) {
			map.put(ref.name(), ref);
		}
		getClassesByName().keySet().retainAll(map.keySet());
		return updateUsingClasses(map);
	}

	protected synchronized JdiModelTargetReferenceType getTargetClass(ReferenceType reftype) {
		return getClassesByName().computeIfAbsent(reftype.name(),
			n -> (JdiModelTargetReferenceType) getInstance(reftype));
	}

	public synchronized JdiModelTargetReferenceType getTargetModuleIfPresent(String name) {
		return getClassesByName().get(name);
	}

	public CompletableFuture<?> refreshInternal() {
		if (!isObserved()) {
			return AsyncUtils.NIL;
		}
		return doRefresh().exceptionally(ex -> {
			Msg.error(this, "Problem refreshing vm's classes", ex);
			return null;
		});
	}

	public Map<String, JdiModelTargetReferenceType> getClassesByName() {
		return classesByName;
	}
}
