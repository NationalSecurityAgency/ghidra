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

import com.sun.jdi.Method;

import ghidra.async.AsyncFence;
import ghidra.dbg.target.schema.*;
import ghidra.dbg.target.schema.TargetObjectSchema.ResyncMode;

@TargetObjectSchemaInfo(
	name = "TargetMethodContainer",
	elements = {
		@TargetElementType(type = JdiModelTargetMethod.class)
	},
	elementResync = ResyncMode.ONCE,
	attributes = {
		@TargetAttributeType(type = Void.class)
	},
	canonicalContainer = true)
public class JdiModelTargetMethodContainer extends JdiModelTargetObjectImpl {

	protected final JdiModelTargetReferenceType reftype;

	private final Map<String, JdiModelTargetMethod> methodsByName = new HashMap<>();
	private boolean useAll;

	public JdiModelTargetMethodContainer(JdiModelTargetReferenceType reftype, boolean all) {
		super(reftype, all ? "Methods (All)" : "Methods");
		this.reftype = reftype;
		this.useAll = all;
	}

	protected CompletableFuture<Void> updateUsingMethods(Map<String, Method> byName) {
		List<JdiModelTargetMethod> methods;
		synchronized (this) {
			methods =
				byName.values().stream().map(this::getTargetMethod).collect(Collectors.toList());
		}
		AsyncFence fence = new AsyncFence();
		for (JdiModelTargetMethod m : methods) {
			fence.include(m.init());
		}
		return fence.ready().thenAccept(__ -> {
			changeElements(List.of(), methods, Map.of(), "Refreshed");
		});
	}

	@Override
	protected CompletableFuture<Void> requestElements(boolean refresh) {
		Map<String, Method> map = new HashMap<>();
		List<Method> methods = useAll ? reftype.reftype.allMethods() : reftype.reftype.methods();
		for (Method var : methods) {
			map.put(var.name(), var);
		}
		getMethodsByName().keySet().retainAll(map.keySet());
		return updateUsingMethods(map);
	}

	protected synchronized JdiModelTargetMethod getTargetMethod(Method method) {
		return getMethodsByName().computeIfAbsent(method.name(),
			n -> (JdiModelTargetMethod) getInstance(method));
	}

	public synchronized JdiModelTargetMethod getTargetMethodIfPresent(String name) {
		return getMethodsByName().get(name);
	}

	@Override
	public CompletableFuture<Void> init() {
		AsyncFence fence = new AsyncFence();
		for (JdiModelTargetMethod method : methodsByName.values()) {
			fence.include(method.init());
		}
		return fence.ready();
	}

	public Map<String, JdiModelTargetMethod> getMethodsByName() {
		return methodsByName;
	}
}
