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
package ghidra.dbg.testutil;

import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.function.Predicate;
import java.util.stream.Collectors;

import ghidra.dbg.DebuggerModelListener;
import ghidra.dbg.DebuggerObjectModel;
import ghidra.dbg.target.TargetObject;

public class TargetObjectCreatedWaiter implements DebuggerModelListener {
	private final Map<List<String>, CompletableFuture<TargetObject>> pathBacklog = new HashMap<>();
	private final Map<Predicate<? super TargetObject>, CompletableFuture<Set<TargetObject>>> predBacklog =
		new HashMap<>();
	private final DebuggerObjectModel model;

	public TargetObjectCreatedWaiter(DebuggerObjectModel model) {
		this.model = model;
		model.addModelListener(this, false);
	}

	@Override
	public void created(TargetObject object) {
		CompletableFuture<TargetObject> cf;
		synchronized (pathBacklog) {
			cf = pathBacklog.remove(object.getPath());
		}
		if (cf != null) {
			cf.complete(object);
		}
		Map<Predicate<? super TargetObject>, CompletableFuture<Set<TargetObject>>> matched;
		synchronized (predBacklog) {
			matched = predBacklog.entrySet()
					.stream()
					.filter(e -> e.getKey().test(object))
					.collect(Collectors.toMap(e -> e.getKey(), e -> e.getValue()));
			predBacklog.keySet().removeAll(matched.keySet());
		}
		if (!matched.isEmpty()) {
			Set<TargetObject> result = Set.of(object);
			for (CompletableFuture<Set<TargetObject>> promise : matched.values()) {
				promise.complete(result);
			}
		}
	}

	public CompletableFuture<TargetObject> wait(List<String> path) {
		synchronized (pathBacklog) {
			TargetObject obj = model.getModelObject(path);
			if (obj != null) {
				return CompletableFuture.completedFuture(obj);
			}
			CompletableFuture<TargetObject> promise = new CompletableFuture<>();
			pathBacklog.put(path, promise);
			return promise;
		}
	}

	public CompletableFuture<Set<TargetObject>> waitAtLeastOne(
			Predicate<? super TargetObject> predicate) {
		synchronized (predBacklog) {
			Set<TargetObject> result = model.getModelObjects(predicate);
			if (!result.isEmpty()) {
				return CompletableFuture.completedFuture(result);
			}
			CompletableFuture<Set<TargetObject>> promise = new CompletableFuture<>();
			predBacklog.put(predicate, promise);
			return promise;
		}
	}
}
