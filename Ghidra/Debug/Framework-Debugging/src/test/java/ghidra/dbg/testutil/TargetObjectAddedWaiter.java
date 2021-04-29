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
import java.util.Map.Entry;
import java.util.concurrent.CompletableFuture;

import ghidra.dbg.DebuggerModelListener;
import ghidra.dbg.DebuggerObjectModel;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.util.*;

public class TargetObjectAddedWaiter
		implements DebuggerModelListener, DebuggerModelTestUtils, AutoCloseable {
	private final DebuggerCallbackReorderer reorderer = new DebuggerCallbackReorderer(this);
	private final Map<List<String>, CompletableFuture<Object>> pathBacklog = new HashMap<>();
	private final Map<PathPredicates, CompletableFuture<NavigableMap<List<String>, ?>>> predBacklog =
		new HashMap<>();
	private final DebuggerObjectModel model;

	public TargetObjectAddedWaiter(DebuggerObjectModel model) {
		this.model = model;
		model.addModelListener(reorderer, true);
	}

	@Override
	public void close() throws Exception {
		model.removeModelListener(reorderer);
	}

	protected void retryBacklogs() {
		synchronized (predBacklog) {
			// NB. getModelRoot() can be non-null before rootAdded. Use fetch.getNow instead.
			TargetObject root = model.fetchModelRoot().getNow(null);
			if (root != null) {
				for (Iterator<Entry<PathPredicates, CompletableFuture<NavigableMap<List<String>, ?>>>> it =
					predBacklog.entrySet().iterator(); it.hasNext();) {
					Entry<PathPredicates, CompletableFuture<NavigableMap<List<String>, ?>>> ent =
						it.next();
					NavigableMap<List<String>, ?> values = ent.getKey().getCachedValues(root);
					if (!values.isEmpty()) {
						// NB. This is completed with a lock, but tests should just use waitOn
						ent.getValue().complete(values);
						it.remove();
					}
				}
			}
		}
	}

	@Override
	public void rootAdded(TargetObject root) {
		retryBacklogs();
	}

	@Override
	public void attributesChanged(TargetObject object, Collection<String> removed,
			Map<String, ?> added) {
		for (Entry<String, ?> ent : added.entrySet()) {
			List<String> attrPath = PathUtils.extend(object.getPath(), ent.getKey());
			CompletableFuture<Object> cf = pathBacklog.remove(attrPath);
			if (cf != null) {
				cf.complete(ent.getValue());
			}
		}
		retryBacklogs();
	}

	@Override
	public void elementsChanged(TargetObject object, Collection<String> removed,
			Map<String, ? extends TargetObject> added) {
		for (Entry<String, ?> ent : added.entrySet()) {
			List<String> elemPath = PathUtils.index(object.getPath(), ent.getKey());
			CompletableFuture<Object> cf = pathBacklog.remove(elemPath);
			if (cf != null) {
				cf.complete(ent.getValue());
			}
		}
		retryBacklogs();
	}

	public CompletableFuture<?> wait(List<String> path) {
		Objects.requireNonNull(path);
		synchronized (pathBacklog) {
			Object val = model.getModelValue(path);
			if (val != null) {
				return CompletableFuture.completedFuture(val);
			}
			CompletableFuture<Object> promise = new CompletableFuture<>();
			pathBacklog.put(path, promise);
			return promise;
		}
	}

	public CompletableFuture<NavigableMap<List<String>, ?>> waitAtLeastOne(
			PathPredicates predicates) {
		synchronized (predBacklog) {
			TargetObject root = model.getModelRoot();
			if (root != null) {
				NavigableMap<List<String>, ?> result = predicates.getCachedValues(root);
				if (!result.isEmpty()) {
					return CompletableFuture.completedFuture(result);
				}
			}
			CompletableFuture<NavigableMap<List<String>, ?>> promise = new CompletableFuture<>();
			predBacklog.put(predicates, promise);
			return promise;
		}
	}
}
