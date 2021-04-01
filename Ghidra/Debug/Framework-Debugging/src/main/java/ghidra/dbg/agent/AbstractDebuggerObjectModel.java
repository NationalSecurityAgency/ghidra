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
package ghidra.dbg.agent;

import java.util.*;
import java.util.concurrent.*;
import java.util.function.Predicate;
import java.util.stream.Collectors;

import org.apache.commons.lang3.concurrent.BasicThreadFactory;

import ghidra.async.AsyncUtils;
import ghidra.dbg.DebuggerModelListener;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.util.PathUtils;
import ghidra.util.Msg;
import ghidra.util.datastruct.ListenerSet;

public abstract class AbstractDebuggerObjectModel implements SpiDebuggerObjectModel {
	public final Object lock = new Object();
	protected final ExecutorService clientExecutor =
		Executors.newSingleThreadExecutor(new BasicThreadFactory.Builder()
				.namingPattern(getClass().getSimpleName() + "-thread-%d")
				.build());
	protected final ListenerSet<DebuggerModelListener> listeners =
		new ListenerSet<>(DebuggerModelListener.class, clientExecutor);

	protected SpiTargetObject root;
	protected boolean rootAdded;
	protected CompletableFuture<SpiTargetObject> completedRoot = new CompletableFuture<>();

	// Remember the order of creation events
	protected final Map<List<String>, SpiTargetObject> creationLog = new LinkedHashMap<>();

	protected void objectCreated(SpiTargetObject object) {
		synchronized (lock) {
			creationLog.put(object.getPath(), object);
			if (object.isRoot()) {
				if (this.root != null) {
					throw new IllegalStateException("Already have a root");
				}
				this.root = object;
			}
		}
	}

	protected void objectInvalidated(TargetObject object) {
		creationLog.remove(object.getPath());
	}

	protected void addModelRoot(SpiTargetObject root) {
		assert root == this.root;
		synchronized (lock) {
			rootAdded = true;
			root.getSchema()
					.validateTypeAndInterfaces(root, null, null, root.enforcesStrictSchema());
			this.completedRoot.completeAsync(() -> root, clientExecutor);
			listeners.fire.rootAdded(root);
		}
	}

	@Override
	public CompletableFuture<? extends TargetObject> fetchModelRoot() {
		return completedRoot;
	}

	@Override
	public SpiTargetObject getModelRoot() {
		synchronized (lock) {
			return root;
		}
	}

	protected void onClientExecutor(DebuggerModelListener listener, Runnable r) {
		CompletableFuture.runAsync(r, clientExecutor).exceptionally(t -> {
			Msg.error(this, "Listener " + listener + " caused unexpected exception", t);
			return null;
		});
	}

	protected void replayTreeEvents(DebuggerModelListener listener) {
		if (root == null) {
			assert creationLog.isEmpty();
			return;
		}
		for (SpiTargetObject object : creationLog.values()) {
			onClientExecutor(listener, () -> listener.created(object));
		}
		Set<SpiTargetObject> visited = new HashSet<>();
		for (SpiTargetObject object : creationLog.values()) {
			replayAddEvents(listener, object, visited);
		}
		if (rootAdded) {
			onClientExecutor(listener, () -> listener.rootAdded(root));
		}
	}

	protected void replayAddEvents(DebuggerModelListener listener, SpiTargetObject object,
			Set<SpiTargetObject> visited) {
		if (!visited.add(object)) {
			return;
		}
		Map<String, ?> cachedAttributes = object.getCachedAttributes();
		for (Object val : cachedAttributes.values()) {
			if (!(val instanceof TargetObject)) {
				continue;
			}
			assert val instanceof SpiTargetObject;
			replayAddEvents(listener, (SpiTargetObject) val, visited);
		}
		if (!cachedAttributes.isEmpty()) {
			onClientExecutor(listener,
				() -> listener.attributesChanged(object, List.of(), cachedAttributes));
		}
		Map<String, ? extends TargetObject> cachedElements = object.getCachedElements();
		for (TargetObject elem : cachedElements.values()) {
			assert elem instanceof SpiTargetObject;
			replayAddEvents(listener, (SpiTargetObject) elem, visited);
		}
		if (!cachedElements.isEmpty()) {
			onClientExecutor(listener,
				() -> listener.elementsChanged(object, List.of(), cachedElements));
		}
	}

	@Override
	public void addModelListener(DebuggerModelListener listener, boolean replay) {
		try {
			synchronized (lock) {
				if (replay) {
					replayTreeEvents(listener);
				}
				listeners.add(listener);
			}
		}
		catch (Throwable ex) {
			listener.catastrophic(ex);
		}
	}

	@Override
	public void removeModelListener(DebuggerModelListener listener) {
		listeners.remove(listener);
	}

	/**
	 * Ensure that dependent computations occur on the client executor
	 * 
	 * @param <T> the type of the future value
	 * @param v the future
	 * @return a future which completes after the given one on the client executor
	 */
	public <T> CompletableFuture<T> gateFuture(CompletableFuture<T> future) {
		return future.whenCompleteAsync((t, ex) -> {
		}, clientExecutor);
	}

	@Override
	public CompletableFuture<Void> flushEvents() {
		return CompletableFuture.supplyAsync(() -> null, clientExecutor);
	}

	/*
	@Override
	public CompletableFuture<Void> flushEvents() {
		return gateFuture(null);
		//return CompletableFuture.supplyAsync(() -> gateFuture((Void) null)).thenCompose(f -> f);
	}
	*/

	@Override
	public CompletableFuture<Void> close() {
		clientExecutor.shutdown();
		return AsyncUtils.NIL;
	}

	public void removeExisting(List<String> path) {
		TargetObject existing = getModelObject(path);
		// It had better be. This also checks for null
		if (existing == null) {
			return;
		}
		TargetObject parent = existing.getParent();
		if (parent == null) {
			assert existing == root;
			throw new IllegalStateException("Cannot replace the root");
		}
		if (!path.equals(existing.getPath())) {
			return; // Is a link
		}
		if (parent instanceof DefaultTargetObject<?, ?>) { // It had better be
			DefaultTargetObject<?, ?> dtoParent = (DefaultTargetObject<?, ?>) parent;
			if (PathUtils.isIndex(path)) {
				dtoParent.changeElements(List.of(PathUtils.getIndex(path)), List.of(), "Replaced");
			}
			else {
				assert PathUtils.isName(path);
				dtoParent.changeAttributes(List.of(PathUtils.getKey(path)), Map.of(), "Replaced");
			}
		}
	}

	@Override
	public TargetObject getModelObject(List<String> path) {
		synchronized (lock) {
			if (path.isEmpty()) {
				return root;
			}
			return creationLog.get(path);
		}
	}

	@Override
	public Set<TargetObject> getModelObjects(Predicate<? super TargetObject> predicate) {
		synchronized (lock) {
			return creationLog.values().stream().filter(predicate).collect(Collectors.toSet());
		}
	}
}
