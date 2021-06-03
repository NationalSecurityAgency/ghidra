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
	public final Object cbLock = new Object();
	protected final ExecutorService clientExecutor =
		Executors.newSingleThreadExecutor(new BasicThreadFactory.Builder()
				.namingPattern(getClass().getSimpleName() + "-thread-%d")
				.build());
	protected final ListenerSet<DebuggerModelListener> listeners =
		new ListenerSet<>(DebuggerModelListener.class, clientExecutor);

	protected SpiTargetObject root;
	protected boolean rootAdded;
	protected boolean cbRootAdded;
	protected CompletableFuture<SpiTargetObject> completedRoot = new CompletableFuture<>();

	// Remember the order of creation events
	protected final Map<List<String>, SpiTargetObject> creationLog = new LinkedHashMap<>();
	protected final Map<List<String>, SpiTargetObject> cbCreationLog = new LinkedHashMap<>();

	protected void objectCreated(SpiTargetObject object) {
		synchronized (lock) {
			creationLog.put(object.getPath(), object);
			if (object.isRoot()) {
				if (this.root != null) {
					throw new IllegalStateException("Already have a root");
				}
				this.root = object;
			}
			CompletableFuture.runAsync(() -> {
				synchronized (cbLock) {
					cbCreationLog.put(object.getPath(), object);
				}
			}, clientExecutor).exceptionally(ex -> {
				Msg.error(this, "Error updating objectCreated before callback");
				return null;
			});
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
			CompletableFuture.runAsync(() -> {
				synchronized (cbLock) {
					cbRootAdded = true;
				}
				completedRoot.complete(root);
			}, clientExecutor).exceptionally(ex -> {
				Msg.error(this, "Error updating rootAdded before callback");
				return null;
			});
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

	protected void replayed(DebuggerModelListener listener, Runnable r) {
		try {
			r.run();
		}
		catch (Throwable t) {
			Msg.error(this, "Listener " + listener + " caused unexpected exception", t);
		}
	}

	protected void replayTreeEvents(DebuggerModelListener listener) {
		for (SpiTargetObject object : cbCreationLog.values()) {
			replayed(listener, () -> listener.created(object));
		}
		Set<SpiTargetObject> visited = new HashSet<>();
		for (SpiTargetObject object : cbCreationLog.values()) {
			replayAddEvents(listener, object, visited);
		}
		if (cbRootAdded) {
			replayed(listener, () -> listener.rootAdded(root));
		}
	}

	protected void replayAddEvents(DebuggerModelListener listener, SpiTargetObject object,
			Set<SpiTargetObject> visited) {
		if (!visited.add(object)) {
			return;
		}
		/**
		 * It's rare, but technically, the creation is logged during construction, so cbAttributes
		 * and/or cbElements could still be null.
		 */
		Map<String, ?> cbAttributes = object.getCallbackAttributes();
		if (cbAttributes != null) {
			for (Object val : cbAttributes.values()) {
				if (!(val instanceof TargetObject)) {
					continue;
				}
				assert val instanceof SpiTargetObject;
				replayAddEvents(listener, (SpiTargetObject) val, visited);
			}
			if (!cbAttributes.isEmpty()) {
				replayed(listener,
					() -> listener.attributesChanged(object, List.of(), Map.copyOf(cbAttributes)));
			}
		}
		Map<String, ? extends TargetObject> cbElements = object.getCallbackElements();
		if (cbElements != null) {
			for (TargetObject elem : cbElements.values()) {
				assert elem instanceof SpiTargetObject;
				replayAddEvents(listener, (SpiTargetObject) elem, visited);
			}
			if (!cbElements.isEmpty()) {
				replayed(listener,
					() -> listener.elementsChanged(object, List.of(), Map.copyOf(cbElements)));
			}
		}
	}

	@Override
	public void addModelListener(DebuggerModelListener listener, boolean replay) {
		synchronized (lock) {
			if (replay) {
				CompletableFuture.runAsync(() -> {
					synchronized (cbLock) {
						replayTreeEvents(listener);
						listeners.add(listener);
					}
				}, clientExecutor).exceptionally(ex -> {
					listener.catastrophic(ex);
					return null;
				});
			}
			else {
				listeners.add(listener);
			}
		}
	}

	@Override
	public void removeModelListener(DebuggerModelListener listener) {
		// NB. Don't really care to lock here. Only making guarantees re/ adds,replays.
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

	@Override
	public CompletableFuture<Void> close() {
		clientExecutor.shutdown();
		return AsyncUtils.NIL;
	}

	public void removeExisting(List<String> path) {
		TargetObject existing = getModelObject(path);
		// It's best if the implementation has already removed it, but just in case....
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
		if (!(parent instanceof SpiTargetObject)) { // It had better be
			Msg.error(this, "Could not remove existing object " + existing +
				", because parent is not an SpiTargetObject");
			return;
		}
		SpiTargetObject spiParent = (SpiTargetObject) parent;
		SpiTargetObject delegate = spiParent.getDelegate();
		if (!(delegate instanceof DefaultTargetObject<?, ?>)) { // It had better be :)
			Msg.error(this, "Could not remove existing object " + existing +
				", because its parent's delegate is not a DefaultTargetObject");
			return;
		}
		DefaultTargetObject<?, ?> dtoParent = (DefaultTargetObject<?, ?>) delegate;
		if (PathUtils.isIndex(path)) {
			dtoParent.changeElements(List.of(PathUtils.getIndex(path)), List.of(),
				"Replaced");
		}
		else {
			assert PathUtils.isName(path);
			dtoParent.changeAttributes(List.of(PathUtils.getKey(path)), Map.of(),
				"Replaced");
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
