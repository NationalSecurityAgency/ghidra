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
package ghidra.dbg;

import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

import ghidra.async.*;
import ghidra.dbg.target.*;
import ghidra.dbg.target.TargetExecutionStateful.TargetExecutionState;
import ghidra.dbg.target.schema.TargetObjectSchema;
import ghidra.dbg.util.PathPredicates;
import ghidra.dbg.util.PathUtils;
import ghidra.dbg.util.PathUtils.PathComparator;
import ghidra.util.Msg;
import ghidra.util.Swing;

public enum DebugModelConventions {
	;

	protected static CompletableFuture<Void> runNotInSwing(Object originator, Runnable runnable,
			String cbName) {
		if (Swing.isSwingThread()) {
			return CompletableFuture.runAsync(runnable).exceptionally(e -> {
				Msg.error(originator, "Error in " + cbName, e);
				return null;
			});
		}
		try {
			runnable.run();
		}
		catch (Throwable e) {
			Msg.error(originator, "Error in " + cbName, e);
		}
		return AsyncUtils.NIL;
	}

	/**
	 * Search for a suitable object implementing the given interface, starting at a given seed.
	 * 
	 * <p>
	 * This performs an n-up-1-down search starting at the given seed, seeking an object which
	 * implements the given interface. The 1-down part is only applied from objects implementing
	 * {@link TargetAggregate}. See {@link TargetObject} for the specifics of expected model
	 * conventions.
	 * 
	 * <p>
	 * Note that many a debugger target object interface type require a self-referential {@code T}
	 * parameter referring to the implementing class type. To avoid referring to a particular
	 * implementation, it becomes necessary to leave {@code T} as {@code ?}, but that can never
	 * satisfy the constraints of this method. To work around this, such interfaces must provide a
	 * static {@code tclass} field, which can properly satisfy the type constraints of this method
	 * for such self-referential type variables. The returned value must be ascribed to the
	 * wild-carded type, because the work-around involves a hidden class. Perhaps a little verbose
	 * (hey, it's Java!), the following is the recommended pattern, e.g., to discover the
	 * environment of a given process:
	 * 
	 * <pre>
	 * CompletableFuture<? extends TargetEnvironment<?>> futureEnv =
	 * 	DebugModelConventions.findSuitable(TargetEnvironment.tclass, aProcess);
	 * </pre>
	 * 
	 * @param <T> the desired interface type.
	 * @param iface the (probably {@code tclass}) of the desired interface type
	 * @param seed the starting object
	 * @return a future which completes with the discovered object or completes with null, if not
	 *         found.
	 * @deprecated use {@link #suitable(Class, TargetObject)} instead
	 */
	@Deprecated(forRemoval = true)
	public static <T extends TargetObject> CompletableFuture<T> findSuitable(Class<T> iface,
			TargetObject seed) {
		if (iface.isAssignableFrom(seed.getClass())) {
			return CompletableFuture.completedFuture(iface.cast(seed));
		}
		if (seed instanceof TargetAggregate) {
			return findInAggregate(iface, seed).thenCompose(agg -> {
				if (agg.size() == 1) {
					return CompletableFuture.completedFuture(agg.iterator().next());
				}
				return findParentSuitable(iface, seed);
			});
		}
		return findParentSuitable(iface, seed);
	}

	/**
	 * Search for a suitable object implementing the given interface, starting at a given seed.
	 * 
	 * <p>
	 * This performs an n-up-m-down search starting at the given seed, seeking an object which
	 * implements the given interface. The m-down part is only applied from objects implementing
	 * {@link TargetAggregate}. See {@link TargetObject} for the specifics of expected model
	 * conventions.
	 * 
	 * <p>
	 * Note that many a debugger target object interface type require a self-referential {@code T}
	 * parameter referring to the implementing class type. To avoid referring to a particular
	 * implementation, it becomes necessary to leave {@code T} as {@code ?}, but that can never
	 * satisfy the constraints of this method. To work around this, such interfaces must provide a
	 * static {@code tclass} field, which can properly satisfy the type constraints of this method
	 * for such self-referential type variables. The returned value must be ascribed to the
	 * wild-carded type, because the work-around involves a hidden class. Perhaps a little verbose
	 * (hey, it's Java!), the following is the recommended pattern, e.g., to discover the
	 * environment of a given process:
	 * 
	 * <pre>
	 * CompletableFuture<? extends TargetEnvironment<?>> futureEnv =
	 * 	DebugModelConventions.suitable(TargetEnvironment.tclass, aProcess);
	 * </pre>
	 * 
	 * @param <T> the desired interface type.
	 * @param iface the (probably {@code tclass}) of the desired interface type
	 * @param seed the starting object
	 * @return a future which completes with the discovered object or completes with null, if not
	 *         found.
	 */
	public static <T extends TargetObject> CompletableFuture<T> suitable(Class<T> iface,
			TargetObject seed) {
		List<String> path =
			seed.getModel().getRootSchema().searchForSuitable(iface, seed.getPath());
		if (path == null) {
			return null;
		}
		return seed.getModel().fetchModelObject(path).thenApply(obj -> iface.cast(obj));
	}

	public static <T extends TargetObject> T ancestor(Class<T> iface, TargetObject seed) {
		List<String> path =
			seed.getModel().getRootSchema().searchForAncestor(iface, seed.getPath());
		if (path == null) {
			return null;
		}
		return iface.cast(seed.getModel().getModelObject(path));
	}

	private static <T extends TargetObject> CompletableFuture<T> findParentSuitable(Class<T> iface,
			TargetObject obj) {
		TargetObject parent = obj.getParent();
		if (parent == null) {
			return AsyncUtils.nil();
		}
		return findSuitable(iface, parent);
	}

	/**
	 * Search for an object implementing the given interface among itself and its attributes.
	 * 
	 * <p>
	 * This method descends into the attributes of objects which implement the
	 * {@link TargetAggregate} interface. All found objects will comes from the same "level" in the
	 * tree, the algorithm terminating as soon as it finds a level with at least one object having
	 * the interface. When it terminates, all such objects at that level will be included. The
	 * resulting collection is in no particular order.
	 * 
	 * @param <T> the desired interface type.
	 * @param iface the (probably {@code tclass}) of the desired interface type
	 * @param seed the starting object
	 * @return a future which completes with the, possibly empty, collection of discovered objects
	 */
	public static <T extends TargetObject> CompletableFuture<Collection<T>> findInAggregate(
			Class<T> iface, TargetObject seed) {
		return findInAggregate(iface, Set.of(seed));
	}

	/**
	 * Search for an object implementing the given interface among those given and their attributes.
	 * 
	 * <p>
	 * All seeds should be at the same "level", or else the result is not well defined.
	 * 
	 * @see #findInAggregate(Class, TargetObject)
	 */
	public static <T extends TargetObject> CompletableFuture<Collection<T>> findInAggregate(
			Class<T> iface, Collection<? extends TargetObject> seeds) {
		if (seeds.isEmpty()) {
			return CompletableFuture.completedFuture(Set.of());
		}
		Set<T> result = seeds.stream()
				.filter(obj -> iface.isAssignableFrom(obj.getClass()))
				.map(obj -> iface.cast(obj))
				.collect(Collectors.toSet());
		if (!result.isEmpty()) {
			return CompletableFuture.completedFuture(result);
		}
		AsyncFence fence = new AsyncFence();
		Set<TargetObject> nextLevel = new HashSet<>();
		for (TargetObject seed : seeds) {
			if (!(seed instanceof TargetAggregate)) {
				continue;
			}
			fence.include(seed.fetchAttributes().thenAccept(attributes -> {
				synchronized (nextLevel) {
					for (Map.Entry<String, ?> ent : attributes.entrySet()) {
						Object val = ent.getValue();
						if (!(val instanceof TargetObject)) {
							continue;
						}
						TargetObject obj = (TargetObject) val;
						if (PathUtils.isLink(seed.getPath(), ent.getKey(), obj.getPath())) {
							// TODO: Resolve links? Must ensure I don't re-visit anyone
							continue;
						}
						nextLevel.add(obj);
					}
				}
			}));
		}
		return fence.ready().thenCompose(__ -> findInAggregate(iface, nextLevel));
	}

	public abstract static class AncestorTraversal<T> extends CompletableFuture<T> {
		public enum Result {
			FOUND, CONTINUE, TERMINATE;
		}

		protected TargetObject cur;

		public AncestorTraversal(TargetObject successor) {
			cur = successor;
		}

		protected abstract Result check(TargetObject obj);

		protected abstract T finish(TargetObject obj);

		public AncestorTraversal<T> start() {
			try {
				next(cur);
			}
			catch (Throwable ex) {
				completeExceptionally(ex);
			}
			return this;
		}

		protected void next(TargetObject ancestor) {
			cur = ancestor;
			if (cur == null) {
				complete(null);
				return;
			}
			switch (check(cur)) {
				case FOUND:
					complete(finish(cur));
					return;
				case CONTINUE:
					next(cur.getParent());
					return;
				case TERMINATE:
					complete(null);
					return;
			}
		}

		protected Void exc(Throwable ex) {
			completeExceptionally(ex);
			return null;
		}
	}

	/**
	 * Find the nearest ancestor which implements the given interface.
	 * 
	 * <p>
	 * This is similar to {@link #findSuitable(Class, TargetObject)}, except without the 1-down
	 * rule.
	 * 
	 * @param <T> the type of the required interface
	 * @param iface the (probably {@code tclass}) for the required interface
	 * @param successor the seed object
	 * @return a future which completes with the found object or completes with null if not found.
	 */
	public static <T extends TargetObject> CompletableFuture<T> nearestAncestor(Class<T> iface,
			TargetObject successor) {
		return new AncestorTraversal<T>(successor) {
			@Override
			protected Result check(TargetObject obj) {
				if (iface.isAssignableFrom(obj.getClass())) {
					return Result.FOUND;
				}
				return Result.CONTINUE;
			}

			@Override
			protected T finish(TargetObject obj) {
				return iface.cast(obj);
			}
		}.start();
	}

	/**
	 * Collect all ancestors (including seed) supporting the given interface
	 * 
	 * @param <T> the type of interface
	 * @param seed the starting point
	 * @param iface the class of the interface
	 * @return the collection of ancestors supporting the interface
	 */
	public static <T extends TargetObject> CompletableFuture<Collection<T>> collectAncestors(
			TargetObject seed, Class<T> iface) {
		DebuggerObjectModel model = seed.getModel();
		List<T> result = new ArrayList<>(seed.getPath().size() + 1);
		AsyncFence fence = new AsyncFence();
		for (List<String> path = seed.getPath(); path != null; path = PathUtils.parent(path)) {
			fence.include(model.fetchModelObject(path).thenAccept(obj -> {
				if (iface.isAssignableFrom(obj.getClass())) {
					result.add(iface.cast(obj));
				}
			}));
		}
		return fence.ready().thenApply(__ -> {
			result.sort(Comparator.comparing(o -> o.getPath().size()));
			return result;
		});
	}

	/**
	 * Collect all successors (including seed) that are elements supporting the given interface.
	 * 
	 * @param <T> the type of interface
	 * @param seed the starting point (root of subtree to inspect)
	 * @param iface the class of the interface
	 * @return the collection of successor elements supporting the interface
	 * @deprecated use {@link TargetObjectSchema#searchFor(Class, boolean)} and
	 *             {@link PathPredicates#collectSuccessorRefs(TargetObject)} instead.
	 */
	// TODO: Test this method
	@Deprecated(forRemoval = true)
	public static <T extends TargetObject> CompletableFuture<Collection<T>> collectSuccessors(
			TargetObject seed, Class<T> iface) {
		Collection<T> result =
			new TreeSet<>(Comparator.comparing(TargetObject::getPath, PathComparator.KEYED));
		AsyncFence fence = new AsyncFence();
		fence.include(seed.fetchElements().thenCompose(elements -> {
			AsyncFence elemFence = new AsyncFence();
			synchronized (result) {
				for (TargetObject e : elements.values()) {
					if (iface.isInstance(e)) {
						result.add(iface.cast(e));
						continue;
					}
					elemFence.include(collectSuccessors(e, iface).thenAccept(sub -> {
						synchronized (result) {
							result.addAll(sub);
						}
					}));
				}
			}
			return elemFence.ready();
		}));
		fence.include(seed.fetchAttributes().thenCompose(attributes -> {
			AsyncFence attrFence = new AsyncFence();
			synchronized (result) {
				for (Map.Entry<String, ?> ent : attributes.entrySet()) {
					Object val = ent.getValue();
					if (!(val instanceof TargetObject)) {
						continue;
					}
					TargetObject a = (TargetObject) val;
					if (PathUtils.isLink(seed.getPath(), ent.getKey(), a.getPath())) {
						continue;
					}
					if (iface.isInstance(a)) {
						result.add(iface.cast(a));
						continue;
					}
					attrFence.include(collectSuccessors(a, iface).thenAccept(sub -> {
						synchronized (result) {
							result.addAll(sub);
						}
					}));
				}
			}
			return attrFence.ready();
		}));
		return fence.ready().thenApply(__ -> {
			return result;
		});
	}

	/**
	 * Find the nearest ancestor thread
	 * 
	 * @param successor the seed object
	 * @return a future which completes with the found thread or completes with {@code null}.
	 */
	public static CompletableFuture<TargetThread> findThread(TargetObject successor) {
		return new AncestorTraversal<TargetThread>(successor) {
			@Override
			protected Result check(TargetObject obj) {
				if (obj.isRoot()) {
					return Result.TERMINATE;
				}
				if (obj instanceof TargetThread) {
					return Result.FOUND;
				}
				return Result.CONTINUE;
			}

			@Override
			protected TargetThread finish(TargetObject obj) {
				return (TargetThread) obj;
			}
		}.start();
	}

	/**
	 * Check if the given process is alive
	 * 
	 * @param process the process
	 * @return true if alive
	 */
	public static boolean isProcessAlive(TargetProcess process) {
		if (!process.isValid()) {
			return false;
		}
		if (!(process instanceof TargetExecutionStateful)) {
			return true;
		}
		TargetExecutionStateful exe = (TargetExecutionStateful) process;
		TargetExecutionState state = exe.getExecutionState();
		if (state == null) {
			Msg.trace(null, "null state for " + exe);
			return false;
		}
		return state.isAlive();
	}

	/**
	 * Check if a target is a live process, and cast if so
	 * 
	 * @param target the potential process
	 * @return the process if live, or null
	 */
	public static TargetProcess liveProcessOrNull(TargetObject target) {
		if (!(target instanceof TargetProcess)) {
			return null;
		}
		TargetProcess process = (TargetProcess) target;
		return isProcessAlive(process) ? process : null;
	}

	public static class AsyncAttribute<T> extends AsyncReference<T, Void>
			implements DebuggerModelListener {
		private final TargetObject obj;
		private final String name;

		@SuppressWarnings("unchecked")
		public AsyncAttribute(TargetObject obj, String name) {
			this.name = name;
			this.obj = obj;
			obj.getModel().addModelListener(this);
			set((T) obj.getCachedAttribute(name), null);
			obj.fetchAttribute(name).exceptionally(ex -> {
				Msg.error(this, "Could not get initial value of " + name + " for " + obj, ex);
				return null;
			});
		}

		@Override
		@SuppressWarnings("unchecked")
		public void attributesChanged(TargetObject parent, Collection<String> removed,
				Map<String, ?> added) {
			if (parent != obj) {
				return;
			}
			if (added.containsKey(name)) {
				set((T) added.get(name), null);
			}
			else if (removed.contains(name)) {
				set(null, null);
			}
		}

		public void dispose() {
			this.dispose(new AssertionError("disposed"));
		}

		@Override
		public void dispose(Throwable reason) {
			super.dispose(reason);
			obj.getModel().removeModelListener(this);
		}
	}

	public static class AsyncState extends AsyncAttribute<TargetExecutionState> {
		public AsyncState(TargetExecutionStateful stateful) {
			super(stateful, TargetExecutionStateful.STATE_ATTRIBUTE_NAME);
		}
	}

	public static class AsyncAccess extends AsyncAttribute<Boolean> {
		public AsyncAccess(TargetAccessConditioned ac) {
			super(ac, TargetAccessConditioned.ACCESSIBLE_ATTRIBUTE_NAME);
		}
	}

	/**
	 * Request activation of the given object in its nearest active scope
	 * 
	 * <p>
	 * Note if the object has no suitable active scope, this method fails silently.
	 * 
	 * @param obj the object on which to request activation
	 * @return a future which completes when activation is granted, or exceptionally
	 */
	public static CompletableFuture<Void> requestActivation(TargetObject obj) {
		CompletableFuture<? extends TargetActiveScope> futureActivator =
			DebugModelConventions.findSuitable(TargetActiveScope.class, obj);
		return futureActivator.thenCompose(activator -> {
			if (activator == null) {
				return AsyncUtils.NIL;
			}
			return activator.requestActivation(obj);
		});
	}

	/**
	 * Request focus on the given object in its nearest focus scope
	 * 
	 * <p>
	 * Note if the object has no suitable focus scope, this method fails silently.
	 * 
	 * @param obj the object on which to request focus
	 * @return a future which completes when focus is granted, or exceptionally
	 */
	public static CompletableFuture<Void> requestFocus(TargetObject obj) {
		CompletableFuture<? extends TargetFocusScope> futureScope =
			DebugModelConventions.findSuitable(TargetFocusScope.class, obj);
		return futureScope.thenCompose(scope -> {
			if (scope == null) {
				return AsyncUtils.NIL;
			}
			return scope.requestFocus(obj);
		});
	}
}
