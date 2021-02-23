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
import java.util.Map.Entry;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

import ghidra.async.*;
import ghidra.dbg.attributes.TargetObjectRef;
import ghidra.dbg.target.*;
import ghidra.dbg.target.TargetAccessConditioned.TargetAccessibility;
import ghidra.dbg.target.TargetAccessConditioned.TargetAccessibilityListener;
import ghidra.dbg.target.TargetExecutionStateful.TargetExecutionState;
import ghidra.dbg.target.TargetObject.TargetObjectListener;
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
	 * Fetch everything in a particular collection of refs
	 * 
	 * <p>
	 * This was added as part of GP-251. Where there are uses of this method, devs should consider
	 * opportunities to be more selective in what they fetch.
	 * 
	 * @param <K> the type of keys
	 * @param refs the collection of refs
	 * @return the collection of objects
	 * @deprecated Just to draw attention to it
	 */
	@Deprecated(forRemoval = false)
	public static <K> CompletableFuture<Map<K, TargetObject>> fetchAll(
			Map<K, ? extends TargetObjectRef> refs) {
		if (refs == null) {
			return AsyncUtils.nil();
		}
		Map<K, TargetObject> result = new HashMap<>();
		AsyncFence fence = new AsyncFence();
		for (Map.Entry<K, ? extends TargetObjectRef> ent : refs.entrySet()) {
			fence.include(ent.getValue().fetch().thenAccept(obj -> {
				synchronized (result) {
					result.put(ent.getKey(), obj);
				}
			}));
		}
		return fence.ready().thenApply(__ -> result);
	}

	/**
	 * Fetch all non-link refs in an attribute map
	 * 
	 * <p>
	 * This was added as part of GP-251. Where there are uses of this method, devs should consider
	 * opportunities to be more selective in what they fetch.
	 * 
	 * @param refs the attribute map
	 * @return the attribute map, but with non-link refs fetched as objects
	 * @deprecated Just to draw attention to it
	 */
	@Deprecated(forRemoval = false)
	public static CompletableFuture<Map<String, ?>> fetchObjAttrs(TargetObjectRef parent,
			Map<String, ?> attrs) {
		if (attrs == null) {
			return AsyncUtils.nil();
		}
		Map<String, Object> result = new HashMap<>();
		AsyncFence fence = new AsyncFence();
		for (Map.Entry<String, ?> ent : attrs.entrySet()) {
			String name = ent.getKey();
			Object a = ent.getValue();
			if (!(a instanceof TargetObjectRef)) {
				synchronized (result) {
					result.put(name, a);
				}
				continue;
			}
			TargetObjectRef ref = (TargetObjectRef) a;
			if (PathUtils.isLink(parent.getPath(), ent.getKey(), ref.getPath())) {
				synchronized (result) {
					result.put(name, a);
				}
				continue;
			}
			fence.include(ref.fetch().thenAccept(obj -> {
				synchronized (result) {
					result.put(name, obj);
				}
			}));
		}
		return fence.ready().thenApply(__ -> result);
	}

	/**
	 * Search for a suitable object implementing the given interface, starting at a given seed.
	 * 
	 * @see #findSuitable(Class, TargetObject)
	 */
	public static <T extends TargetObject> CompletableFuture<T> findSuitable(Class<T> iface,
			TargetObjectRef seed) {
		return seed.fetch().thenCompose(obj -> findSuitable(iface, obj));
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
	 */
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

	private static <T extends TargetObject> CompletableFuture<T> findParentSuitable(Class<T> iface,
			TargetObject obj) {
		return obj.fetchParent().thenCompose(parent -> {
			if (parent == null) {
				return AsyncUtils.nil();
			}
			return findSuitable(iface, parent);
		});
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
			fence.include(seed.fetchAttributes().thenCompose(attributes -> {
				AsyncFence f2 = new AsyncFence();
				for (Map.Entry<String, ?> ent : attributes.entrySet()) {
					Object val = ent.getValue();
					if (!(val instanceof TargetObjectRef)) {
						continue;
					}
					TargetObjectRef ref = (TargetObjectRef) val;
					if (PathUtils.isLink(seed.getPath(), ent.getKey(), ref.getPath())) {
						// TODO: Resolve refs? Must ensure I don't re-visit anyone
						continue;
					}
					f2.include(ref.fetch().thenAccept(obj -> {
						synchronized (nextLevel) {
							nextLevel.add(obj);
						}
					}));
				}
				return f2.ready();
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
					cur.fetchParent().thenAccept(this::next).exceptionally(this::exc);
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
	 */
	// TODO: Test this method
	public static <T extends TargetObject> CompletableFuture<Collection<T>> collectSuccessors(
			TargetObject seed, Class<T> iface) {
		Collection<T> result =
			new TreeSet<>(Comparator.comparing(TargetObject::getPath, PathComparator.KEYED));
		AsyncFence fence = new AsyncFence();
		fence.include(seed.fetchElements().thenCompose(elements -> {
			AsyncFence elemFence = new AsyncFence();
			for (TargetObjectRef r : elements.values()) {
				elemFence.include(r.fetch().thenCompose(e -> {
					if (iface.isInstance(e)) {
						synchronized (result) {
							result.add(iface.cast(e));
						}
						return AsyncUtils.NIL;
					}
					return collectSuccessors(e, iface).thenAccept(sub -> {
						synchronized (result) {
							result.addAll(sub);
						}
					});
				}));
			}
			return elemFence.ready();
		}));
		fence.include(seed.fetchAttributes().thenCompose(attributes -> {
			AsyncFence attrFence = new AsyncFence();
			for (Map.Entry<String, ?> ent : attributes.entrySet()) {
				Object obj = ent.getValue();
				if (!(obj instanceof TargetObjectRef)) {
					continue;
				}
				TargetObjectRef r = (TargetObjectRef) obj;
				if (PathUtils.isLink(seed.getPath(), ent.getKey(), r.getPath())) {
					continue;
				}
				attrFence.include(r.fetch().thenCompose(a -> {
					if (iface.isInstance(a)) {
						synchronized (result) {
							result.add(iface.cast(a));
						}
						return AsyncUtils.NIL;
					}
					return collectSuccessors(a, iface).thenAccept(sub -> {
						synchronized (result) {
							result.addAll(sub);
						}
					});
				}));
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
	public static CompletableFuture<TargetThread<?>> findThread(TargetObject successor) {
		return new AncestorTraversal<TargetThread<?>>(successor) {
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
			protected TargetThread<?> finish(TargetObject obj) {
				return (TargetThread<?>) obj;
			}
		}.start();
	}

	/**
	 * Find the nearest ancestor thread
	 * 
	 * @see #findThread(TargetObject)
	 */
	public static CompletableFuture<TargetThread<?>> findThread(TargetObjectRef successorRef) {
		return successorRef.fetch().thenCompose(DebugModelConventions::findThread);
	}

	/**
	 * Check if a target is a live process
	 * 
	 * @param target the potential process
	 * @return the process if live, or null
	 */
	public static TargetProcess<?> liveProcessOrNull(TargetObject target) {
		if (!(target instanceof TargetProcess<?>)) {
			return null;
		}
		// TODO: When schemas are introduced, we'll better handle "associated"
		// For now, require "implements"
		if (!(target instanceof TargetExecutionStateful<?>)) {
			return (TargetProcess<?>) target;
		}
		TargetExecutionStateful<?> exe = (TargetExecutionStateful<?>) target;
		TargetExecutionState state = exe.getExecutionState();
		if (!state.isAlive()) {
			return null;
		}
		return (TargetProcess<?>) target;
	}

	/**
	 * A convenience for listening to selected portions (possible all) of a sub-tree of a model
	 */
	public abstract static class SubTreeListenerAdapter implements TargetObjectListener {
		protected boolean disposed = false;
		protected final NavigableMap<List<String>, TargetObject> objects =
			new TreeMap<>(PathComparator.KEYED);

		/**
		 * An object has been removed from the sub-tree
		 * 
		 * @param removed the removed object
		 */
		protected abstract void objectRemoved(TargetObject removed);

		/**
		 * An object has been added to the sub-tree
		 * 
		 * @param added the added object
		 */
		protected abstract void objectAdded(TargetObject added);

		/**
		 * Decide whether a sub-tree (of the sub-tree) should be tracked
		 * 
		 * @param ref the root of the sub-tree to consider
		 * @return false to ignore, true to track
		 */
		protected abstract boolean checkDescend(TargetObjectRef ref);

		@Override
		public void invalidated(TargetObject object, TargetObject branch, String reason) {
			runNotInSwing(this, () -> doInvalidated(object, reason), "invalidated");
		}

		private void doInvalidated(TargetObject object, String reason) {
			List<TargetObject> removed = new ArrayList<>();
			synchronized (objects) {
				if (disposed) {
					return;
				}
				/**
				 * NOTE: Can't use iteration, because subtrees will also remove stuff, causing
				 * ConcurrentModificationException, even if removal is via the iterator...
				 */
				List<String> path = object.getPath();
				while (true) {
					Entry<List<String>, TargetObject> ent = objects.ceilingEntry(path);
					if (ent == null || !PathUtils.isAncestor(path, ent.getKey())) {
						break;
					}
					objects.remove(ent.getKey());
					TargetObject succ = ent.getValue();
					succ.removeListener(this);
					removed.add(succ);
				}
			}
			for (TargetObject r : removed) {
				objectRemovedSafe(r);
			}
		}

		private void objectRemovedSafe(TargetObject removed) {
			try {
				objectRemoved(removed);
			}
			catch (Throwable t) {
				Msg.error(this, "Error in callback", t);
			}
		}

		private void objectAddedSafe(TargetObject obj) {
			try {
				objectAdded(obj);
			}
			catch (Throwable t) {
				Msg.error(this, "Error in callback", t);
			}
		}

		private void considerRef(TargetObjectRef ref) {
			if (!checkDescend(ref)) {
				return;
			}
			ref.fetch()
					.thenAcceptAsync(this::addListenerAndConsiderSuccessors)
					.exceptionally(ex -> {
						Msg.error(this, "Could not fetch a ref: " + ref, ex);
						return null;
					});
		}

		private void considerElements(TargetObject parent,
				Map<String, ? extends TargetObjectRef> elements) {
			synchronized (objects) {
				if (disposed) {
					return;
				}
				if (!objects.containsKey(parent.getPath())) {
					return;
				}
			}
			for (TargetObjectRef e : elements.values()) {
				considerRef(e);
			}
		}

		private void considerAttributes(TargetObject obj, Map<String, ?> attributes) {
			synchronized (objects) {
				if (disposed) {
					return;
				}
				if (!objects.containsKey(obj.getPath())) {
					return;
				}
			}
			for (Map.Entry<String, ?> ent : attributes.entrySet()) {
				String name = ent.getKey();
				Object a = ent.getValue();
				if (!(a instanceof TargetObjectRef)) {
					continue;
				}
				TargetObjectRef r = (TargetObjectRef) a;
				if (PathUtils.isLink(obj.getPath(), name, r.getPath())) {
					continue;
				}
				considerRef(r);
			}
		}

		/**
		 * Track a specified object, without initially adding the sub-tree
		 * 
		 * <p>
		 * Note that {@link #checkDescend(TargetObject)} must also exclude the sub-tree, otherwise
		 * children added later will be tracked.
		 * 
		 * @param obj the object to track
		 * @return true if the object was not already being listened to
		 */
		public boolean addListener(TargetObject obj) {
			if (obj == null) {
				return false;
			}
			obj.addListener(this);
			synchronized (objects) {
				if (objects.put(obj.getPath(), obj) == obj) {
					return false;
				}
			}
			objectAddedSafe(obj);
			return true;
		}

		/**
		 * Add a specified sub-tree to this listener
		 * 
		 * @param obj
		 * @return true if the object was not already being listened to
		 */
		public boolean addListenerAndConsiderSuccessors(TargetObject obj) {
			boolean result = addListener(obj);
			if (result && checkDescend(obj)) {
				obj.fetchElements()
						.thenAcceptAsync(elems -> considerElements(obj, elems))
						.exceptionally(ex -> {
							Msg.error(this, "Could not fetch elements of obj: " + obj, ex);
							return null;
						});
				obj.fetchAttributes()
						.thenAcceptAsync(attrs -> considerAttributes(obj, attrs))
						.exceptionally(ex -> {
							Msg.error(this, "Could not fetch attributes of obj: " + obj, ex);
							return null;
						});
			}
			return result;
		}

		@Override
		public void elementsChanged(TargetObject parent, Collection<String> removed,
				Map<String, ? extends TargetObjectRef> added) {
			runNotInSwing(this, () -> doElementsChanged(parent, removed, added), "elementsChanged");
		}

		private void doElementsChanged(TargetObject parent, Collection<String> removed,
				Map<String, ? extends TargetObjectRef> added) {
			if (checkDescend(parent)) {
				considerElements(parent, added);
			}
		}

		@Override
		public void attributesChanged(TargetObject parent, Collection<String> removed,
				Map<String, ?> added) {
			runNotInSwing(this, () -> doAttributesChanged(parent, removed, added),
				"attributesChanged");
		}

		private void doAttributesChanged(TargetObject parent, Collection<String> removed,
				Map<String, ?> added) {
			if (checkDescend(parent)) {
				considerAttributes(parent, added);
			}
		}

		/**
		 * Dispose of this sub-tree tracker/listener
		 * 
		 * <p>
		 * This uninstalls the listener from every tracked object and clears its collection of
		 * tracked objects.
		 */
		public void dispose() {
			synchronized (objects) {
				disposed = true;
				for (Iterator<TargetObject> it = objects.values().iterator(); it.hasNext();) {
					TargetObject obj = it.next();
					obj.removeListener(this);
					it.remove();
				}
			}
		}
	}

	public static class AllRequiredAccess extends AsyncReference<TargetAccessibility, Void> {
		protected class ListenerForAccess implements TargetAccessibilityListener {
			protected final TargetAccessConditioned<?> access;
			private boolean accessible;

			public ListenerForAccess(TargetAccessConditioned<?> access) {
				this.access = access;
				this.access.addListener(this);
				this.accessible = access.getAccessibility() == TargetAccessibility.ACCESSIBLE;
			}

			@Override
			public void accessibilityChanged(TargetAccessConditioned<?> object,
					TargetAccessibility accessibility) {
				//Msg.debug(this, "Obj " + object + " has become " + accessibility);
				synchronized (AllRequiredAccess.this) {
					this.accessible = accessibility == TargetAccessibility.ACCESSIBLE;
					// Check that all requests have been issued (fence is ready)
					if (listeners != null) {
						set(getAllAccessibility(), null);
					}
				}
			}
		}

		protected final List<ListenerForAccess> listeners;
		protected final AsyncFence initFence = new AsyncFence();

		public AllRequiredAccess(Collection<? extends TargetAccessConditioned<?>> allReq) {
			Msg.debug(this, "Listening for access on: " + allReq);
			listeners = allReq.stream().map(ListenerForAccess::new).collect(Collectors.toList());
			set(getAllAccessibility(), null);
		}

		public TargetAccessibility getAllAccessibility() {
			return TargetAccessibility.fromBool(listeners.stream().allMatch(l -> l.accessible));
		}
	}

	/**
	 * Obtain an object which tracks accessibility for a given target object.
	 * 
	 * <p>
	 * Recall that for an object to be considered accessible, it and its ancestors must all be
	 * accessible. Objects without the {@link TargetAccessConditioned} interface, are assumed
	 * accessible.
	 * 
	 * <p>
	 * <b>Caution:</b> The returned {@link AllRequiredAccess} object has the only strong references
	 * to the listeners. If you intend to wait for access, e.g., by calling
	 * {@link AsyncReference#waitValue(Object)}, you must ensure a strong reference to this object
	 * is maintained for the duration of the wait. If not, it could be garbage collected, and you
	 * will never get a callback.
	 * 
	 * @param obj the object whose accessibility to track
	 * @return a future which completes with an {@link AsyncReference} of the objects effective
	 *         accessibility.
	 */
	public static CompletableFuture<AllRequiredAccess> trackAccessibility(TargetObject obj) {
		CompletableFuture<? extends Collection<? extends TargetAccessConditioned<?>>> collectAncestors =
			collectAncestors(obj, TargetAccessConditioned.tclass);
		return collectAncestors.thenApply(AllRequiredAccess::new);
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
	public static CompletableFuture<Void> requestFocus(TargetObjectRef obj) {
		CompletableFuture<? extends TargetFocusScope<?>> futureScope =
			DebugModelConventions.findSuitable(TargetFocusScope.tclass, obj);
		return futureScope.thenCompose(scope -> {
			if (scope == null) {
				return AsyncUtils.NIL;
			}
			return scope.requestFocus(obj);
		});
	}
}
