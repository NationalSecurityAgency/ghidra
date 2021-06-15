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
package ghidra.dbg.util;

import java.util.*;
import java.util.Map.Entry;
import java.util.concurrent.CompletableFuture;

import ghidra.async.AsyncFence;
import ghidra.async.AsyncUtils;
import ghidra.dbg.DebuggerModelClosedReason;
import ghidra.dbg.DebuggerModelListener;
import ghidra.dbg.error.DebuggerMemoryAccessException;
import ghidra.dbg.target.*;
import ghidra.dbg.target.TargetConsole.Channel;
import ghidra.dbg.target.TargetEventScope.TargetEventType;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.util.Msg;

/**
 * A mechanism for re-ordering model callbacks
 * 
 * <p>
 * When this is added to the model, {@code replay} must be true, or behavior of the mechanism is
 * undefined.
 */
public class DebuggerCallbackReorderer implements DebuggerModelListener {

	private class ObjectRecord {
		private final TargetObject obj;
		private final CompletableFuture<TargetObject> addedToParent = new CompletableFuture<>();
		private final CompletableFuture<TargetObject> complete;

		ObjectRecord(TargetObject obj) {
			this.obj = obj;
			TargetObject parent = obj.getParent();
			ObjectRecord parentRecord;
			synchronized (records) {
				parentRecord = parent == null ? null : records.get(parent);
			}
			if (parentRecord == null) {
				complete = addedToParent.thenApply(this::completed);
			}
			else {
				complete = parentRecord.complete.thenCompose(__ -> addedToParent)
						.thenApply(this::completed);
			}
		}

		TargetObject completed(TargetObject obj) {
			synchronized (records) {
				records.remove(obj);
			}
			// NB. We should already be on the clientExecutor
			Map<String, ?> attributes = obj.getCallbackAttributes();
			if (!attributes.isEmpty()) {
				defensive(() -> listener.attributesChanged(obj, List.of(), Map.copyOf(attributes)),
					"attributesChanged(r)");
			}
			Map<String, ? extends TargetObject> elements = obj.getCallbackElements();
			if (!elements.isEmpty()) {
				defensive(() -> listener.elementsChanged(obj, List.of(), Map.copyOf(elements)),
					"elementsChanged(r)");
			}
			return obj;
		}

		void added() {
			if (!addedToParent.isDone()) {
				addedToParent.complete(obj);
			}
		}

		void removed() {
			if (!addedToParent.isDone()) {
				addedToParent.cancel(false);
			}
		}

		public void cancel() {
			addedToParent.cancel(false);
			complete.cancel(false);
		}
	}

	private final DebuggerModelListener listener;

	private final Map<TargetObject, ObjectRecord> records = new HashMap<>();
	private CompletableFuture<Void> lastEvent = AsyncUtils.NIL;

	private volatile boolean disposed = false;

	public DebuggerCallbackReorderer(DebuggerModelListener listener) {
		this.listener = listener;
	}

	private void defensive(Runnable r, String cb) {
		try {
			r.run();
		}
		catch (Throwable t) {
			Msg.error(this, "Listener " + listener + " caused exception processing " + cb, t);
		}
	}

	@Override
	public void catastrophic(Throwable t) {
		if (disposed) {
			return;
		}
		listener.catastrophic(t);
	}

	@Override
	public void modelClosed(DebuggerModelClosedReason reason) {
		if (disposed) {
			return;
		}
		listener.modelClosed(reason);
	}

	@Override
	public void modelOpened() {
		if (disposed) {
			return;
		}
		listener.modelOpened();
	}

	@Override
	public void modelStateChanged() {
		if (disposed) {
			return;
		}
		listener.modelStateChanged();
	}

	@Override
	public void created(TargetObject object) {
		if (disposed) {
			return;
		}
		//System.err.println("created object='" + object.getJoinedPath(".") + "'");
		synchronized (records) {
			records.put(object, new ObjectRecord(object));
		}
		defensive(() -> listener.created(object), "created");
	}

	@Override
	public void invalidated(TargetObject object, TargetObject branch, String reason) {
		if (disposed) {
			return;
		}
		ObjectRecord remove;
		synchronized (records) {
			remove = records.remove(object);
		}
		if (remove != null) {
			remove.removed();
		}
		defensive(() -> listener.invalidated(object, branch, reason), "invalidated");
	}

	@Override
	public void rootAdded(TargetObject root) {
		if (disposed) {
			return;
		}
		defensive(() -> listener.rootAdded(root), "rootAdded");
		synchronized (records) {
			records.get(root).added();
		}
	}

	@Override
	public void attributesChanged(TargetObject object, Collection<String> removed,
			Map<String, ?> added) {
		if (disposed) {
			return;
		}
		//System.err.println("attributesChanged object=" + object.getJoinedPath(".") + ",removed=" +
		//	removed + ",added=" + added);
		ObjectRecord record;
		synchronized (records) {
			record = records.get(object);
		}
		if (record == null) {
			defensive(() -> listener.attributesChanged(object, removed, added),
				"attributesChanged");
		}
		// Removed taken care of via invalidation
		for (Entry<String, ?> ent : added.entrySet()) {
			//System.err.println("  " + ent.getKey());
			Object val = ent.getValue();
			if (val instanceof TargetObject) {
				TargetObject obj = (TargetObject) val;
				if (!PathUtils.isLink(object.getPath(), ent.getKey(), obj.getPath())) {
					ObjectRecord rec;
					synchronized (records) {
						rec = records.get(obj);
					}
					if (rec != null) {
						rec.added();
					}
				}
			}
		}
	}

	@Override
	public void elementsChanged(TargetObject object, Collection<String> removed,
			Map<String, ? extends TargetObject> added) {
		if (disposed) {
			return;
		}
		//System.err.println("elementsChanged object=" + object.getJoinedPath(".") + ",removed=" +
		//	removed + ",added=" + added);
		ObjectRecord record;
		synchronized (records) {
			record = records.get(object);
		}
		if (record == null) {
			defensive(() -> listener.elementsChanged(object, removed, added), "elementsChanged");
		}
		// Removed taken care of via invalidation
		for (Entry<String, ? extends TargetObject> ent : added.entrySet()) {
			//System.err.println("  " + ent.getKey());
			TargetObject obj = ent.getValue();
			if (!PathUtils.isElementLink(object.getPath(), ent.getKey(), obj.getPath())) {
				ObjectRecord rec;
				synchronized (records) {
					rec = records.get(obj);
				}
				if (rec != null) {
					rec.added();
				}
			}
		}
	}

	private void orderedOnObjects(Collection<TargetObject> objects, Runnable r, String cb) {
		AsyncFence fence = new AsyncFence();
		fence.include(lastEvent);
		synchronized (records) {
			for (TargetObject obj : objects) {
				ObjectRecord record = records.get(obj);
				if (record != null) {
					fence.include(record.complete);
				}
			}
		}
		lastEvent = fence.ready().thenAccept(__ -> {
			defensive(r, cb);
		}).exceptionally(ex -> {
			Msg.error(this, "Callback " + cb + " dropped for error in dependency", ex);
			return null;
		});
	}

	@Override
	public void breakpointHit(TargetObject container, TargetObject trapped, TargetStackFrame frame,
			TargetBreakpointSpec spec, TargetBreakpointLocation breakpoint) {
		if (disposed) {
			return;
		}
		List<TargetObject> args = frame == null
				? List.of(container, trapped, spec, breakpoint)
				: List.of(container, trapped, frame, spec, breakpoint);
		orderedOnObjects(args, () -> {
			listener.breakpointHit(container, trapped, frame, spec, breakpoint);
		}, "breakpointHit");
	}

	@Override
	public void consoleOutput(TargetObject console, Channel channel, byte[] data) {
		if (disposed) {
			return;
		}
		orderedOnObjects(List.of(console), () -> {
			listener.consoleOutput(console, channel, data);
		}, "consoleOutput");
	}

	private Collection<TargetObject> gatherObjects(Collection<?>... collections) {
		Set<TargetObject> objs = new HashSet<>();
		for (Collection<?> col : collections) {
			for (Object val : col) {
				if (val instanceof TargetObject) {
					objs.add((TargetObject) val);
				}
			}
		}
		return objs;
	}

	@Override
	public void event(TargetObject object, TargetThread eventThread, TargetEventType type,
			String description, List<Object> parameters) {
		if (disposed) {
			return;
		}
		List<TargetObject> objs = eventThread == null
				? List.of(object)
				: List.of(object, eventThread);
		orderedOnObjects(gatherObjects(objs, parameters), () -> {
			listener.event(object, eventThread, type, description, parameters);
		}, "event(" + type + ") " + description);
	}

	@Override
	public void invalidateCacheRequested(TargetObject object) {
		if (disposed) {
			return;
		}
		orderedOnObjects(List.of(object), () -> {
			listener.invalidateCacheRequested(object);
		}, "invalidateCacheRequested");
	}

	@Override
	public void memoryReadError(TargetObject memory, AddressRange range,
			DebuggerMemoryAccessException e) {
		if (disposed) {
			return;
		}
		orderedOnObjects(List.of(memory), () -> {
			listener.memoryReadError(memory, range, e);
		}, "invalidateCacheRequested");
	}

	@Override
	public void memoryUpdated(TargetObject memory, Address address, byte[] data) {
		if (disposed) {
			return;
		}
		orderedOnObjects(List.of(memory), () -> {
			listener.memoryUpdated(memory, address, data);
		}, "invalidateCacheRequested");
	}

	@Override
	public void registersUpdated(TargetObject bank, Map<String, byte[]> updates) {
		if (disposed) {
			return;
		}
		orderedOnObjects(List.of(bank), () -> {
			listener.registersUpdated(bank, updates);
		}, "invalidateCacheRequested");
	}

	public void dispose() {
		disposed = true;
		Set<ObjectRecord> volRecs;
		synchronized (records) {
			volRecs = Set.copyOf(records.values());
			records.clear();
		}
		for (ObjectRecord rec : volRecs) {
			rec.cancel();
		}
	}
}
