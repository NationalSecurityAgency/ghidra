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
package ghidra.app.plugin.core.debug.service.model;

import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.function.Consumer;

import ghidra.async.AsyncFence;
import ghidra.dbg.*;
import ghidra.dbg.target.*;
import ghidra.dbg.util.DebuggerCallbackReorderer;
import ghidra.dbg.util.PathUtils.PathComparator;
import ghidra.util.Msg;
import ghidra.util.datastruct.PrivatelyQueuedListener;

public class TraceObjectListener implements DebuggerModelListener {

	private TraceObjectManager objectManager;
	private TargetObject target;

	protected boolean disposed = false;
	protected final NavigableMap<List<String>, TargetObject> initialized =
		new TreeMap<>(PathComparator.KEYED);
	protected final DebuggerCallbackReorderer reorderer = new DebuggerCallbackReorderer(this);
	protected final PrivatelyQueuedListener<DebuggerModelListener> queue;

	public TraceObjectListener(TraceObjectManager manager) {
		this.objectManager = manager;
		this.target = objectManager.getTarget();

		DefaultTraceRecorder recorder = objectManager.getRecorder();
		this.queue = new PrivatelyQueuedListener<>(DebuggerModelListener.class,
			recorder.privateQueue, reorderer);
	}

	public void init() {
		findInitialObjects(target).thenAccept(adds -> {
			for (TargetObject added : adds) {
				processInit(added);
			}
			DebuggerObjectModel model = target.getModel();
			model.addModelListener(queue.in, true);
		});
	}

	boolean matchesTarget(TargetObject object) {
		TargetObject proc = object;
		while (proc != null) {
			if (proc == target)
				return true;
			if (proc.getClass().equals(target.getClass()))
				return false;
			proc = proc.getParent();
		}
		return true;
	}

	protected void processCreate(TargetObject added) {
		if (!objectManager.hasObject(added) && matchesTarget(added)) {
			objectManager.addObject(added);
			objectManager.createObject(added);
		}
		/*
		else {
			Msg.info(this, "processCreate dropped " + added);
		}
		*/
	}

	protected void processInit(TargetObject added) {
		if (objectManager.hasObject(added)) {
			if (!initialized.containsKey(added.getPath())) {
				initialized.put(added.getPath(), added);
				objectManager.initObject(added);
			}
		}
	}

	protected void processRemove(TargetObject removed) {
		if (objectManager.hasObject(removed)) {
			objectManager.removeObject(removed);
			objectManager.removeObject(removed.getPath());
		}
	}

	protected void processAttributesChanged(TargetObject changed, Map<String, ?> added) {
		if (objectManager.hasObject(changed)) {
			objectManager.attributesChanged(changed, added);
		}
	}

	protected void processElementsChanged(TargetObject changed, Map<String, ?> added) {
		if (objectManager.hasObject(changed)) {
			objectManager.elementsChanged(changed, added);
		}
	}

	@Override
	public void created(TargetObject object) {
		//System.err.println("CR:" + object);
		processCreate(object);
	}

	@Override
	public void invalidated(TargetObject object, TargetObject branch, String reason) {
		processRemove(object);
	}

	@Override
	public void attributesChanged(TargetObject parent, Collection<String> removed,
			Map<String, ?> added) {
		//System.err.println("AC:" + added + ":" + parent);
		if (parent.isValid()) {
			processInit(parent);
			processAttributesChanged(parent, added);
		}
	}

	@Override
	public void elementsChanged(TargetObject parent, Collection<String> removed,
			Map<String, ? extends TargetObject> added) {
		//System.err.println("EC:" + added + ":" + parent);
		if (parent.isValid()) {
			processElementsChanged(parent, added);
		}
	}

	public List<TargetBreakpointLocation> collectBreakpoints(TargetThread thread) {
		synchronized (objectManager.objects) {
			return objectManager.collectBreakpoints(thread);
		}
	}

	protected void onProcessBreakpointContainers(
			Consumer<? super TargetBreakpointSpecContainer> action) {
		synchronized (objectManager.objects) {
			objectManager.onProcessBreakpointContainers(action);
		}
	}

	protected void onThreadBreakpointContainers(TargetThread thread,
			Consumer<? super TargetBreakpointSpecContainer> action) {
		synchronized (objectManager.objects) {
			objectManager.onThreadBreakpointContainers(thread, action);
		}
	}

	/*
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
		return true;
	}
	
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
	*/

	private CompletableFuture<List<TargetObject>> findInitialObjects(TargetObject target) {
		List<TargetObject> result = new ArrayList<>();
		result.add(target);
		AsyncFence fence = new AsyncFence();
		CompletableFuture<? extends TargetEventScope> futureEvents =
			DebugModelConventions.findSuitable(TargetEventScope.class, target);
		fence.include(futureEvents.thenAccept(events -> {
			if (events != null) {
				result.add(events);
			}
		}).exceptionally(e -> {
			Msg.warn(this, "Could not search for event scope", e);
			return null;
		}));
		CompletableFuture<? extends TargetFocusScope> futureFocus =
			DebugModelConventions.findSuitable(TargetFocusScope.class, target);
		fence.include(futureFocus.thenAccept(focus -> {
			if (focus != null) {
				// Don't descend. Scope may be the entire session.
				result.add(focus);
			}
		}).exceptionally(e -> {
			Msg.error(this, "Could not search for focus scope", e);
			return null;
		}));
		return fence.ready().thenApply(__ -> {
			return result;
		});
	}

	public void dispose() {
		target.getModel().removeModelListener(reorderer);
		reorderer.dispose();
	}

	/*
	private CompletableFuture<List<TargetObject>> findDependenciesTop(TargetObject added) {
		List<TargetObject> result = new ArrayList<>();
		result.add(added);
		return findDependencies(added, result);
	}
	
	private CompletableFuture<List<TargetObject>> findDependencies(TargetObject added,
			List<TargetObject> result) {
		//System.err.println("findDependencies " + added);
		AsyncFence fence = new AsyncFence();
		fence.include(added.fetchAttributes(false).thenCompose(attrs -> {
			AsyncFence af = new AsyncFence();
			for (String key : attrs.keySet()) { //requiredObjKeys) {
				Object object = attrs.get(key);
				if (!(object instanceof TargetObject)) {
					continue;
				}
				TargetObject ref = (TargetObject) object;
				if (PathUtils.isLink(added.getPath(), key, ref.getPath())) {
					continue;
				}
				af.include(ref.fetch().thenCompose(obj -> {
					if (!objectManager.isRequired(obj)) {
						return CompletableFuture.completedFuture(result);
					}
					synchronized (result) {
						result.add(obj);
					}
					return findDependencies(obj, result);
				}));
			}
			return af.ready();
		}));
		fence.include(added.fetchElements(false).thenCompose(elems -> {
			AsyncFence ef = new AsyncFence();
			for (TargetObject ref : elems.values()) {
				ef.include(ref.fetch().thenCompose(obj -> {
					synchronized (result) {
						result.add(obj);
					}
					return findDependencies(obj, result);
				}));
			}
			return ef.ready();
		}));
		return fence.ready().thenApply(__ -> {
			return result;
		});
	}
	*/
}
