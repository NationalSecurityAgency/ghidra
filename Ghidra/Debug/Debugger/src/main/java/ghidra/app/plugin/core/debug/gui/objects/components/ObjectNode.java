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
package ghidra.app.plugin.core.debug.gui.objects.components;

import java.util.*;
import java.util.concurrent.*;

import javax.swing.Icon;
import javax.swing.ImageIcon;

import docking.widgets.tree.*;
import ghidra.app.plugin.core.debug.gui.objects.DebuggerObjectsProvider;
import ghidra.app.plugin.core.debug.gui.objects.ObjectContainer;
import ghidra.dbg.target.*;
import ghidra.dbg.target.TargetExecutionStateful.TargetExecutionState;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import resources.ResourceManager;

public class ObjectNode extends GTreeSlowLoadingNode {  //extends GTreeNode

	static final ImageIcon ICON_POPULATED =
		ResourceManager.loadImage("images/object-populated.png");
	static final ImageIcon ICON_EMPTY = ResourceManager.loadImage("images/object-unpopulated.png");
	static final ImageIcon ICON_RUNNING = ResourceManager.loadImage("images/object-running.png");
	static final ImageIcon ICON_TERMINATED =
		ResourceManager.loadImage("images/object-terminated.png");
	static final ImageIcon ICON_EVENT = ResourceManager.loadImage("images/register-marker.png");

	private ObjectContainer container;
	private String name;
	private ObjectTree tree;
	private Set<GTreeNode> oldChildren;
	private boolean restructured = false;

	public ObjectNode(ObjectTree tree, ObjectContainer parent, ObjectContainer container) {
		this.tree = tree;
		setContainer(tree, parent, container);
	}

	public ObjectContainer getContainer() {
		return container;
	}

	public void setContainer(ObjectTree tree, ObjectContainer parent, ObjectContainer container) {
		this.container = container;
		name = container.getName();
		if (parent != null) {
			tree.addToMap(parent, container, this);
		}
		//fireNodeStructureChanged(this);
	}

	public TargetObject getTargetObject() {
		return container.getTargetObject();
	}

	@Override
	public String getName() {
		return name;
	}

	@Override
	public String toString() {
		return container.getDecoratedName();
	}

	@Override
	public List<GTreeNode> generateChildren(TaskMonitor monitor) throws CancelledException {

		if (!container.isImmutable() || isInProgress()) {
			try {
				CompletableFuture<ObjectContainer> cf = container.getOffspring();
				if (cf != null) {
					// NB: We're allowed to do this because we're guaranteed to be 
					//   in our own thread by the GTreeSlowLoadingNode
					ObjectContainer oc = cf.get(60, TimeUnit.SECONDS);
					return tree.update(oc);
				}
			}
			catch (InterruptedException | ExecutionException e) {
				Msg.warn(this, e);
			}
			catch (TimeoutException e) {
				Msg.showWarn(this, container.getProvider().getComponent(), "Timeout Exception",
					"Request for children timed - out - try refreshing the node");
			}
		}
		List<GTreeNode> list = new ArrayList<>();
		if (oldChildren != null) {
			list.addAll(oldChildren);
		}
		return list;
	}

	public DebuggerObjectsProvider getProvider() {
		return container.getProvider();
	}

	@Override
	public String getDisplayText() {
		return getContainer().getDecoratedName();
	}

	@Override
	public int loadAll(TaskMonitor monitor) throws CancelledException {
		int count = 1;
		if (!isLoaded()) {
			return count;
// This was too aggressive: these children do not have provider or any of 
//   the necessary fields for constructing a node
//			if (container.getCurrentChildren() == null) {
//				return count;
//			}
//			doSetChildren(tree.update(container));
		}
		List<GTreeNode> children = children();
		monitor = new TreeTaskMonitor(monitor, children.size());
		for (GTreeNode child : children) {
			monitor.checkCanceled();
			count += child.loadAll(monitor);
			monitor.incrementProgress(1);
		}
		return count;
	}

	@Override
	public Icon getIcon(boolean expanded) {
		TargetObject targetObject = container.getTargetObject();
		if (targetObject instanceof TargetExecutionStateful) {
			TargetExecutionStateful stateful = (TargetExecutionStateful) targetObject;
			if (stateful.getExecutionState().equals(TargetExecutionState.RUNNING)) {
				return ICON_RUNNING;
			}
			if (stateful.getExecutionState().equals(TargetExecutionState.TERMINATED)) {
				return ICON_TERMINATED;
			}
		}
		/*
		Map<String, Object> attributeMap = container.getAttributeMap();
		if (attributeMap.containsKey(TargetExecutionStateful.STATE_ATTRIBUTE_NAME)) {
			Object object = attributeMap.get(TargetExecutionStateful.STATE_ATTRIBUTE_NAME);
			if (object.equals(TargetExecutionState.RUNNING)) {
				return ICON_RUNNING;
			}
		}
		*/
		DebuggerObjectsProvider provider = getProvider();
		if (provider != null) {
			ObjectContainer rootContainer = provider.getRoot();
			Map<String, Object> rootMap = rootContainer.getAttributeMap();
			if (rootMap.containsKey(TargetEventScope.EVENT_OBJECT_ATTRIBUTE_NAME)) {
				TargetThread targetProcess =
					(TargetThread) rootMap.get(TargetEventScope.EVENT_OBJECT_ATTRIBUTE_NAME);
				if (container.getTargetObject().equals(targetProcess)) {
					return ICON_EVENT;
				}
			}
		}
		return container.hasElements() ? ICON_POPULATED : ICON_EMPTY;
	}

	@Override
	public String getToolTip() {
		return container.getDecoratedName();
	}

	@Override
	public boolean isLeaf() {
		TargetObject to = container.getTargetObject();
		return to != null && to instanceof DummyTargetObject;
	}

	public boolean isVisible() {
		return container.isVisible();
	}

	public void markExpanded() {
		//container.subscribe();
	}

	public void markCollapsed() {
		//container.unsubscribe();
	}

	public void cleanUpOldChildren(List<GTreeNode> newChildren) {
		if (oldChildren != null) {
			synchronized (oldChildren) {
				oldChildren.removeAll(newChildren);
				for (GTreeNode node : oldChildren) {
					setRestructured(true);
					tree.cleanupOldNode((ObjectNode) node);
				}
			}
		}
		oldChildren = new HashSet<>(newChildren);
	}

	public void callUpdate() {
		// NB: this has to be in its own thread
		CompletableFuture.runAsync(new Runnable() {
			@Override
			public void run() {
				List<GTreeNode> updateNodes = tree.update(container);
				if (isRestructured()) {
					setChildren(updateNodes);
				}
			}
		});
	}

	public void callModified() {
		// NB: this has to be in its own thread
		CompletableFuture.runAsync(new Runnable() {
			@Override
			public void run() {
				List<GTreeNode> updateNodes = tree.update(container);
				for (GTreeNode n : updateNodes) {
					n.fireNodeChanged(ObjectNode.this, n);
				}
			}
		});
	}

	public boolean isRestructured() {
		return restructured;
	}

	public void setRestructured(boolean restructured) {
		this.restructured = restructured;
	}

}
