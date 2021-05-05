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

import java.awt.Point;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;

import javax.swing.ImageIcon;
import javax.swing.JComponent;
import javax.swing.event.TreeExpansionEvent;
import javax.swing.event.TreeExpansionListener;
import javax.swing.tree.TreePath;
import javax.swing.tree.TreeSelectionModel;

import docking.widgets.tree.GTree;
import docking.widgets.tree.GTreeNode;
import docking.widgets.tree.support.GTreeSelectionEvent;
import docking.widgets.tree.support.GTreeSelectionEvent.EventOrigin;
import docking.widgets.tree.support.GTreeSelectionListener;
import ghidra.app.plugin.core.debug.gui.objects.DebuggerObjectsProvider;
import ghidra.app.plugin.core.debug.gui.objects.ObjectContainer;
import ghidra.app.plugin.core.debug.mapping.DebuggerMemoryMapper;
import ghidra.app.services.*;
import ghidra.async.AsyncUtils;
import ghidra.async.TypeSpec;
import ghidra.dbg.DebugModelConventions;
import ghidra.dbg.target.TargetAccessConditioned;
import ghidra.dbg.target.TargetObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRangeImpl;
import ghidra.util.*;
import ghidra.util.task.SwingUpdateManager;
import resources.ResourceManager;

public class ObjectTree implements ObjectPane {

	public static final ImageIcon ICON_TREE =
		ResourceManager.loadImage("images/breakpoint-disable.png");

	private ObjectNode root;
	private GTree tree;
	private TreePath[] currentSelectionPaths;
	private List<TreePath> currentExpandedPaths;
	private Point currentViewPosition;

	private Map<String, ObjectNode> nodeMap = new LinkedHashMap<>();
	private SwingUpdateManager restoreTreeStateManager =
		new SwingUpdateManager(this::restoreTreeState);

	private DebuggerListingService listingService;
	private DebuggerModelService modelService;

	public ObjectTree(ObjectContainer container) {
		this.root = new ObjectNode(this, null, container);
		addToMap(null, container, root);
		this.tree = new GTree(root);

		this.listingService = container.getProvider().getListingService();
		this.modelService = container.getProvider().getModelService();

		tree.addGTreeSelectionListener(new GTreeSelectionListener() {
			@Override
			public void valueChanged(GTreeSelectionEvent e) {
				DebuggerObjectsProvider provider = container.getProvider();
				provider.updateActions(container);
				TreePath path = e.getPath();
				Object last = path.getLastPathComponent();
				if (last instanceof ObjectNode) {
					ObjectNode node = (ObjectNode) last;
					TargetObject targetObject = node.getTargetObject();
					if (targetObject != null && !(targetObject instanceof DummyTargetObject) &&
						e.getEventOrigin().equals(EventOrigin.USER_GENERATED)) {
						DebugModelConventions.requestActivation(targetObject).exceptionally(ex -> {
							Msg.error(this, "Could not activate " + targetObject, ex);
							return null;
						});
						DebugModelConventions.requestFocus(targetObject).exceptionally(ex -> {
							Msg.error(this, "Could not focus " + targetObject, ex);
							return null;
						});
					}
				}
				provider.getTool().contextChanged(provider);
				if (e.getEventOrigin() == EventOrigin.INTERNAL_GENERATED) {
					restoreTreeStateManager.updateLater();
					return;
				}
				TreePath[] selectionPaths = tree.getSelectionPaths();
				if (e.getEventOrigin() == EventOrigin.API_GENERATED) {
					if (currentSelectionPaths != null && currentSelectionPaths.length > 0) {
						if (selectionPaths != null && selectionPaths.length > 0) {
							TreePath currentPath = currentSelectionPaths[0];
							TreePath selectedPath = selectionPaths[0];
							// NB. isDescendant == has a descendent
							if (selectedPath.isDescendant(currentPath)) {
								return;
							}
						}
					}
				}
				currentSelectionPaths = selectionPaths;
				currentExpandedPaths = tree.getExpandedPaths();
				currentViewPosition = tree.getViewPosition();
				restoreTreeStateManager.updateLater();
			}
		});
		tree.setCellRenderer(new ObjectTreeCellRenderer(root.getProvider()));
		tree.setDataTransformer(new FilterTransformer<GTreeNode>() {

			@Override
			public List<String> transform(GTreeNode t) {
				if (t instanceof ObjectNode) {
					ObjectNode node = (ObjectNode) t;
					return List.of(node.getContainer().getDecoratedName());
				}
				return null;
			}
		});
		tree.addTreeExpansionListener(new TreeExpansionListener() {

			@Override
			public void treeExpanded(TreeExpansionEvent event) {
				TreePath expandedPath = event.getPath();
				Object last = expandedPath.getLastPathComponent();
				if (last instanceof ObjectNode) {
					ObjectNode node = (ObjectNode) last;
					if (!node.isExpanded()) {
						//currentExpandedPaths = tree.getExpandedPaths();
						node.markExpanded();
					}
				}
			}

			@Override
			public void treeCollapsed(TreeExpansionEvent event) {
				TreePath collapsedPath = event.getPath();
				Object last = collapsedPath.getLastPathComponent();
				if (last instanceof ObjectNode) {
					ObjectNode node = (ObjectNode) last;
					if (node.isExpanded()) {
						//currentExpandedPaths = tree.getExpandedPaths();
						node.markCollapsed();
					}
				}
			}
		});

		tree.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				if (e.getClickCount() == 2) {
					navigateToSelectedObject();
				}
			}
		});

		tree.getSelectionModel().setSelectionMode(TreeSelectionModel.SINGLE_TREE_SELECTION);
		tree.setSelectedNode(root);
	}

	@Override
	public ObjectContainer getContainer() {
		return root.getContainer();
	}

	@Override
	public TargetObject getTargetObject() {
		return root.getTargetObject();
	}

	public DebuggerObjectsProvider getProvider() {
		return root.getProvider();
	}

	@Override
	public TargetObject getSelectedObject() {
		TreePath path = tree.getSelectionPath();
		if (path != null) {
			Object last = path.getLastPathComponent();
			if (last instanceof ObjectNode) {
				return ((ObjectNode) last).getContainer().getTargetObject();
			}
		}
		return null;
	}

	@Override
	public JComponent getComponent() {
		return tree;
	}

	@Override
	public JComponent getPrincipalComponent() {
		return tree;
	}

	private void restoreTreeState() {
		if (currentExpandedPaths != null) {
			tree.expandPaths(currentExpandedPaths);
		}
		if (currentSelectionPaths != null) {
			tree.setSelectionPaths(currentSelectionPaths);
		}
		if (currentViewPosition != null) {
			tree.runTask(m -> {
				if (currentViewPosition != null) {
					tree.setViewPosition(currentViewPosition);
				}
				currentViewPosition = null;
			});
		}
	}

	@Override
	public String getName() {
		TargetObject targetObject = getTargetObject();
		return targetObject == null ? "Main" : targetObject.getName();
	}

	@Override
	public void signalContentsChanged(ObjectContainer container) {
		ObjectNode node = nodeMap.get(path(container));
		if (node != null) {
			node.callUpdate();
		}
	}

	@Override
	public void signalDataChanged(ObjectContainer container) {
		Swing.runIfSwingOrRunLater(() -> {
			ObjectNode node = nodeMap.get(path(container));
			if (node != null) {
				node.setContainer(this, container.getParent(), container);
				node.fireNodeChanged(node.getParent(), node);
			}
		});
	}

	@Override
	public void signalUpdate(ObjectContainer container) {
		AtomicReference<TargetAccessConditioned> access = new AtomicReference<>();
		TargetObject targetObject = container.getTargetObject();
		if (targetObject == null) {
			return;
		}
		AsyncUtils.sequence(TypeSpec.VOID).then(seq -> {
			DebugModelConventions.findSuitable(TargetAccessConditioned.class, targetObject)
					.handle(seq::next);
		}, access).then(seq -> {
			boolean accessible = true;
			TargetAccessConditioned conditioned = access.get();
			if (conditioned != null) {
				accessible = conditioned.isAccessible();
			}
			if (accessible) {
				Swing.runIfSwingOrRunLater(() -> {
					ObjectNode node = nodeMap.get(path(container));
					//Msg.debug(this, "update node: " + node);
					if (node != null) {
						if (currentSelectionPaths == null) {
							currentSelectionPaths = tree.getSelectionPaths();
						}
						if (currentExpandedPaths == null) {
							currentExpandedPaths = tree.getExpandedPaths();
						}
						if (currentViewPosition == null) {
							currentViewPosition = tree.getViewPosition();
						}
						tree.runTask(monitor -> node.unloadChildren());
						restoreTreeStateManager.updateLater();
					}
				});
			}
		}).finish();
	}

	public void waitOnLoad() {
		List<TreePath> expandedPaths = tree.getExpandedPaths();
		while (!checkLoaded(expandedPaths)) {
			try {
				Thread.sleep(10);
			}
			catch (InterruptedException e) {
				e.printStackTrace();
			}
		}
	}

	private boolean checkLoaded(List<TreePath> expandedPaths) {
		for (TreePath path : expandedPaths) {
			Object[] objs = path.getPath();
			for (int i = 0; i < objs.length - 2; i++) {
				if (objs[i] instanceof ObjectNode) {
					ObjectNode node = (ObjectNode) objs[i];
					if (!node.isLoaded()) {
						return false;
					}
				}
			}
		}
		return true;
	}

	@Override
	public List<GTreeNode> update(ObjectContainer container) {
		ObjectNode node = nodeMap.get(path(container));
		if (node == null) {
			if (path(container) != null) {
				Msg.warn(this, "Missing node: " + path(container));
			}
			return new ArrayList<>();
		}

		Set<ObjectContainer> currentChildren = container.getCurrentChildren();
		List<GTreeNode> childList = new ArrayList<GTreeNode>();

		node.setRestructured(false);
		for (ObjectContainer c : currentChildren) {
			ObjectNode nc;
			String path = path(c);
			boolean hideIntrinsics = getContainer().getProvider().isHideIntrinsics();
			if (c.isVisible() || !hideIntrinsics) {
				if (nodeMap.containsKey(path)) {
					nc = nodeMap.get(path);
					nc.setContainer(this, container, c);
				}
				else {
					node.setRestructured(true);
					nc = new ObjectNode(this, container, c);
				}
				childList.add(nc);
			}
		}
		node.markExpanded();
		node.cleanUpOldChildren(childList);
		return childList;
	}

	private String path(ObjectContainer container) {
		if (container == null) {
			return null;
		}
		return container.getTreePath();
	}

	@Override
	public void setFocus(TargetObject object, TargetObject focused) {
		Swing.runIfSwingOrRunLater(() -> {
			List<String> path = focused.getPath();
			tree.setSelectedNodeByNamePath(addRootNameToPath(path));
		});
	}

	private String[] addRootNameToPath(List<String> path) {
		String[] fullPath = new String[path.size() + 1];
		fullPath[0] = tree.getModelRoot().getName();
		for (int i = 0; i < path.size(); i++) {
			fullPath[i + 1] = path.get(i);
		}
		return fullPath;
	}

	public void addToMap(ObjectContainer parent, ObjectContainer container, ObjectNode node) {
		String ppath = parent == null ? "" : parent.getTreePath();
		String tpath = ppath + ":" + node.getName();
		container.setTreePath(tpath);
		nodeMap.put(tpath, node);
	}

	@Override
	public void setRoot(ObjectContainer container, TargetObject targetObject) {
		nodeMap.remove(path(container));
		container.setTargetObject(targetObject);
		root.setContainer(this, null, container);
		nodeMap.put(path(container), root);
		tree.setRootVisible(true);
		//	tree.setSelectedNode(root);
	}

	public void setSelectedNode(ObjectNode node) {
		if (tree != null) {
			tree.setSelectedNode(node);
		}
	}

	public void cleanupOldNode(ObjectNode node) {
		DebuggerObjectsProvider provider = getProvider();
		ObjectContainer oc = node.getContainer();
		provider.deleteFromMap(oc);
		oc.getTargetObject().removeListener(provider.getListener());
		nodeMap.remove(path(node.getContainer()));
	}

	protected void navigateToSelectedObject() {
		if (listingService != null) {
			TargetObject selectedObject = getSelectedObject();
			if (selectedObject == null) {
				return;
			}
			Object value = selectedObject.getCachedAttribute(TargetObject.VALUE_ATTRIBUTE_NAME);
			Address addr = null;
			if (value instanceof Address) {
				addr = (Address) value;
			}
			if (value instanceof AddressRangeImpl) {
				AddressRangeImpl range = (AddressRangeImpl) value;
				addr = range.getMinAddress();
			}
			if (value instanceof Long) {
				Long lval = (Long) value;
				addr = selectedObject.getModel().getAddress("ram", lval);
			}
			if (modelService != null && addr != null) {
				TraceRecorder recorder = modelService.getRecorderForSuccessor(selectedObject);
				DebuggerMemoryMapper memoryMapper = recorder.getMemoryMapper();
				Address traceAddr = memoryMapper.targetToTrace(addr);
				listingService.goTo(traceAddr, true);
			}
		}
	}
}
