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
package ghidra.app.plugin.core.debug.gui.target;

import static ghidra.app.plugin.core.debug.gui.DebuggerResources.showError;

import java.awt.BorderLayout;
import java.awt.event.MouseEvent;

import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.tree.TreePath;
import javax.swing.tree.TreeSelectionModel;

import docking.ActionContext;
import docking.WindowPosition;
import docking.action.*;
import docking.widgets.tree.*;
import docking.widgets.tree.support.GTreeSelectionEvent.EventOrigin;
import ghidra.app.plugin.core.debug.DebuggerPluginPackage;
import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.app.plugin.core.debug.gui.DebuggerResources.*;
import ghidra.app.services.DebuggerModelService;
import ghidra.dbg.DebuggerObjectModel;
import ghidra.framework.plugintool.AutoService;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.annotation.AutoServiceConsumed;

public class DebuggerTargetsProvider extends ComponentProviderAdapter {

	protected static DebuggerModelService getModelServiceFromContext(ActionContext context) {
		if (!(context instanceof DebuggerModelActionContext)) {
			return null;
		}
		DebuggerModelActionContext ctx = (DebuggerModelActionContext) context;
		return ctx.getIfModelService();
	}

	protected static DebuggerObjectModel getModelFromContext(ActionContext context) {
		if (!(context instanceof DebuggerModelActionContext)) {
			return null;
		}
		DebuggerModelActionContext ctx = (DebuggerModelActionContext) context;
		return ctx.getIfDebuggerModel();
	}

	protected class FlushCachesAction extends AbstractFlushCachesAction {
		public static final String GROUP = DebuggerResources.GROUP_MAINTENANCE;

		public FlushCachesAction() {
			super(plugin);
			setPopupMenuData(new MenuData(new String[] { NAME }, GROUP));
			addLocalAction(this);
			setEnabled(true);
		}

		@Override
		public void actionPerformed(ActionContext context) {
			DebuggerModelService service = myActionContext.getIfModelService();
			if (service != null) {
				clearServiceCaches(service);
				return;
			}
			DebuggerObjectModel model = myActionContext.getIfDebuggerModel();
			if (model != null) {
				model.invalidateAllLocalCaches();
				return;
			}
		}

		@Override
		public boolean isAddToPopup(ActionContext context) {
			if (myActionContext.getIfModelService() != null) {
				return true;
			}
			if (myActionContext.getIfDebuggerModel() != null) {
				return true;
			}
			return false;
		}
	}

	protected class ConnectAction extends AbstractConnectAction {
		public static final String GROUP = DebuggerResources.GROUP_CONNECTION;

		public ConnectAction() {
			super(plugin);
			setToolBarData(new ToolBarData(ICON, GROUP));
			setPopupMenuData(new MenuData(new String[] { NAME }, ICON, GROUP));
			addLocalAction(this);
		}

		@Override
		public void actionPerformed(ActionContext context) {
			// NB. Drop the future on the floor, because the UI will report issues.
			// Cancellation should be ignored.
			modelService.showConnectDialog();
		}

		@Override
		public boolean isAddToPopup(ActionContext context) {
			return getModelServiceFromContext(myActionContext) != null;
		}

		@Override
		public boolean isEnabledForContext(ActionContext context) {
			return modelService != null;
		}
	}

	protected class DisconnectAction extends AbstractDisconnectAction {
		public static final String GROUP = DebuggerResources.GROUP_CONNECTION;

		public DisconnectAction() {
			super(plugin);
			setMenuBarData(new MenuData(new String[] { NAME }, ICON, GROUP));
			setPopupMenuData(new MenuData(new String[] { NAME }, ICON, GROUP));
			addLocalAction(this);
			setEnabled(false);
		}

		@Override
		public void actionPerformed(ActionContext context) {
			DebuggerObjectModel model = getModelFromContext(myActionContext);
			if (model == null) {
				return;
			}
			model.close().exceptionally(showError(getComponent(), "Problem disconnecting"));
		}

		@Override
		public boolean isAddToPopup(ActionContext context) {
			return getModelFromContext(myActionContext) != null;
		}

		@Override
		public boolean isEnabledForContext(ActionContext context) {
			return getModelFromContext(myActionContext) != null;
		}
	}

	final DebuggerTargetsPlugin plugin;

	@AutoServiceConsumed
	DebuggerModelService modelService;
	@SuppressWarnings("unused")
	private final AutoService.Wiring autoServiceWiring;

	private JPanel mainPanel;
	protected GTree tree;
	protected DebuggerConnectionsNode rootNode;

	ConnectAction actionConnect;
	DisconnectAction actionDisconnect;
	DockingAction actionDisconnectAll;
	FlushCachesAction actionFlushCaches;

	DebuggerModelActionContext myActionContext;

	public DebuggerTargetsProvider(final DebuggerTargetsPlugin plugin) {
		super(plugin.getTool(), DebuggerResources.TITLE_PROVIDER_TARGETS, plugin.getName());
		this.plugin = plugin;

		this.autoServiceWiring = AutoService.wireServicesConsumed(plugin, this);

		setTitle(DebuggerResources.TITLE_PROVIDER_TARGETS);
		setIcon(DebuggerResources.ICON_PROVIDER_TARGETS);
		setHelpLocation(DebuggerResources.HELP_PROVIDER_TARGETS);
		setWindowMenuGroup(DebuggerPluginPackage.NAME);

		buildMainPanel();

		setDefaultWindowPosition(WindowPosition.LEFT);
		setVisible(true);
		createActions();

		myActionContext = new DebuggerModelActionContext(this, null, tree);
	}

	@Override
	public void addLocalAction(DockingActionIf action) {
		super.addLocalAction(action);
	}

	private void createActions() {
		actionConnect = new ConnectAction();
		actionDisconnect = new DisconnectAction();
		actionDisconnectAll = DisconnectAllAction.builder(plugin, plugin)
				.menuPath(DisconnectAllAction.NAME)
				.onAction(this::activatedDisconnectAll)
				.buildAndInstallLocal(this);
		actionFlushCaches = new FlushCachesAction();
	}

	private void activatedDisconnectAll(ActionContext context) {
		if (modelService == null) {
			return;
		}
		modelService.closeAllModels();
	}

	@Override
	public ActionContext getActionContext(MouseEvent event) {
		if (myActionContext == null) {
			return super.getActionContext(event);
		}
		return myActionContext;
	}

	@Override
	public JComponent getComponent() {
		return mainPanel;
	}

	private void setContext() {
		myActionContext = new DebuggerModelActionContext(this, tree.getSelectionPath(), tree);
		contextChanged();
	}

	private void emitEvents() {
		DebuggerObjectModel model = myActionContext.getIfDebuggerModel();
		if (model != null) {
			modelService.activateModel(model);
		}
	}

	private void buildMainPanel() {
		mainPanel = new JPanel(new BorderLayout());

		rootNode = new DebuggerConnectionsNode(modelService, this);
		tree = new GTree(rootNode);
		tree.setRootVisible(false);
		tree.getSelectionModel().setSelectionMode(TreeSelectionModel.SINGLE_TREE_SELECTION);
		mainPanel.add(tree);

		// NB: for both of these, setContext should precede emitEvents
		tree.getGTSelectionModel().addGTreeSelectionListener(evt -> {
			setContext();
			if (evt.getEventOrigin() != EventOrigin.API_GENERATED) {
				emitEvents();
			}
		});
		tree.addGTModelListener((AnyChangeTreeModelListener) e -> {
			setContext();
			emitEvents();
		});
	}

	@AutoServiceConsumed
	private void setModelService(DebuggerModelService modelService) {
		if (tree != null) {
			rootNode = new DebuggerConnectionsNode(modelService, this);
			tree.setRootNode(rootNode);
		}
	}

	protected void updateTree(boolean select, Object obj) {
		if (tree == null) {
			return;
		}
		tree.repaint();
		if (!select) {
			return;
		}
		GTreeNode node = rootNode.findNodeForObject(obj);
		if (node != null) {
			tree.setSelectedNode(node);
			myActionContext = new DebuggerModelActionContext(this, node.getTreePath(), tree);
			contextChanged();
		}
	}

	public void modelActivated(DebuggerObjectModel model) {
		if (rootNode == null || tree == null) {
			return;
		}
		GTreeNode node = rootNode.findNodeForObject(model);
		if (node == null) {
			return;
			// TODO: Ensure when tree is populated, correct model is selected
		}
		// Note, setSelectedNode does not take EventOrigin
		tree.setSelectionPaths(new TreePath[] { node.getTreePath() }, EventOrigin.API_GENERATED);
	}

	protected void clearServiceCaches(DebuggerModelService service) {
		for (DebuggerObjectModel model : service.getModels()) {
			model.invalidateAllLocalCaches();
		}
	}
}
