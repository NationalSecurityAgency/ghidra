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
package ghidra.app.plugin.core.debug.gui.tracermi.connection;

import java.awt.AWTEvent;
import java.awt.BorderLayout;
import java.awt.event.*;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

import javax.swing.*;
import javax.swing.tree.TreeSelectionModel;

import docking.ActionContext;
import docking.WindowPosition;
import docking.action.DockingAction;
import docking.action.builder.ActionBuilder;
import docking.widgets.tree.*;
import ghidra.app.plugin.core.debug.DebuggerPluginPackage;
import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.app.plugin.core.debug.gui.objects.components.DebuggerMethodInvocationDialog;
import ghidra.app.plugin.core.debug.gui.tracermi.connection.tree.*;
import ghidra.app.services.*;
import ghidra.dbg.target.TargetMethod.ParameterDescription;
import ghidra.dbg.target.TargetMethod.TargetParameterMap;
import ghidra.debug.api.control.ControlMode;
import ghidra.debug.api.target.Target;
import ghidra.debug.api.tracemgr.DebuggerCoordinates;
import ghidra.debug.api.tracermi.TraceRmiAcceptor;
import ghidra.debug.api.tracermi.TraceRmiConnection;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.AutoService.Wiring;
import ghidra.framework.plugintool.annotation.AutoServiceConsumed;
import ghidra.framework.plugintool.util.PluginUtils;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;

public class TraceRmiConnectionManagerProvider extends ComponentProviderAdapter {
	public static final String TITLE = "Connections";
	public static final HelpLocation HELP =
		new HelpLocation(PluginUtils.getPluginNameFromClass(TraceRmiConnectionManagerPlugin.class),
			DebuggerResources.HELP_ANCHOR_PLUGIN);

	private static final String GROUP_SERVER = "2. Server";
	private static final String GROUP_CONNECT = "1. Connect";
	private static final String GROUP_MAINTENANCE = "3. Maintenance";

	private static final ParameterDescription<String> PARAM_ADDRESS =
		ParameterDescription.create(String.class, "address", true, "localhost",
			"Host/Address", "Address or hostname for interface(s) to listen on");
	private static final ParameterDescription<Integer> PARAM_PORT =
		ParameterDescription.create(Integer.class, "port", true, 0,
			"Port", "TCP port number, 0 for ephemeral");
	private static final TargetParameterMap PARAMETERS = TargetParameterMap.ofEntries(
		Map.entry(PARAM_ADDRESS.name, PARAM_ADDRESS),
		Map.entry(PARAM_PORT.name, PARAM_PORT));

	interface StartServerAction {
		String NAME = "Start Server";
		String DESCRIPTION = "Start a TCP server for incoming connections (indefinitely)";
		String GROUP = GROUP_SERVER;
		String HELP_ANCHOR = "start_server";

		static ActionBuilder builder(Plugin owner) {
			String ownerName = owner.getName();
			return new ActionBuilder(NAME, ownerName)
					.description(DESCRIPTION)
					.menuPath(NAME)
					.menuGroup(GROUP)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
		}
	}

	interface StopServerAction {
		String NAME = "Stop Server";
		String DESCRIPTION = "Close the TCP server";
		String GROUP = GROUP_SERVER;
		String HELP_ANCHOR = "stop_server";

		static ActionBuilder builder(Plugin owner) {
			String ownerName = owner.getName();
			return new ActionBuilder(NAME, ownerName)
					.description(DESCRIPTION)
					.menuPath(NAME)
					.menuGroup(GROUP)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
		}
	}

	interface ConnectAcceptAction {
		String NAME = "Connect by Accept";
		String DESCRIPTION = "Accept a single inbound TCP connection";
		String GROUP = GROUP_CONNECT;
		Icon ICON = DebuggerResources.ICON_CONNECT_ACCEPT;
		String HELP_ANCHOR = "connect_accept";

		static ActionBuilder builder(Plugin owner) {
			String ownerName = owner.getName();
			return new ActionBuilder(NAME, ownerName)
					.description(DESCRIPTION)
					.toolBarIcon(ICON)
					.toolBarGroup(GROUP)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
		}
	}

	interface ConnectOutboundAction {
		String NAME = "Connect Outbound";
		String DESCRIPTION = "Connect to a listening agent/plugin by TCP";
		String GROUP = GROUP_CONNECT;
		Icon ICON = DebuggerResources.ICON_CONNECT_OUTBOUND;
		String HELP_ANCHOR = "connect_outbound";

		static ActionBuilder builder(Plugin owner) {
			String ownerName = owner.getName();
			return new ActionBuilder(NAME, ownerName)
					.description(DESCRIPTION)
					.toolBarIcon(ICON)
					.toolBarGroup(GROUP)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
		}
	}

	interface CloseConnectionAction {
		String NAME = "Close";
		String DESCRIPTION = "Close a connection or server";
		String GROUP = GROUP_MAINTENANCE;
		String HELP_ANCHOR = "close";

		static ActionBuilder builder(Plugin owner) {
			String ownerName = owner.getName();
			return new ActionBuilder(NAME, ownerName)
					.description(DESCRIPTION)
					.menuPath(NAME)
					.popupMenuPath(NAME)
					.menuGroup(GROUP)
					.popupMenuGroup(GROUP)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
		}
	}

	interface CloseAllAction {
		String NAME = "Close All";
		String DESCRIPTION = "Close all connections and the server";
		String GROUP = GROUP_MAINTENANCE;
		String HELP_ANCHOR = "close_all";

		static ActionBuilder builder(Plugin owner) {
			String ownerName = owner.getName();
			return new ActionBuilder(NAME, ownerName)
					.description(DESCRIPTION)
					.menuPath(NAME)
					.menuGroup(GROUP)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
		}
	}

	class InjectableGTree extends GTree {
		public InjectableGTree(GTreeNode root) {
			super(root);
		}

		/**
		 * This allows the test framework to use reflection to access this method.
		 */
		@Override
		protected void processEvent(AWTEvent e) {
			super.processEvent(e);
		}
	}

	private final TraceRmiConnectionManagerPlugin plugin;

	// @AutoServiceConsumed via method
	TraceRmiService traceRmiService;
	// @AutoServiceConsumed via method
	DebuggerTargetService targetService;
	@AutoServiceConsumed
	DebuggerConsoleService consoleService;
	@AutoServiceConsumed
	DebuggerTraceManagerService traceManagerService;
	@AutoServiceConsumed
	DebuggerControlService controlService;
	@SuppressWarnings("unused")
	private final Wiring autoServiceWiring;

	private JPanel mainPanel;
	protected GTree tree;
	protected TraceRmiServiceNode rootNode = new TraceRmiServiceNode(this);

	DockingAction actionStartServer;
	DockingAction actionStopServer;
	DockingAction actionConnectAccept;
	DockingAction actionConnectOutbound;
	DockingAction actionCloseConnection;
	DockingAction actionCloseAll;

	TraceRmiManagerActionContext myActionContext;

	public TraceRmiConnectionManagerProvider(TraceRmiConnectionManagerPlugin plugin) {
		super(plugin.getTool(), TITLE, plugin.getName());
		this.plugin = plugin;

		this.autoServiceWiring = AutoService.wireServicesConsumed(plugin, this);
		setTitle(TITLE);
		setIcon(DebuggerResources.ICON_PROVIDER_TARGETS);
		setHelpLocation(HELP);
		setWindowMenuGroup(DebuggerPluginPackage.NAME);

		buildMainPanel();

		setDefaultWindowPosition(WindowPosition.LEFT);
		setVisible(true);
		createActions();
	}

	private void buildMainPanel() {
		mainPanel = new JPanel(new BorderLayout());

		tree = new InjectableGTree(rootNode);
		tree.setRootVisible(false);
		tree.getSelectionModel().setSelectionMode(TreeSelectionModel.SINGLE_TREE_SELECTION);
		mainPanel.add(tree);

		tree.getGTSelectionModel().addGTreeSelectionListener(evt -> {
			setContext();
		});
		tree.addGTModelListener((AnyChangeTreeModelListener) e -> {
			setContext();
		});
		// TODO: Double-click or ENTER (activate) should open and/or activate trace/snap
		tree.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				if (e.getClickCount() == 2 && e.getButton() == MouseEvent.BUTTON1) {
					activateSelectedNode();
					e.consume();
				}
			}
		});
		tree.addKeyListener(new KeyAdapter() {
			@Override
			public void keyPressed(KeyEvent e) {
				if (e.getKeyCode() == KeyEvent.VK_ENTER) {
					activateSelectedNode();
					e.consume();
				}
			}
		});
	}

	private void activateSelectedNode() {
		List<GTreeNode> selList = tree.getSelectedNodes();
		if (selList.isEmpty()) {
			return;
		}
		assert selList.size() == 1;
		GTreeNode sel = selList.get(0);
		nodeActivated((TraceRmiManagerNode) sel);
	}

	private void nodeActivated(TraceRmiManagerNode node) {
		if (node instanceof TraceRmiTargetNode tNode) {
			if (traceManagerService == null) {
				return;
			}
			Target target = tNode.getTarget();
			traceManagerService.activateTarget(target);
			if (controlService == null) {
				return;
			}
			if (!controlService.getCurrentMode(target.getTrace()).isTarget()) {
				controlService.setCurrentMode(target.getTrace(), ControlMode.RO_TARGET);
			}
		}
	}

	private void createActions() {
		actionStartServer = StartServerAction.builder(plugin)
				.enabledWhen(this::isActionStartServerEnabled)
				.onAction(this::doActionStartServerActivated)
				.buildAndInstallLocal(this);
		actionStopServer = StopServerAction.builder(plugin)
				.enabledWhen(this::isActionStopServerEnabled)
				.onAction(this::doActionStopServerActivated)
				.buildAndInstallLocal(this);

		actionConnectAccept = ConnectAcceptAction.builder(plugin)
				.enabledWhen(this::isActionConnectAcceptEnabled)
				.onAction(this::doActionConnectAcceptActivated)
				.buildAndInstallLocal(this);
		actionConnectOutbound = ConnectOutboundAction.builder(plugin)
				.enabledWhen(this::isActionConnectOutboundEnabled)
				.onAction(this::doActionConnectOutboundActivated)
				.buildAndInstallLocal(this);

		actionCloseConnection = CloseConnectionAction.builder(plugin)
				.withContext(TraceRmiManagerActionContext.class)
				.enabledWhen(this::isActionCloseConnectionEnabled)
				.onAction(this::doActionCloseConnectionActivated)
				.buildAndInstallLocal(this);
		actionCloseAll = CloseAllAction.builder(plugin)
				.enabledWhen(this::isActionCloseAllEnabled)
				.onAction(this::doActionCloseAllActivated)
				.buildAndInstallLocal(this);
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
		myActionContext = new TraceRmiManagerActionContext(this, tree.getSelectionPath(), tree);
		contextChanged();
	}

	private boolean isActionStartServerEnabled(ActionContext __) {
		return traceRmiService != null && !traceRmiService.isServerStarted();
	}

	private InetSocketAddress promptSocketAddress(String title, String okText) {
		DebuggerMethodInvocationDialog dialog = new DebuggerMethodInvocationDialog(tool,
			title, okText, DebuggerResources.ICON_CONNECTION);
		Map<String, ?> arguments;
		do {
			dialog.forgetMemorizedArguments();
			arguments = dialog.promptArguments(PARAMETERS);
		}
		while (dialog.isResetRequested());
		if (arguments == null) {
			return null;
		}
		String address = PARAM_ADDRESS.get(arguments);
		int port = PARAM_PORT.get(arguments);
		return new InetSocketAddress(address, port);
	}

	private void doActionStartServerActivated(ActionContext __) {
		InetSocketAddress sockaddr = promptSocketAddress("Start Trace RMI Server", "Start");
		if (sockaddr == null) {
			return;
		}
		try {
			traceRmiService.setServerAddress(sockaddr);
			traceRmiService.startServer();
			if (consoleService != null) {
				consoleService.log(DebuggerResources.ICON_CONNECTION,
					"TraceRmi Server listening at " + traceRmiService.getServerAddress());
			}
		}
		catch (Exception e) {
			Msg.error(this, "Could not start TraceRmi server: " + e);
		}
	}

	private boolean isActionStopServerEnabled(ActionContext __) {
		return traceRmiService != null && traceRmiService.isServerStarted();
	}

	private void doActionStopServerActivated(ActionContext __) {
		traceRmiService.stopServer();
		if (consoleService != null) {
			consoleService.log(DebuggerResources.ICON_DISCONNECT, "TraceRmi Server stopped");
		}
	}

	private boolean isActionConnectAcceptEnabled(ActionContext __) {
		return traceRmiService != null;
	}

	private void doActionConnectAcceptActivated(ActionContext __) {
		InetSocketAddress sockaddr = promptSocketAddress("Accept Trace RMI Connection", "Listen");
		if (sockaddr == null) {
			return;
		}
		CompletableFuture.runAsync(() -> {
			// TODO: Progress entry
			try {
				TraceRmiAcceptor acceptor = traceRmiService.acceptOne(sockaddr);
				acceptor.accept();
			}
			catch (CancelledException e) {
				// Nothing. User should already know.
			}
			catch (Throwable e) {
				Msg.showError(this, null, "Accept",
					"Could not accept Trace RMI Connection on " + sockaddr + ": " + e);
			}
		});
	}

	private boolean isActionConnectOutboundEnabled(ActionContext __) {
		return traceRmiService != null;
	}

	private void doActionConnectOutboundActivated(ActionContext __) {
		InetSocketAddress sockaddr = promptSocketAddress("Connect to Trace RMI", "Connect");
		if (sockaddr == null) {
			return;
		}
		CompletableFuture.runAsync(() -> {
			// TODO: Progress entry?
			try {
				traceRmiService.connect(sockaddr);
			}
			catch (Throwable e) {
				Msg.showError(this, null, "Connect",
					"Could connect to Trace RMI at " + sockaddr + ": " + e.getMessage());
			}
		});
	}

	private boolean isActionCloseConnectionEnabled(TraceRmiManagerActionContext context) {
		TraceRmiManagerNode node = context.getSelectedNode();
		if (node instanceof TraceRmiConnectionNode) {
			return true;
		}
		if (node instanceof TraceRmiAcceptorNode) {
			return true;
		}
		return false;
	}

	private void doActionCloseConnectionActivated(TraceRmiManagerActionContext context) {
		TraceRmiManagerNode node = context.getSelectedNode();
		if (node instanceof TraceRmiConnectionNode cxNode) {
			try {
				cxNode.getConnection().close();
			}
			catch (IOException e) {
				Msg.showError(this, null, "Close Connection",
					"Could not close Trace RMI connection: " + e);
			}
		}
		else if (node instanceof TraceRmiAcceptorNode acNode) {
			acNode.getAcceptor().cancel();
		}
	}

	private boolean isActionCloseAllEnabled(ActionContext __) {
		return traceRmiService != null;
	}

	private void doActionCloseAllActivated(ActionContext __) {
		try {
			doActionStopServerActivated(__);
		}
		catch (Throwable e) {
			Msg.error(this, "Could not close server: " + e);
		}
		for (TraceRmiConnection connection : traceRmiService.getAllConnections()) {
			try {
				connection.close();
			}
			catch (Throwable e) {
				Msg.error(this, "Could not close " + connection + ": " + e);
			}
		}
		for (TraceRmiAcceptor acceptor : traceRmiService.getAllAcceptors()) {
			try {
				acceptor.cancel();
			}
			catch (Throwable e) {
				Msg.error(this, "Could not cancel " + acceptor + ": " + e);
			}
		}
	}

	@AutoServiceConsumed
	private void setTraceRmiService(TraceRmiService traceRmiService) {
		if (this.traceRmiService != null) {
			this.traceRmiService.removeTraceServiceListener(rootNode);
		}
		this.traceRmiService = traceRmiService;
		if (this.traceRmiService != null) {
			this.traceRmiService.addTraceServiceListener(rootNode);
		}
	}

	@AutoServiceConsumed
	private void setTargetService(DebuggerTargetService targetService) {
		if (this.targetService != null) {
			this.targetService.removeTargetPublicationListener(rootNode);
		}
		this.targetService = targetService;
		if (this.targetService != null) {
			this.targetService.addTargetPublicationListener(rootNode);
		}
	}

	public TraceRmiService getTraceRmiService() {
		return traceRmiService;
	}

	/**
	 * Coordinates, whether active or inactive, for a trace changed
	 * 
	 * @param coordinates the coordinates
	 */
	public void coordinates(DebuggerCoordinates coordinates) {
		if (rootNode == null) {
			return;
		}
		rootNode.coordinates(coordinates);
	}
}
