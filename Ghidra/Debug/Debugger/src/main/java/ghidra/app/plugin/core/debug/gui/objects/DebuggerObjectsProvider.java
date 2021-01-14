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
package ghidra.app.plugin.core.debug.gui.objects;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.event.MouseEvent;
import java.lang.invoke.MethodHandles;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicReference;

import javax.swing.*;
import javax.swing.tree.TreePath;

import org.apache.commons.collections4.map.LinkedMap;
import org.apache.commons.lang3.StringUtils;

import docking.ActionContext;
import docking.WindowPosition;
import docking.action.*;
import docking.action.builder.ActionBuilder;
import docking.action.builder.ToggleActionBuilder;
import docking.widgets.table.DefaultEnumeratedColumnTableModel;
import docking.widgets.tree.GTree;
import ghidra.app.plugin.core.debug.DebuggerCoordinates;
import ghidra.app.plugin.core.debug.DebuggerPluginPackage;
import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.app.plugin.core.debug.gui.DebuggerResources.*;
import ghidra.app.plugin.core.debug.gui.objects.actions.*;
import ghidra.app.plugin.core.debug.gui.objects.components.*;
import ghidra.app.services.*;
import ghidra.async.AsyncUtils;
import ghidra.async.TypeSpec;
import ghidra.dbg.DebugModelConventions;
import ghidra.dbg.DebuggerObjectModel;
import ghidra.dbg.attributes.TargetObjectRef;
import ghidra.dbg.error.DebuggerMemoryAccessException;
import ghidra.dbg.target.*;
import ghidra.dbg.target.TargetAccessConditioned.TargetAccessibility;
import ghidra.dbg.target.TargetAccessConditioned.TargetAccessibilityListener;
import ghidra.dbg.target.TargetConsole.Channel;
import ghidra.dbg.target.TargetExecutionStateful.TargetExecutionState;
import ghidra.dbg.target.TargetExecutionStateful.TargetExecutionStateListener;
import ghidra.dbg.target.TargetFocusScope.TargetFocusScopeListener;
import ghidra.dbg.target.TargetInterpreter.TargetInterpreterListener;
import ghidra.dbg.target.TargetLauncher.TargetCmdLineLauncher;
import ghidra.dbg.target.TargetMemory.TargetMemoryListener;
import ghidra.dbg.target.TargetObject.TargetObjectFetchingListener;
import ghidra.dbg.target.TargetRegisterBank.TargetRegisterBankListener;
import ghidra.dbg.target.TargetSteppable.TargetStepKind;
import ghidra.dbg.util.PathUtils;
import ghidra.framework.options.AutoOptions;
import ghidra.framework.options.SaveState;
import ghidra.framework.options.annotation.*;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.annotation.AutoConfigStateField;
import ghidra.framework.plugintool.annotation.AutoServiceConsumed;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.listing.Program;
import ghidra.trace.model.Trace;
import ghidra.trace.model.thread.TraceThread;
import ghidra.util.*;
import ghidra.util.table.GhidraTable;
import resources.ResourceManager;

public class DebuggerObjectsProvider extends ComponentProviderAdapter implements //AllTargetObjectListenerAdapter,
		TargetObjectFetchingListener, TargetAccessibilityListener, TargetExecutionStateListener,
		TargetFocusScopeListener, TargetInterpreterListener, TargetMemoryListener,
		TargetRegisterBankListener, ObjectContainerListener {

	public static final String PATH_JOIN_CHAR = ".";
	//private static final String AUTOUPDATE_ATTRIBUTE_NAME = "autoupdate";

	private static final AutoConfigState.ClassHandler<DebuggerObjectsProvider> CONFIG_STATE_HANDLER =
		AutoConfigState.wireHandler(DebuggerObjectsProvider.class, MethodHandles.lookup());

	private final DebuggerObjectsPlugin plugin;

	@AutoServiceConsumed
	public DebuggerModelService modelService;
	@AutoServiceConsumed
	private DebuggerTraceManagerService traceManager;
	@AutoServiceConsumed
	private DebuggerStaticMappingService mappingService;
	@AutoServiceConsumed
	private DebuggerListingService listingService;
	@AutoServiceConsumed
	private GraphDisplayBroker graphBroker;
	@AutoServiceConsumed
	private ConsoleService consoleService;
	@SuppressWarnings("unused")
	private final AutoService.Wiring autoServiceWiring;

	public static final String OPTION_NAME_DEFAULT_FOREGROUND_COLOR = "Object Colors.Default";
	public static final String OPTION_NAME_MODIFIED_FOREGROUND_COLOR = "Object Colors.Modifed";
	public static final String OPTION_NAME_SUBSCRIBED_FOREGROUND_COLOR = "Object Colors.Subscribed";
	public static final String OPTION_NAME_INVISIBLE_FOREGROUND_COLOR =
		"Object Colors.Invisible (when toggled on)";
	public static final String OPTION_NAME_ERROR_FOREGROUND_COLOR = "Object Colors.Errors";
	public static final String OPTION_NAME_INTRINSIC_FOREGROUND_COLOR = "Object Colors.Intrinsics";
	public static final String OPTION_NAME_TARGET_FOREGROUND_COLOR = "Object Colors.Targets";
	public static final String OPTION_NAME_ACCESSOR_FOREGROUND_COLOR = "Object Colors.Accessors";
	public static final String OPTION_NAME_LINK_FOREGROUND_COLOR = "Object Colors.Links";
	public static final String OPTION_NAME_DEFAULT_BACKGROUND_COLOR = "Object Colors.Background";

	@AutoOptionDefined( //
			name = OPTION_NAME_DEFAULT_FOREGROUND_COLOR, //
			description = "The default foreground color of items in the objects tree", //
			help = @HelpInfo(anchor = "colors") //
	)
	Color defaultForegroundColor = Color.BLACK;
	@AutoOptionDefined( //
			name = OPTION_NAME_DEFAULT_BACKGROUND_COLOR, //
			description = "The default background color of items in the objects tree", //
			help = @HelpInfo(anchor = "colors") //
	)
	Color defaultBackgroundColor = Color.WHITE;

	@AutoOptionDefined( //
			name = OPTION_NAME_INVISIBLE_FOREGROUND_COLOR, //
			description = "The foreground color for items normally not visible (toggleable)", //
			help = @HelpInfo(anchor = "colors") //
	)
	Color invisibleForegroundColor = Color.LIGHT_GRAY;
	@AutoOptionDefined( //
			name = OPTION_NAME_MODIFIED_FOREGROUND_COLOR, //
			description = "The foreground color for modified items in the objects tree", //
			help = @HelpInfo(anchor = "colors") //
	)
	Color modifiedForegroundColor = Color.RED;
	@AutoOptionDefined( //
			name = OPTION_NAME_SUBSCRIBED_FOREGROUND_COLOR, //
			description = "The foreground color for subscribed items in the objects tree", //
			help = @HelpInfo(anchor = "colors") //
	)
	Color subscribedForegroundColor = Color.BLACK;
	@AutoOptionDefined( //
			name = OPTION_NAME_ERROR_FOREGROUND_COLOR, //
			description = "The foreground color for items in error", //
			help = @HelpInfo(anchor = "colors") //
	)
	Color errorForegroundColor = Color.RED;
	@AutoOptionDefined( //
			name = OPTION_NAME_INTRINSIC_FOREGROUND_COLOR, //
			description = "The foreground color for intrinsic items in the objects tree", //
			help = @HelpInfo(anchor = "colors") //
	)
	Color intrinsicForegroundColor = Color.BLUE;
	@AutoOptionDefined( //
			name = OPTION_NAME_TARGET_FOREGROUND_COLOR, //
			description = "The foreground color for target object items in the objects tree", //
			help = @HelpInfo(anchor = "colors") //
	)
	Color targetForegroundColor = Color.MAGENTA;
	@AutoOptionDefined( //
			name = OPTION_NAME_ACCESSOR_FOREGROUND_COLOR, //
			description = "The foreground color for property accessor items in the objects tree", //
			help = @HelpInfo(anchor = "colors") //
	)
	Color accessorForegroundColor = Color.LIGHT_GRAY;
	@AutoOptionDefined( //
			name = OPTION_NAME_LINK_FOREGROUND_COLOR, //
			description = "The foreground color for links to items in the objects tree", //
			help = @HelpInfo(anchor = "colors") //
	)
	Color linkForegroundColor = Color.GREEN;

	private static final Icon ENABLED_ICON = ResourceManager.loadImage("images/enabled.png");
	private static final Icon DISABLED_ICON = ResourceManager.loadImage("images/disabled.png");

	@SuppressWarnings("unused")
	private final AutoOptions.Wiring autoOptionsWiring;

	private JPanel mainPanel;
	private ObjectPane pane;
	protected ObjectContainer root;
	private Map<String, ObjectContainer> targetMap;
	private Set<TargetObjectRef> refSet;

	public Program currentProgram; // For quick launch
	protected Map<Long, Trace> traces = new HashMap<>();
	protected Trace currentTrace;
	protected DebuggerObjectModel currentModel;
	// NB: We're getting rid of this because the ObjectsProvider is beating the trace
	//  to the punch and causing the pattern-matcher to fail
	// private TraceRecorder recorder;  
	protected Runnable repeatLastSet = () -> {
	};

	private boolean asTree = true;

	public DebuggerMethodInvocationDialog launchDialog;
	public DebuggerAttachDialog attachDialog;
	public DebuggerBreakpointDialog breakpointDialog;

	DockingAction actionLaunch;
	DockingAction actionAddBreakpoint;
	DisplayAsTreeAction displayAsTreeAction;
	DisplayAsTableAction displayAsTableAction;
	DisplayAsGraphAction displayAsGraphAction;
	DisplayAsXMLAction displayAsXMLAction;
	DisplayFilteredTreeAction displayFilteredTreeAction;
	DisplayFilteredTableAction displayFilteredTableAction;
	DisplayFilteredGraphAction displayFilteredGraphAction;
	DisplayFilteredXMLAction displayFilteredXMLAction;
	DisplayMethodsAction displayMethodsAction;
	ExportAsXMLAction exportAsXMLAction;
	ExportAsFactsAction exportAsFactsAction;
	ImportFromXMLAction importFromXMLAction;
	ImportFromFactsAction importFromFactsAction;
	OpenWinDbgTraceAction openTraceAction;

	private ToggleDockingAction actionToggleSubscribe;
	private ToggleDockingAction actionToggleAutoRecord;
	private ToggleDockingAction actionToggleHideIntrinsics;
	private ToggleDockingAction actionToggleSelectionOnly;
	private ToggleDockingAction actionToggleIgnoreState;

	@AutoConfigStateField
	private boolean autoRecord = true;
	@AutoConfigStateField
	private boolean hideIntrinsics = true;
	@AutoConfigStateField
	private boolean selectionOnly = false;
	@AutoConfigStateField
	private boolean ignoreState = false;

	public DebuggerObjectsProvider(final DebuggerObjectsPlugin plugin, DebuggerObjectModel model,
			ObjectContainer container, boolean asTree) throws Exception {
		super(plugin.getTool(), container.getPrefixedName(), plugin.getName());
		this.plugin = plugin;
		currentProgram = plugin.getActiveProgram();
		plugin.addProvider(this);
		this.currentModel = model;
		this.root = container;
		this.asTree = asTree;
		setIcon(asTree ? ObjectTree.ICON_TREE : ObjectTable.ICON_TABLE);

		targetMap = new LinkedMap<String, ObjectContainer>();
		refSet = new HashSet<TargetObjectRef>();
		getRoot().propagateProvider(this);

		this.autoServiceWiring = AutoService.wireServicesConsumed(plugin, this);
		this.autoOptionsWiring = AutoOptions.wireOptions(plugin, this);

		setHelpLocation(DebuggerResources.HELP_PROVIDER_OBJECTS);

		// Not sure any of this has any effect
		setDefaultWindowPosition(WindowPosition.STACK);
		setWindowGroup("Debugger.Core.Objects");
		setIntraGroupPosition(WindowPosition.STACK);
		setWindowMenuGroup(DebuggerPluginPackage.NAME);

		buildMainPanel();

		setVisible(true);
		createActions();

		repeatLastSet.run();
	}

	@Override
	public void addLocalAction(DockingActionIf action) {
		super.addLocalAction(action);
	}

	@Override
	public ObjectActionContext getActionContext(MouseEvent event) {
		return new ObjectActionContext(this);
	}

	public TargetObject getObjectFromContext(ActionContext context) {
		/*
		Object obj = context.getContextObject();
		ObjectContainer sel = getSelectedContainer(obj);
		if (sel == null) {
			return null;
		}
		return sel.getTargetObject();
		*/
		return pane == null ? null : pane.getSelectedObject();
	}

	public DebuggerObjectModel getModel() {
		return currentModel;
	}

	public void setModel(DebuggerObjectModel model) {
		currentModel = model;
		refresh();
	}

	@Override
	public JComponent getComponent() {
		return mainPanel;
	}

	private void buildMainPanel() throws Exception {
		mainPanel = new JPanel(new BorderLayout());
		if (asTree) {
			addTree(getRoot());
		}
		else {
			addTable(getRoot());
		}

		launchDialog = new DebuggerMethodInvocationDialog(tool, "Launch", "Launch",
			DebuggerResources.ICON_LAUNCH);
		//attachDialogOld = new DebuggerAttachDialog(this);
		attachDialog = new DebuggerAttachDialog(this);
		breakpointDialog = new DebuggerBreakpointDialog(this);
	}

	private void addToPanel(ObjectPane p) throws Exception {
		if (p == null) {
			throw new Exception("NULL PANE generated!");
		}
		pane = p;
		mainPanel.add(pane.getComponent());
	}

	JComponent getContextObject() {
		return pane == null ? null : pane.getPrincipalComponent();
	}

	@AutoOptionConsumed(name = OPTION_NAME_DEFAULT_BACKGROUND_COLOR)
	private void setDefaultBackgroundColor(Color color) {
		defaultBackgroundColor = color;
		if (pane != null) {
			pane.getComponent().repaint();
		}
	}

	@AutoOptionConsumed(name = OPTION_NAME_DEFAULT_FOREGROUND_COLOR)
	private void setDefaultForegroundColor(Color color) {
		defaultForegroundColor = color;
		if (pane != null) {
			pane.getComponent().repaint();
		}
	}

	@AutoOptionConsumed(name = OPTION_NAME_ACCESSOR_FOREGROUND_COLOR)
	private void setAccessorForegroundColor(Color color) {
		accessorForegroundColor = color;
		if (pane != null) {
			pane.getComponent().repaint();
		}
	}

	@AutoOptionConsumed(name = OPTION_NAME_ERROR_FOREGROUND_COLOR)
	private void setErrorForegroundColor(Color color) {
		errorForegroundColor = color;
		if (pane != null) {
			pane.getComponent().repaint();
		}
	}

	@AutoOptionConsumed(name = OPTION_NAME_INTRINSIC_FOREGROUND_COLOR)
	private void setIntrinsicForegroundColor(Color color) {
		intrinsicForegroundColor = color;
		if (pane != null) {
			pane.getComponent().repaint();
		}
	}

	@AutoOptionConsumed(name = OPTION_NAME_INVISIBLE_FOREGROUND_COLOR)
	private void setInvisibleForegroundColor(Color color) {
		invisibleForegroundColor = color;
		if (pane != null) {
			pane.getComponent().repaint();
		}
	}

	@AutoOptionConsumed(name = OPTION_NAME_LINK_FOREGROUND_COLOR)
	private void setLinkForegroundColor(Color color) {
		linkForegroundColor = color;
		if (pane != null) {
			pane.getComponent().repaint();
		}
	}

	@AutoOptionConsumed(name = OPTION_NAME_MODIFIED_FOREGROUND_COLOR)
	private void setModifiedForegroundColor(Color color) {
		modifiedForegroundColor = color;
		if (pane != null) {
			pane.getComponent().repaint();
		}
	}

	@AutoOptionConsumed(name = OPTION_NAME_SUBSCRIBED_FOREGROUND_COLOR)
	private void setSubscribedForegroundColor(Color color) {
		subscribedForegroundColor = color;
		if (pane != null) {
			pane.getComponent().repaint();
		}
	}

	@AutoOptionConsumed(name = OPTION_NAME_TARGET_FOREGROUND_COLOR)
	private void setTargetForegroundColor(Color color) {
		targetForegroundColor = color;
		if (pane != null) {
			pane.getComponent().repaint();
		}
	}

	public void setProgram(Program program) {
		if (program == currentProgram) {
			return;
		}
		currentProgram = program;
		plugin.setActiveProgram(currentProgram);
		contextChanged();
	}

	private boolean hasModelAndProgram() {
		return currentModel != null && currentProgram != null;
	}

	public void traceOpened(Trace trace) {
		refresh();
		repeatLastSet.run();
	}

	public void refresh() {
		if (pane != null) {
			if (currentModel != null) {
				currentModel.fetchModelRoot().thenAccept(this::refresh).exceptionally(ex -> {
					Msg.error(this, "Error refreshing model root", ex);
					return null;
				});
			}
		}
	}

	public void refresh(TargetObject targetObject) {
		if (pane != null) {
			Swing.runIfSwingOrRunLater(() -> {
				pane.setRoot(getRoot(), targetObject);
				getRoot().propagateProvider(getRoot().getProvider());
				pane.signalUpdate(getRoot());
			});
		}
	}

	public void refresh(String key) {
		if (pane != null) {
			if (key != null) {
				List<ObjectContainer> containers = new ArrayList<>();
				for (String path : targetMap.keySet()) {
					if (path.endsWith(key)) {
						ObjectContainer container = targetMap.get(path);
						containers.add(container);
					}
				}
				for (ObjectContainer container : containers) {
					pane.signalUpdate(container);
				}
			}
			else {
				pane.signalUpdate(pane.getContainer());
			}
		}
	}

	public void modelActivated(DebuggerObjectModel model) {
		//TODO: what do we want here - change of focus, selection?
		if (model != null && model.equals(currentModel)) {
			this.requestFocus();
			this.toFront();
		}
	}

	// TODO: These events aren't being called anymore
	// TraceActivatedEvents now carry complete "coordinates" (trace,thread,snap,frame,etc.)
	public void traceActivated(DebuggerCoordinates coordinates) {
		if (currentTrace == coordinates.getTrace()) {
			return;
		}
		setTrace(coordinates.getTrace(), coordinates.getThread(), true);
	}

	public void setTrace(Trace trace, TraceThread thread, boolean select) {
		TargetObject target = modelService.getTarget(trace);
		if (!refSet.contains(target)) {
			return;
		}
		repeatLastSet = () -> setTrace(trace, thread, select);
		if (trace != null) {
			//traces.put(thread.getKey(), trace);
			currentTrace = trace;
		}
		contextChanged();
		//refresh(getRoot().getName());
	}

	public void traceClosed(Trace trace) {
		if (trace == currentTrace) {
			setTrace(null, null, true);
		}
		//rootNode.tracesNode.traceClosed(trace);
	}

	public GraphDisplayBroker getGraphBroker() {
		return graphBroker;
	}

	public ConsoleService getConsoleService() {
		return consoleService;
	}

	public ObjectContainer getSelectedContainer(Object obj) {
		if (obj instanceof GTree) {
			GTree tree = (GTree) obj;
			TreePath path = tree.getSelectionPath();
			if (path != null) {
				Object last = path.getLastPathComponent();
				if (last instanceof ObjectNode) {
					return ((ObjectNode) last).getContainer();
				}
			}
			return pane.getContainer();
		}
		if (obj instanceof GhidraTable) {
			GhidraTable table = (GhidraTable) obj;
			ObjectContainer container = pane.getContainer();
			if (pane.getPrincipalComponent().equals(table)) {
				TargetObject object = pane.getSelectedObject();
				if (object instanceof DummyTargetObject) {
					return container;
				}
				ObjectContainer subContainer = container.getSubContainer(object);
				if (subContainer != null) {
					return subContainer;
				}
			}
			return container;
		}
		return null;
	}

	// TODO: right now, getSelectedObject and getSelectedContainer.getTargetObject
	//   might (?) not return the same thing.  Remedy?
	public TargetObject getSelectedObject() {
		TargetObject selectedObject = pane.getSelectedObject();
		if (selectedObject != null) {
			return selectedObject;
		}
		return null;
	}

	public void addTree(ObjectContainer container) {
		ObjectTree objTree = new ObjectTree(container);
		try {
			addToPanel(objTree);
		}
		catch (Exception e) {
			e.printStackTrace();
		}
		GTree tree = (GTree) objTree.getPrincipalComponent();
		tree.setRootVisible(true);
	}

	public void addTable(ObjectContainer container) {
		AtomicReference<ObjectContainer> update = new AtomicReference<>();
		AsyncUtils.sequence(TypeSpec.cls(ObjectContainer.class)).then(seq -> {
			container.getOffspring().handle(seq::next);
		}, update).then(seq -> {
			try {
				ObjectContainer oc = update.get();
				if (oc.hasElements()) {
					addToPanel(buildTableFromElements(oc));
				}
				else {
					addToPanel(buildTableFromAttributes(oc));
				}
				seq.exit();
			}
			catch (Exception e) {
				e.printStackTrace();
			}
		}).finish().completeExceptionally(new RuntimeException("Unable to add table"));
	}

	private ObjectTable<ObjectAttributeRow> buildTableFromAttributes(ObjectContainer container) {
		TargetObject targetObject = container.getTargetObject();
		String name = targetObject.getName();
		DefaultEnumeratedColumnTableModel<?, ObjectAttributeRow> model =
			new DefaultEnumeratedColumnTableModel<>(name, ObjectAttributeColumn.class);
		Map<String, Object> map = container.getAttributeMap();
		List<ObjectAttributeRow> list = new ArrayList<>();
		for (Object val : map.values()) {
			if (val instanceof TargetObjectRef) {
				TargetObjectRef ref = (TargetObjectRef) val;
				list.add(new ObjectAttributeRow(ref, container.getProvider()));
			}
		}
		model.addAll(list);
		return new ObjectTable<ObjectAttributeRow>(container, ObjectAttributeRow.class, model);
	}

	private ObjectTable<ObjectElementRow> buildTableFromElements(ObjectContainer container) {
		TargetObject targetObject = container.getTargetObject();
		String name = targetObject.getName();
		Map<String, TargetObjectRef> map = container.getElementMap();
		List<ObjectElementRow> list = new ArrayList<>();
		for (Object obj : map.values()) {
			if (obj instanceof TargetObjectRef) {
				TargetObjectRef ref = (TargetObjectRef) obj;
				list.add(new ObjectElementRow(ref, container.getProvider()));
			}
		}
		ObjectElementColumn[] cols = new ObjectElementColumn[1];
		cols[0] = new ObjectElementColumn("Accessor", ObjectElementRow::getValue);
		ObjectEnumeratedColumnTableModel<ObjectElementColumn, ObjectElementRow> model =
			new ObjectEnumeratedColumnTableModel<>(name, cols);
		model.addAll(list);
		ObjectTable<ObjectElementRow> table =
			new ObjectTable<ObjectElementRow>(container, ObjectElementRow.class, model);
		for (Object obj : map.values()) {
			if (obj instanceof TargetObjectRef) {
				TargetObjectRef ref = (TargetObjectRef) obj;
				AtomicReference<TargetObject> to = new AtomicReference<>();
				AtomicReference<Map<String, ?>> attrs = new AtomicReference<>();
				AsyncUtils.sequence(TypeSpec.VOID).then(seq -> {
					ref.fetch().handle(seq::next);
				}, to).then(seq -> {
					to.get().fetchAttributes(true).handle(seq::next);
				}, attrs).then(seq -> {
					table.setColumns();
				}).finish();
			}
		}
		return table;
	}

	public DebuggerObjectsPlugin getPlugin() {
		return plugin;
	}

	public void addTargetToMap(ObjectContainer container) {
		DebuggerObjectsProvider provider = container.getProvider();
		if (!this.equals(provider)) {
			Msg.error(this, "TargetMap corrupted");
		}
		TargetObject targetObject = container.getTargetObject();
		if (targetObject != null) {
			String key = targetObject.getJoinedPath(PATH_JOIN_CHAR);
			targetMap.put(key, container);
			refSet.add(targetObject);
			if (targetObject instanceof TargetInterpreter) {
				TargetInterpreter<?> interpreter = (TargetInterpreter<?>) targetObject;
				getPlugin().showConsole(interpreter);
				DebugModelConventions.findSuitable(TargetFocusScope.class, targetObject)
						.thenAccept(f -> {
							setFocus(f, targetObject);
						});
			}
		}
	}

	public void deleteFromMap(ObjectContainer container) {
		TargetObject targetObject = container.getTargetObject();
		if (targetObject != null) {
			targetMap.remove(targetObject.getJoinedPath(PATH_JOIN_CHAR));
			refSet.remove(targetObject);
		}
	}

	public ObjectContainer getContainerByPath(List<String> path) {
		String joinedPath = "";
		for (String segment : path) {
			joinedPath += segment + PATH_JOIN_CHAR;
		}
		if (joinedPath.length() > 1) {
			joinedPath = joinedPath.substring(0, joinedPath.length() - 1);
		}
		return targetMap.get(joinedPath);
	}

	static List<ObjectContainer> getContainersFromObjects(Map<String, ?> objectMap,
			TargetObject parent, boolean usingAttributes) {
		List<ObjectContainer> result = new ArrayList<ObjectContainer>();
		if (parent == null || parent instanceof DummyTargetObject) {
			return result;
		}
		synchronized (objectMap) {
			for (String key : objectMap.keySet()) {
				Object object = objectMap.get(key);
				if (object == null) {
					System.err.println("null object for " + key);
					continue;
				}
				ObjectContainer container = null;
				try {
					container = buildContainerFromObject(parent, key, object, usingAttributes);
				}
				catch (Exception e) {
					e.printStackTrace();
				}
				if (container != null) {
					result.add(container);
				}
			}
		}
		return result;

	}

	static ObjectContainer buildContainerFromObject(TargetObject parent, String key, Object val,
			boolean usingAttributes) {
		String xkey = usingAttributes ? key : "[" + key + "]";
		if (val instanceof TargetObjectRef) {
			TargetObjectRef ref = (TargetObjectRef) val;
			List<String> path = ref.getPath();
			boolean isLink = PathUtils.isLink(parent.getPath(), xkey, path);
			boolean isMethod = false;
			if (ref instanceof TargetObject) {
				TargetObject to = (TargetObject) ref;
				isMethod = to instanceof TargetMethod;
			}
			if (!(val instanceof DummyTargetObject) && !isMethod) {
				return new ObjectContainer(ref, isLink ? xkey : null);
			}
		}
		else {
			List<String> xpath = PathUtils.extend(parent.getPath(), key);
			DummyTargetObject to = new DummyTargetObject(parent, xpath, "", val, "");
			return new ObjectContainer(to, null);
		}
		return null;
	}

	@Override
	public void closeComponent() {
		TargetObject targetObject = getRoot().getTargetObject();
		if (targetObject != null) {
			targetObject.removeListener(this);
		}
		super.closeComponent();
	}

	@Override
	public void update(ObjectContainer container) {
		if (pane != null) {
			pane.signalUpdate(container);
		}
	}

	public ObjectContainer getRoot() {
		return root;
	}

	public ObjectContainer getParent(ObjectContainer container) {
		List<String> path = container.getTargetObject().getPath();
		List<String> ppath = new ArrayList<String>();
		for (String link : path) {
			ppath.add(link);
		}
		if (path.size() == 0) {
			return null;
		}
		ppath.remove(path.size() - 1);
		String joinedPath = StringUtils.join(ppath, PATH_JOIN_CHAR);
		return targetMap.get(joinedPath);
	}

	public void fireObjectUpdated(ObjectContainer object) {
		plugin.fireObjectUpdated(object);
	}

	class ObjectActionContext extends ActionContext {

		private DebuggerObjectsProvider provider;

		ObjectActionContext(DebuggerObjectsProvider provider) {
			super(provider);
			this.provider = provider;
		}

		@Override
		public Object getContextObject() {
			return provider.getContextObject();
		}

	}

	public boolean isInstance(ActionContext context, Class<? extends TargetObject> clazz) {
		TargetObject object = this.getObjectFromContext(context);
		if (object == null) {
			return false;
		}
		if (isLocalOnly()) {
			return clazz.isInstance(object);
		}
		TargetObject result = DebugModelConventions.findSuitable(clazz, object).getNow(null);
		return result != null;
	}

	public TargetObjectRef getAncestor(ActionContext context, Class<? extends TargetObject> clazz) {
		TargetObject object = this.getObjectFromContext(context);
		TargetObjectRef ref = object;
		while (ref != null) {
			if (clazz.isInstance(ref)) {
				return ref;
			}
			ref = ref.getParent();
		}
		return null;
	}

	public boolean descendsFrom(ActionContext context, Class<? extends TargetObject> clazz) {
		TargetObjectRef ref = getAncestor(context, clazz);
		return ref != null;
	}

	//@formatter:off
	private void createActions() {
		int groupTargetIndex = 0;
		
		new ActionBuilder("Refresh Node", plugin.getName())
			.keyBinding("SHIFT R")
			.toolBarGroup(DebuggerResources.GROUP_MAINTENANCE, "M" + groupTargetIndex)
			.toolBarIcon(AbstractRefreshAction.ICON)
			.helpLocation(new HelpLocation(plugin.getName(), "refresh"))
			.onAction(ctx -> performRefresh(ctx))
			.enabled(true)
			.buildAndInstallLocal(this);

		groupTargetIndex++;

		actionToggleSubscribe = new ToggleActionBuilder("Toggle Subscription", plugin.getName())
			.keyBinding("U")
			.menuPath("&Toggle subscription")
			.menuGroup(DebuggerResources.GROUP_TARGET, "M" + groupTargetIndex)
			.helpLocation(new HelpLocation(plugin.getName(), "toggle_subscription"))
			.onAction(ctx -> performToggleSubscription(ctx))
			.buildAndInstallLocal(this);
	
		groupTargetIndex++;

		actionToggleAutoRecord = new ToggleActionBuilder("&Record Automatically", plugin.getName())
			.menuPath("&Record Automatically")
			.menuGroup(DebuggerResources.GROUP_TARGET, "M" + groupTargetIndex)
			.helpLocation(new HelpLocation(plugin.getName(), "record_automatically"))
			.onAction(ctx -> performToggleAutoRecord(ctx))
			.selected(autoRecord)
			.enabled(true)
			.buildAndInstallLocal(this);
	
		groupTargetIndex++;

		actionToggleHideIntrinsics = new ToggleActionBuilder("Hide Intrinsic Atributes", plugin.getName())
			.menuPath("Maintenance","&Hide Intrinsic Attributes")
			.menuGroup(DebuggerResources.GROUP_TARGET, "M" + groupTargetIndex)
			.helpLocation(new HelpLocation(plugin.getName(), "hide_intrinsic_attributes"))
			.onAction(ctx -> performToggleHideIntrinsics(ctx))
			.selected(hideIntrinsics)
			.enabled(true)
			.buildAndInstallLocal(this);
		
		groupTargetIndex++;

		actionToggleSelectionOnly = new ToggleActionBuilder("Act on Selection Only", plugin.getName())
			.menuPath("Maintenance","Act on &Selection Only")
			.menuGroup(DebuggerResources.GROUP_TARGET, "M" + groupTargetIndex)
			.helpLocation(new HelpLocation(plugin.getName(), "act_on_selection_only"))
			.onAction(ctx -> performToggleSelectionOnly(ctx))
			.selected(selectionOnly)
			.enabled(true)
			.buildAndInstallLocal(this);
		
		groupTargetIndex++;

		actionToggleIgnoreState = new ToggleActionBuilder("Toggle ignore state on/off", plugin.getName())
			.menuPath("Maintenance","&Ignore State")
			.menuGroup(DebuggerResources.GROUP_TARGET, "M" + groupTargetIndex)
			.helpLocation(new HelpLocation(plugin.getName(), "toggle_ignore_state"))
			.onAction(ctx -> performToggleIgnoreState(ctx))
			.selected(selectionOnly)
			.enabled(true)
			.buildAndInstallLocal(this);
		
		groupTargetIndex = 0;

		new ActionBuilder("Quick Launch", plugin.getName())
			.keyBinding("Q")
			.toolBarGroup(DebuggerResources.GROUP_TARGET, "" + groupTargetIndex)
			.toolBarIcon(AbstractQuickLaunchAction.ICON)
			.helpLocation(AbstractQuickLaunchAction.help(plugin))
			.enabledWhen(ctx -> hasModelAndProgram())
			.onAction(ctx -> performQuickLaunch(ctx))
			.enabled(currentModel != null)
			.buildAndInstallLocal(this);
		
		groupTargetIndex++;

		actionLaunch = new ActionBuilder("Launch", plugin.getName())
			.keyBinding("X")
			.toolBarGroup(DebuggerResources.GROUP_TARGET, "T" + groupTargetIndex)
			.toolBarIcon(AbstractLaunchAction.ICON)
			.popupMenuPath("&Exec")
			.popupMenuGroup(DebuggerResources.GROUP_TARGET, "T" + groupTargetIndex)
			.popupMenuIcon(AbstractLaunchAction.ICON)
			.helpLocation(AbstractLaunchAction.help(plugin))
			.enabledWhen(ctx -> isInstance(ctx, TargetLauncher.tclass))
			.popupWhen(ctx -> isInstance(ctx, TargetLauncher.tclass))
			.onAction(ctx -> performLaunch(ctx))
			.enabled(false)
			.buildAndInstallLocal(this);
		
		groupTargetIndex++;

		new ActionBuilder("Attach", plugin.getName())
			.keyBinding("A")
			.toolBarGroup(DebuggerResources.GROUP_TARGET, "T" + groupTargetIndex)
			.toolBarIcon(AbstractAttachAction.ICON)
			.popupMenuPath("&Attach")
			.popupMenuGroup(DebuggerResources.GROUP_TARGET, "T" + groupTargetIndex)
			.popupMenuIcon(AbstractAttachAction.ICON)
			.helpLocation(AbstractAttachAction.help(plugin))
			.enabledWhen(ctx -> isInstance(ctx, TargetAttachable.tclass))
			.onAction(ctx -> performAttach(ctx))
			.enabled(true)
			.buildAndInstallLocal(this);
		
		groupTargetIndex++;

		new ActionBuilder("Re-attach", plugin.getName())
			.keyBinding("ALT A")
			.menuPath("&Reattach")
			.menuGroup(DebuggerResources.GROUP_TARGET, "T" + groupTargetIndex)
			.menuIcon(AbstractDetachAction.ICON)
			.helpLocation(AbstractAttachAction.help(plugin))
			.enabledWhen(ctx -> isInstance(ctx, TargetAttachable.tclass) && isStopped(ctx))
			.onAction(ctx -> performReattach(ctx))
			.enabled(true)
			.buildAndInstallLocal(this);
		
		groupTargetIndex++;

		/*
		new ActionBuilder("AttachAction", plugin.getName())
			.keyBinding("A")
			.toolBarGroup(DebuggerResources.GROUP_TARGET, "T" + groupTargetIndex)
			.toolBarIcon(AbstractAttachAction.ICON)
			.popupMenuPath("&Attach")
			.popupMenuGroup(DebuggerResources.GROUP_TARGET, "T" + groupTargetIndex)
			.popupMenuIcon(AbstractAttachAction.ICON)
			.enabledWhen(ctx -> isInstance(ctx, TargetAttachable.tclass) || isInstance(ctx, TargetAttacher.tclass))
			.popupWhen(ctx -> isInstance(ctx, TargetAttachable.tclass)  || isInstance(ctx, TargetAttacher.tclass))
			.onAction(ctx -> performAttach(ctx))
			.enabled(false)
			.buildAndInstallLocal(this);
		
		groupTargetIndex++;
		*/
		
		new ActionBuilder("Detach", plugin.getName())
			.keyBinding("D")
			.menuPath("&Detach")
			.menuGroup(DebuggerResources.GROUP_TARGET, "T" + groupTargetIndex)
			.menuIcon(AbstractDetachAction.ICON)
			.popupMenuPath("&Detach")
			.popupMenuGroup(DebuggerResources.GROUP_TARGET, "T" + groupTargetIndex)
			.popupMenuIcon(AbstractDetachAction.ICON)
			.helpLocation(AbstractDetachAction.help(plugin))
			.popupWhen(ctx -> isInstance(ctx, TargetDetachable.tclass) && isStopped(ctx))
			.enabledWhen(ctx -> isInstance(ctx, TargetDetachable.tclass) && isStopped(ctx))
			.onAction(ctx -> performDetach(ctx))
			.enabled(false)
			.buildAndInstallLocal(this);
		
		groupTargetIndex++;
		
		new ActionBuilder("Kill", plugin.getName())
			.keyBinding("K")
			.menuPath("&Kill")
			.menuGroup(DebuggerResources.GROUP_TARGET, "T" + groupTargetIndex)
			.menuIcon(AbstractKillAction.ICON)
			.popupMenuPath("&Kill")
			.popupMenuGroup(DebuggerResources.GROUP_TARGET, "T" + groupTargetIndex)
			.popupMenuIcon(AbstractKillAction.ICON)
			.helpLocation(AbstractKillAction.help(plugin))
			.enabledWhen(ctx -> isInstance(ctx, TargetKillable.tclass) && isStopped(ctx))
			.popupWhen(ctx -> isInstance(ctx, TargetKillable.tclass) && isStopped(ctx))
			.onAction(ctx -> performKill(ctx))
			.enabled(false)
			.buildAndInstallLocal(this);
		
		groupTargetIndex++;
		
		new ActionBuilder("Start Recording", plugin.getName())
			.keyBinding("R")
			.menuPath("&Record")
			.menuGroup(DebuggerResources.GROUP_TARGET, "T" + groupTargetIndex)
			.menuIcon(AbstractRecordAction.ICON)
			.popupMenuPath("&Record")
			.popupMenuGroup(DebuggerResources.GROUP_TARGET, "T" + groupTargetIndex)
			.popupMenuIcon(AbstractRecordAction.ICON)
			.helpLocation(new HelpLocation(plugin.getName(), "record"))
			.enabledWhen(ctx -> isInstance(ctx, TargetProcess.tclass))
			.popupWhen(ctx -> isInstance(ctx, TargetProcess.tclass))
			.onAction(ctx -> performStartRecording(ctx))
			.enabled(true)
			.buildAndInstallLocal(this);
		
		groupTargetIndex = 0;
	
		new ActionBuilder("Resume", plugin.getName())
			.keyBinding("F5")
			.toolBarGroup(DebuggerResources.GROUP_CONTROL, "C" + groupTargetIndex)
			.toolBarIcon(AbstractResumeAction.ICON)
			.popupMenuPath("&Resume")
			.popupMenuGroup(DebuggerResources.GROUP_CONTROL, "C" + groupTargetIndex)
			.popupMenuIcon(AbstractResumeAction.ICON)
			.helpLocation(AbstractResumeAction.help(plugin))
			.enabledWhen(ctx -> 
				isInstance(ctx, TargetResumable.tclass) && isStopped(ctx))
			.popupWhen(ctx -> 
				isInstance(ctx, TargetResumable.tclass) && isStopped(ctx))
			.onAction(ctx -> performResume(ctx))
			.enabled(false)
			.buildAndInstallLocal(this);
		
		groupTargetIndex++;

		new ActionBuilder("Interrupt", plugin.getName())
			.keyBinding("pause")
			.toolBarGroup(DebuggerResources.GROUP_CONTROL, "C" + groupTargetIndex)
			.toolBarIcon(AbstractInterruptAction.ICON)
			.popupMenuPath("&Interrupt")
			.popupMenuGroup(DebuggerResources.GROUP_CONTROL, "C" + groupTargetIndex)
			.popupMenuIcon(AbstractInterruptAction.ICON)
			.helpLocation(AbstractInterruptAction.help(plugin))
			.enabledWhen(ctx -> 
				isInstance(ctx, TargetInterruptible.tclass) && (!isStopped(ctx) || ignoreState))
			.popupWhen(ctx -> 
				isInstance(ctx, TargetInterruptible.tclass) && (!isStopped(ctx) || ignoreState))
			.onAction(ctx -> performInterrupt(ctx))
			.enabled(false)
			.buildAndInstallLocal(this);
		
		groupTargetIndex++;

		new ActionBuilder("Step Into", plugin.getName())
			.keyBinding("F8")
			.toolBarGroup(DebuggerResources.GROUP_CONTROL, "C" + groupTargetIndex)
			.toolBarIcon(AbstractStepIntoAction.ICON)
			.popupMenuPath("&Step Into")
			.popupMenuGroup(DebuggerResources.GROUP_CONTROL, "C" + groupTargetIndex)
			.popupMenuIcon(AbstractStepIntoAction.ICON)
			.helpLocation(AbstractStepIntoAction.help(plugin))
			.enabledWhen(ctx -> 
				isInstance(ctx, TargetSteppable.tclass) && isStopped(ctx))
			.popupWhen(ctx -> 
				isInstance(ctx, TargetSteppable.tclass) && isStopped(ctx))
			.onAction(ctx -> performStepInto(ctx))
			.enabled(false)
			.buildAndInstallLocal(this);
		
		groupTargetIndex++;
	
		new ActionBuilder("Step Over", plugin.getName())
			.keyBinding("F10")
			.toolBarGroup(DebuggerResources.GROUP_CONTROL, "C" + groupTargetIndex)
			.toolBarIcon(AbstractStepOverAction.ICON)
			.popupMenuPath("&Step Over")
			.popupMenuGroup(DebuggerResources.GROUP_CONTROL, "C" + groupTargetIndex)
			.popupMenuIcon(AbstractStepOverAction.ICON)
			.helpLocation(AbstractStepOverAction.help(plugin))
			//.withContext(ObjectActionContext.class)
			.enabledWhen(ctx -> 
				isInstance(ctx, TargetSteppable.tclass) && isStopped(ctx))
			.popupWhen(ctx -> 
				isInstance(ctx, TargetSteppable.tclass) && isStopped(ctx))
			.onAction(ctx -> performStepOver(ctx))
			.enabled(false)
			.buildAndInstallLocal(this);
		
		groupTargetIndex++;

		new ActionBuilder("Step Finish", plugin.getName())
			.keyBinding("F12")
			.toolBarGroup(DebuggerResources.GROUP_CONTROL, "C" + groupTargetIndex)
			.toolBarIcon(AbstractStepFinishAction.ICON)
			.popupMenuPath("&Step Finish")
			.popupMenuGroup(DebuggerResources.GROUP_CONTROL, "C" + groupTargetIndex)
			.popupMenuIcon(AbstractStepFinishAction.ICON)
			.helpLocation(AbstractStepFinishAction.help(plugin))
			//.withContext(ObjectActionContext.class)
			.enabledWhen(ctx -> 
				isInstance(ctx, TargetSteppable.tclass) && isStopped(ctx))
			.popupWhen(ctx -> 
				isInstance(ctx, TargetSteppable.tclass) && isStopped(ctx))
			.onAction(ctx -> performStepFinish(ctx))
			.enabled(false)
			.buildAndInstallLocal(this);
		
		groupTargetIndex++;
		
		actionAddBreakpoint = new ActionBuilder("Add Breakpoint", plugin.getName())
			.keyBinding("F3")
			.toolBarGroup(DebuggerResources.GROUP_CONTROL, "C" + groupTargetIndex)
			.toolBarIcon(AbstractSetBreakpointAction.ICON)
			.popupMenuPath("&AddBreakpoint")
			.popupMenuGroup(DebuggerResources.GROUP_CONTROL, "C" + groupTargetIndex)
			.popupMenuIcon(AbstractSetBreakpointAction.ICON)
			.helpLocation(AbstractSetBreakpointAction.help(plugin))
			//.withContext(ObjectActionContext.class)
			.enabledWhen(ctx -> 
				isInstance(ctx, TargetBreakpointContainer.tclass) && isStopped(ctx))
			.popupWhen(ctx -> 
				isInstance(ctx, TargetBreakpointContainer.tclass) && isStopped(ctx))
			.onAction(ctx -> performSetBreakpoint(ctx))
			.enabled(false) 
			.buildAndInstallLocal(this); 
		
		groupTargetIndex = 0;
	
		new ActionBuilder("Show Console", plugin.getName())
			//.keyBinding("pause")
			.toolBarGroup(DebuggerResources.GROUP_CONNECTION, "X" + groupTargetIndex)
			.toolBarIcon(AbstractConsoleAction.ICON)
			.popupMenuPath("&Show Console")
			.popupMenuGroup(DebuggerResources.GROUP_CONNECTION, "X" + groupTargetIndex)
			.popupMenuIcon(AbstractConsoleAction.ICON)
			.helpLocation(AbstractConsoleAction.help(plugin))
			//.withContext(ObjectActionContext.class)
			.enabledWhen(ctx -> isInstance(ctx, TargetInterpreter.tclass))
			.popupWhen(ctx -> isInstance(ctx, TargetInterpreter.tclass))
			.onAction(ctx -> initiateConsole(ctx))
			.enabled(false)
			.buildAndInstallLocal(this);
		
		groupTargetIndex++;
	
		displayAsTreeAction = new DisplayAsTreeAction(tool, plugin.getName(), this);
		displayAsTableAction = new DisplayAsTableAction(tool, plugin.getName(), this);
		displayAsGraphAction = new DisplayAsGraphAction(tool, plugin.getName(), this);
		displayAsXMLAction = new DisplayAsXMLAction(tool, plugin.getName(), this);

		displayFilteredTreeAction =
			new DisplayFilteredTreeAction(tool, plugin.getName(), this);
		displayFilteredTableAction =
			new DisplayFilteredTableAction(tool, plugin.getName(), this);
		displayFilteredGraphAction =
			new DisplayFilteredGraphAction(tool, plugin.getName(), this);
		displayFilteredXMLAction =
				new DisplayFilteredXMLAction(tool, plugin.getName(), this);

		displayMethodsAction = new DisplayMethodsAction(tool, plugin.getName(), this);

		exportAsXMLAction = new ExportAsXMLAction(tool, plugin.getName(), this);
		exportAsFactsAction = new ExportAsFactsAction(tool, plugin.getName(), this);
		importFromXMLAction = new ImportFromXMLAction(tool, plugin.getName(), this);
		importFromFactsAction = new ImportFromFactsAction(tool, plugin.getName(), this);
		openTraceAction = new OpenWinDbgTraceAction(tool, plugin.getName(), this);
	}

	//@formatter:on

	public void performRefresh(ActionContext context) {
		TargetObject current = getObjectFromContext(context);
		if (current != null) {
			refresh(current.getName());
		}
		else {
			refresh();
		}
	}

	public void performToggleAutoupdate(ActionContext context) {
		TargetObject object = getObjectFromContext(context);
		/*
		if (object instanceof DefaultTargetObject) {
			Map<String, ?> attributes = object.listAttributes();
			Boolean autoupdate = (Boolean) attributes.get(AUTOUPDATE_ATTRIBUTE_NAME);
			if (autoupdate == null) {
				autoupdate = false;
			}
			@SuppressWarnings("unchecked")
			DefaultTargetObject<TargetObject, TargetObject> defobj =
				(DefaultTargetObject<TargetObject, TargetObject>) object;
			defobj.changeAttributes(List.of(), Map.of(//
				AUTOUPDATE_ATTRIBUTE_NAME, !autoupdate), //
				"Refreshed");
		}
		*/
	}

	public void performToggleSubscription(ActionContext context) {
		Object contextObject = context.getContextObject();
		ObjectContainer container = getSelectedContainer(contextObject);
		if (container.isSubscribed()) {
			container.unsubscribe();
		}
		else {
			container.subscribe();
		}
	}

	public void performToggleAutoRecord(ActionContext context) {
		autoRecord = actionToggleAutoRecord.isSelected();
	}

	public void performToggleHideIntrinsics(ActionContext context) {
		hideIntrinsics = actionToggleHideIntrinsics.isSelected();
		refresh("");
	}

	public void performToggleSelectionOnly(ActionContext context) {
		selectionOnly = actionToggleSelectionOnly.isSelected();
		refresh("");
	}

	public void performToggleIgnoreState(ActionContext context) {
		ignoreState = actionToggleIgnoreState.isSelected();
		refresh("");
	}

	public void performQuickLaunch(ActionContext context) {
		if (currentProgram == null) {
			return;
		}
		TargetObject obj = getObjectFromContext(context);
		if (obj == null) {
			obj = root.getTargetObject();
		}
		// TODO: A generic or pluggable way of deriving the launch arguments 
		CompletableFuture<? extends TargetLauncher<?>> fl =
			DebugModelConventions.findSuitable(TargetLauncher.tclass, obj);
		fl.thenCompose(launcher -> {
			return launcher.launch(Map.of(TargetCmdLineLauncher.CMDLINE_ARGS_NAME,
				currentProgram.getExecutablePath()));
		}).exceptionally(e -> {
			Msg.showError(this, getComponent(), "Could not launch", e);
			return null;
		});
	}

	public void performLaunch(ActionContext context) {
		TargetObject obj = getObjectFromContext(context);
		if (obj == null) {
			obj = root.getTargetObject();
		}
		CompletableFuture<? extends TargetLauncher<?>> fl =
			DebugModelConventions.findSuitable(TargetLauncher.tclass, obj);
		fl.thenCompose(launcher -> {
			if (currentProgram != null) {
				// TODO: A generic or pluggable way of deriving the default arguments
				String path = currentProgram.getExecutablePath();
				String cmdlineArgs = launchDialog.getMemorizedArgument(
					TargetCmdLineLauncher.CMDLINE_ARGS_NAME, String.class);
				if (path != null && cmdlineArgs != null) {
					if (!cmdlineArgs.startsWith(path)) {
						launchDialog.setMemorizedArgument(TargetCmdLineLauncher.CMDLINE_ARGS_NAME,
							String.class, path);
					}
				}
			}
			Map<String, ?> args = launchDialog.promptArguments(launcher.getParameters());
			if (args == null) {
				return AsyncUtils.NIL;
			}
			return launcher.launch(args);
		}).exceptionally(ex -> {
			Msg.showError(this, null, "Launch", "Problem during launch", ex);
			return null;
		});
	}

	public void performAttach(ActionContext context) {
		TargetObject obj = getObjectFromContext(context);
		AtomicReference<TargetAttacher<?>> attacher = new AtomicReference<>();
		AsyncUtils.sequence(TypeSpec.VOID).then(seq -> {
			DebugModelConventions.findSuitable(TargetAttacher.class, obj).handle(seq::next);
		}, attacher).then(seq -> {
			TargetAttacher<?> a = attacher.get();
			attachDialog.setAttacher(a);
			if (obj instanceof TargetAttachable) {
				TargetAttachable<?> attachable = (TargetAttachable<?>) obj;
				long pid = attachDialog.getPid(attachable);
				a.attach(pid);
			}
			else {
				attachDialog.fetchAndDisplayAttachable();
				tool.showDialog(attachDialog);
			}
		}).finish();
	}

	public void performReattach(ActionContext context) {
		TargetObject obj = getObjectFromContext(context);
		if (!(obj instanceof TargetAttachable<?>)) {
			return;
		}
		AtomicReference<TargetObject> parent = new AtomicReference<>();
		AsyncUtils.sequence(TypeSpec.VOID).then(seq -> {
			DebugModelConventions.findSuitable(TargetAttacher.class, obj).handle(seq::next);
		}, parent).then(seq -> {
			TargetAttacher<?> attacher = parent.get().as(TargetAttacher.tclass);
			attacher.attach((TargetAttachable<?>) obj).handle(seq::nextIgnore);
		}).finish();
	}

	public CompletableFuture<Void> startRecording(TargetProcess<?> targetObject, boolean prompt) {
		CompletableFuture<TraceRecorder> future;
		if (prompt) {
			future = modelService.recordTargetPromptOffers(targetObject);
		}
		else {
			future = modelService.recordTargetBestOffer(targetObject);
		}
		return future.thenAccept(rec -> {
			if (rec == null) {
				return; // Cancelled
			}
			//this.recorder = rec;
			Trace trace = rec.getTrace();
			traceManager.openTrace(trace);
			traceManager.activateTrace(trace);
		});
	}

	public void addListener(TargetObject targetObject) {
		/*
		if (recorder != null) {
			recorder.getListenerForRecord().addListener(targetObject);
		}
		*/
	}

	public void stopRecording(TargetObject targetObject) {
		// TODO: Do `this.recorder = ...` on every object selection change?
		TraceRecorder rec = modelService.getRecorderForSuccessor(targetObject);
		if (rec != null) {
			rec.stopRecording();
		}
	}

	public void performDetach(ActionContext context) {
		TargetObject obj = getObjectFromContext(context);
		if (!isLocalOnly()) {
			DebugModelConventions.findSuitable(TargetDetachable.class, obj)
					.thenAccept(detachable -> {
						detachable.detach();
					})
					.exceptionally(DebuggerResources.showError(getComponent(), "Couldn't detach"));
		}
		else {
			TargetDetachable<?> detachable = (TargetDetachable<?>) obj;
			detachable.detach();
		}
	}

	public void performKill(ActionContext context) {
		TargetObject obj = getObjectFromContext(context);
		if (!isLocalOnly()) {
			DebugModelConventions.findSuitable(TargetKillable.class, obj).thenAccept(killable -> {
				killable.kill();
			}).exceptionally(DebuggerResources.showError(getComponent(), "Couldn't kill"));
		}
		else {
			TargetKillable<?> killable = (TargetKillable<?>) obj;
			killable.kill();
		}
	}

	public void performStartRecording(ActionContext context) {
		TargetObject obj = getObjectFromContext(context);
		if (!isLocalOnly()) {
			DebugModelConventions.findSuitable(TargetProcess.class, obj).thenAccept(process -> {
				TargetProcess<?> valid = DebugModelConventions.liveProcessOrNull(process);
				if (valid != null) {
					startRecording(valid, true).exceptionally(ex -> {
						Msg.showError(this, null, "Record",
							"Could not record and/or open target: " + valid, ex);
						return null;
					});
				}
			}).exceptionally(DebuggerResources.showError(getComponent(), "Couldn't record"));
		}
		else {
			TargetProcess<?> valid = DebugModelConventions.liveProcessOrNull(obj);
			if (valid != null) {
				startRecording(valid, true).exceptionally(ex -> {
					Msg.showError(this, null, "Record",
						"Could not record and/or open target: " + valid, ex);
					return null;
				});
			}
		}
	}

	public void performResume(ActionContext context) {
		TargetObject obj = getObjectFromContext(context);
		if (!isLocalOnly()) {
			DebugModelConventions.findSuitable(TargetResumable.class, obj).thenAccept(resumable -> {
				resumable.resume();
			}).exceptionally(DebuggerResources.showError(getComponent(), "Couldn't resume"));
		}
		else {
			TargetResumable<?> resumable = (TargetResumable<?>) obj;
			resumable.resume();
		}
	}

	public void performInterrupt(ActionContext context) {
		TargetObject obj = getObjectFromContext(context);
		if (!isLocalOnly()) {
			DebugModelConventions.findSuitable(TargetInterruptible.class, obj)
					.thenAccept(interruptible -> {
						interruptible.interrupt();
					})
					.exceptionally(
						DebuggerResources.showError(getComponent(), "Couldn't interrupt"));
		}
		else {
			TargetInterruptible<?> interruptible = (TargetInterruptible<?>) obj;
			interruptible.interrupt();
		}
	}

	public void performStepInto(ActionContext context) {
		TargetObject obj = getObjectFromContext(context);
		if (!isLocalOnly()) {
			DebugModelConventions.findSuitable(TargetSteppable.class, obj).thenAccept(steppable -> {
				steppable.step();
			}).exceptionally(DebuggerResources.showError(getComponent(), "Couldn't step"));
		}
		else {
			TargetSteppable<?> steppable = (TargetSteppable<?>) obj;
			steppable.step();
		}
	}

	public void performStepOver(ActionContext context) {
		TargetObject obj = getObjectFromContext(context);
		if (!isLocalOnly()) {
			DebugModelConventions.findSuitable(TargetSteppable.class, obj).thenAccept(steppable -> {
				steppable.step(TargetStepKind.OVER);
			}).exceptionally(DebuggerResources.showError(getComponent(), "Couldn't step"));
		}
		else {
			TargetSteppable<?> steppable = (TargetSteppable<?>) obj;
			steppable.step(TargetStepKind.OVER);
		}
	}

	public void performStepFinish(ActionContext context) {
		TargetObject obj = getObjectFromContext(context);
		if (!isLocalOnly()) {
			DebugModelConventions.findSuitable(TargetSteppable.class, obj).thenAccept(steppable -> {
				steppable.step(TargetStepKind.FINISH);
			}).exceptionally(DebuggerResources.showError(getComponent(), "Couldn't step"));
		}
		else {
			TargetSteppable<?> steppable = (TargetSteppable<?>) obj;
			steppable.step(TargetStepKind.FINISH);
		}
	}

	public void performSetBreakpoint(ActionContext context) {
		TargetObject obj = getObjectFromContext(context);
		if (!isLocalOnly()) {
			DebugModelConventions.findSuitable(TargetBreakpointContainer.class, obj)
					.thenAccept(suitable -> {
						breakpointDialog.setContainer(suitable);
						tool.showDialog(breakpointDialog);
					})
					.exceptionally(
						DebuggerResources.showError(getComponent(), "Couldn't set breakpoint"));
		}
		else {
			TargetBreakpointContainer<?> container = (TargetBreakpointContainer<?>) obj;
			breakpointDialog.setContainer(container);
			tool.showDialog(breakpointDialog);
		}
	}

	public void initiateConsole(ActionContext context) {
		TargetObject obj = getObjectFromContext(context);
		if (!isLocalOnly()) {
			DebugModelConventions.findSuitable(TargetInterpreter.class, obj)
					.thenAccept(interpreter -> {
						getPlugin().showConsole(interpreter);
					})
					.exceptionally(
						DebuggerResources.showError(getComponent(), "Couldn't launch interpreter"));
		}
		else {
			TargetInterpreter<?> interpreter = (TargetInterpreter<?>) obj;
			getPlugin().showConsole(interpreter);
		}
	}

	public boolean isStopped(ActionContext context) {
		TargetObject object = this.getObjectFromContext(context);
		if (object == null) {
			return false;
		}
		if (ignoreState) {
			return true;
		}
		if (isLocalOnly()) {
			if (object instanceof TargetExecutionStateful<?>) {
				TargetExecutionStateful<?> stateful = (TargetExecutionStateful<?>) object;
				TargetExecutionState executionState = stateful.getExecutionState();
				//System.err.println(stateful + ":" + executionState);
				return !executionState.equals(TargetExecutionState.RUNNING);
			}
			return false;
		}
		TargetObject result =
			DebugModelConventions.findSuitable(TargetExecutionStateful.class, object).getNow(null);
		if (result != null) {
			TargetExecutionStateful<?> stateful = (TargetExecutionStateful<?>) result;
			TargetExecutionState executionState = stateful.getExecutionState();
			return !executionState.equals(TargetExecutionState.RUNNING);
		}
		return false;
	}

	@Override
	public void accessibilityChanged(TargetAccessConditioned<?> object,
			TargetAccessibility accessibility) {
		//this.access = accessibility.equals(TargetAccessibility.ACCESSIBLE);
		plugin.getTool().contextChanged(this);
	}

	@Override
	public void consoleOutput(TargetObject console, Channel channel, String out) {
		//getPlugin().showConsole((TargetInterpreter<?>) console);
		System.err.println("consoleOutput: " + out);
	}

	@Override
	public void displayChanged(TargetObject object, String display) {
		//System.err.println("displayChanged: " + display);
		if (ObjectContainer.visibleByDefault(object.getName())) {
			pane.signalDataChange(getContainerByPath(object.getPath()));
		}
	}

	@Override
	public void executionStateChanged(TargetExecutionStateful<?> object,
			TargetExecutionState state) {
		//this.state = state;
		plugin.getTool().contextChanged(this);
	}

	@Override
	public void focusChanged(TargetFocusScope<?> object, TargetObjectRef focused) {
		plugin.setFocus(object, focused);
		plugin.getTool().contextChanged(this);
	}

	public void setFocus(TargetFocusScope<?> object, TargetObjectRef focused) {
		if (focused.getModel() != currentModel) {
			return;
		}
		pane.setFocus(object, focused);
	}

	@Override
	public void memoryUpdated(TargetMemory<?> memory, Address address, byte[] data) {
		System.err.println("memoryUpdated");
	}

	@Override
	public void memoryReadError(TargetMemory<?> memory, AddressRange range,
			DebuggerMemoryAccessException e) {
		System.err.println("memoryReadError");
	}

	@Override
	public void promptChanged(TargetInterpreter<?> interpreter, String prompt) {
		System.err.println("promptChanged: " + prompt);
	}

	@Override
	public void registersUpdated(TargetRegisterBank<?> bank, Map<String, byte[]> updates) {
		Map<String, ? extends TargetObjectRef> cachedElements = bank.getCachedElements();
		for (String key : cachedElements.keySet()) {
			TargetObjectRef ref = cachedElements.get(key);
			if (ref instanceof TargetObject) {
				displayChanged((TargetObject) ref, "registersUpdated");
			}
		}
	}

	@Override
	public void elementsChangedObjects(TargetObject parent, Collection<String> removed,
			Map<String, ? extends TargetObject> added) {
		//System.err.println("local EC: " + parent);
		ObjectContainer container = getContainerByPath(parent.getPath());
		if (container != null) {
			container.augmentElements(removed, added);
			boolean visibleChange = false;
			for (String key : removed) {
				visibleChange |= ObjectContainer.visibleByDefault(key);
			}
			for (String key : added.keySet()) {
				visibleChange |= ObjectContainer.visibleByDefault(key);
			}
			if (visibleChange) {
				container.propagateProvider(this);
				update(container);
			}
		}
	}

	@Override
	public void attributesChangedObjects(TargetObject parent, Collection<String> removed,
			Map<String, ?> added) {
		//System.err.println("local AC: " + parent + ":" + removed + ":" + added);
		ObjectContainer container = getContainerByPath(parent.getPath());
		if (container != null) {
			container.augmentAttributes(removed, added);
			boolean visibleChange = false;
			for (String key : removed) {
				visibleChange |= ObjectContainer.visibleByDefault(key);
			}
			for (String key : added.keySet()) {
				visibleChange |= ObjectContainer.visibleByDefault(key);
			}
			if (visibleChange) {
				container.propagateProvider(this);
				update(container);
			}
		}
	}

	public DebuggerTraceManagerService getTraceManager() {
		return traceManager;
	}

	public boolean isHideIntrinsics() {
		return hideIntrinsics;
	}

	public void setHideIntrinsics(boolean hideIntrinsics) {
		this.hideIntrinsics = hideIntrinsics;
	}

	public boolean isLocalOnly() {
		return selectionOnly;
	}

	public void setLocalOnly(boolean localOnly) {
		this.selectionOnly = localOnly;
	}

	public Color getColor(String name) {
		switch (name) {
			case OPTION_NAME_ACCESSOR_FOREGROUND_COLOR:
				return accessorForegroundColor;
			case OPTION_NAME_DEFAULT_BACKGROUND_COLOR:
				return defaultBackgroundColor;
			case OPTION_NAME_DEFAULT_FOREGROUND_COLOR:
				return defaultForegroundColor;
			case OPTION_NAME_ERROR_FOREGROUND_COLOR:
				return errorForegroundColor;
			case OPTION_NAME_INTRINSIC_FOREGROUND_COLOR:
				return intrinsicForegroundColor;
			case OPTION_NAME_INVISIBLE_FOREGROUND_COLOR:
				return invisibleForegroundColor;
			case OPTION_NAME_MODIFIED_FOREGROUND_COLOR:
				return modifiedForegroundColor;
			case OPTION_NAME_SUBSCRIBED_FOREGROUND_COLOR:
				return subscribedForegroundColor;
			case OPTION_NAME_LINK_FOREGROUND_COLOR:
				return linkForegroundColor;
			case OPTION_NAME_TARGET_FOREGROUND_COLOR:
				return targetForegroundColor;
			default:
				return Color.BLACK;
		}
	}

	public boolean isAutorecord() {
		return autoRecord;
	}

	public void setAutorecord(boolean autorecord) {
		this.autoRecord = autorecord;
	}

	public void updateActions(ObjectContainer providerContainer) {
		TargetObject obj = getSelectedObject();
		if (obj != null) {
			actionToggleSubscribe.setEnabled(true);
			actionToggleSubscribe.setSelected(providerContainer.isSubscribed());
			MenuData menuData = actionToggleSubscribe.getMenuBarData();
			if (menuData != null) {
				menuData.setMenuPath(new String[] { "Subscribe to '" + obj.getDisplay() + "'" });
			}
		}
		else {
			actionToggleSubscribe.setEnabled(false);
			actionToggleSubscribe.setSelected(false);
			MenuData menuData = actionToggleSubscribe.getMenuBarData();
			if (menuData != null) {
				menuData.setMenuPath(new String[] { "Subscribe" });
			}
		}
	}

	public void writeConfigState(SaveState saveState) {
		CONFIG_STATE_HANDLER.writeConfigState(this, saveState);
		launchDialog.writeConfigState(saveState);
	}

	public void readConfigState(SaveState saveState) {
		CONFIG_STATE_HANDLER.readConfigState(this, saveState);

		actionToggleAutoRecord.setSelected(autoRecord);
		actionToggleHideIntrinsics.setSelected(hideIntrinsics);
		actionToggleSelectionOnly.setSelected(selectionOnly);

		launchDialog.readConfigState(saveState);
	}

	@Override
	public void componentActivated() {
		if (currentTrace != null && !this.isActive()) {
			traceManager.activateTrace(currentTrace);
		}
	}

	public DebuggerModelService getModelService() {
		return modelService;
	}

	public DebuggerListingService getListingService() {
		return listingService;
	}

}
