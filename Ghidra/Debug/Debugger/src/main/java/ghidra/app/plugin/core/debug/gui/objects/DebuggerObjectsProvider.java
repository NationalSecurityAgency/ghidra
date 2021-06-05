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
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;

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
import ghidra.dbg.*;
import ghidra.dbg.error.DebuggerMemoryAccessException;
import ghidra.dbg.target.*;
import ghidra.dbg.target.TargetConsole.Channel;
import ghidra.dbg.target.TargetExecutionStateful.TargetExecutionState;
import ghidra.dbg.target.TargetLauncher.TargetCmdLineLauncher;
import ghidra.dbg.target.TargetSteppable.TargetStepKind;
import ghidra.dbg.util.DebuggerCallbackReorderer;
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
import ghidra.util.datastruct.PrivatelyQueuedListener;
import ghidra.util.table.GhidraTable;
import resources.ResourceManager;

public class DebuggerObjectsProvider extends ComponentProviderAdapter
		implements ObjectContainerListener {

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
	public static final String OPTION_NAME_INVALIDATED_FOREGROUND_COLOR =
		"Object Colors.Invalidated";
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
		name = OPTION_NAME_INVALIDATED_FOREGROUND_COLOR, //
		description = "The foreground color for items no longer valid", //
		help = @HelpInfo(anchor = "colors") //
	)
	Color invalidatedForegroundColor = Color.LIGHT_GRAY;
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
	Color linkForegroundColor = Color.GREEN.darker();

	@AutoOptionDefined( //
		name = "Default Extended Step", //
		description = "The default string for the extended step command" //
	//help = @HelpInfo(anchor = "colors") //
	)
	String extendedStep = "";

	private static final Icon ENABLED_ICON = ResourceManager.loadImage("images/enabled.png");
	private static final Icon DISABLED_ICON = ResourceManager.loadImage("images/disabled.png");

	@SuppressWarnings("unused")
	private final AutoOptions.Wiring autoOptionsWiring;

	private JPanel mainPanel;
	private ObjectPane pane;
	protected ObjectContainer root;
	private Map<String, ObjectContainer> targetMap;
	private Set<TargetObject> refSet;

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
	private MyObjectListener listener = new MyObjectListener();

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

	private ToggleDockingAction actionToggleBase;
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

	Set<TargetConfigurable> configurables = new HashSet<>();

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
		refSet = new HashSet<>();
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
		currentModel.addModelListener(getListener(), true);
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

	@AutoOptionConsumed(name = OPTION_NAME_INVALIDATED_FOREGROUND_COLOR)
	private void setInvalidatedForegroundColor(Color color) {
		invalidatedForegroundColor = color;
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
		//refresh();
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
						synchronized (targetMap) {
							ObjectContainer container = targetMap.get(path);
							containers.add(container);
						}
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
			this.requestFocus(); // COMPONENT
			this.toFront();
			setSubTitle(currentModel.getBrief());
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
			if (val instanceof TargetObject) {
				TargetObject ref = (TargetObject) val;
				list.add(new ObjectAttributeRow(ref, container.getProvider()));
			}
		}
		model.addAll(list);
		return new ObjectTable<ObjectAttributeRow>(container, ObjectAttributeRow.class, model);
	}

	private ObjectTable<ObjectElementRow> buildTableFromElements(ObjectContainer container) {
		TargetObject targetObject = container.getTargetObject();
		String name = targetObject.getName();
		Map<String, TargetObject> map = container.getElementMap();
		List<ObjectElementRow> list = new ArrayList<>();
		for (Object obj : map.values()) {
			if (obj instanceof TargetObject) {
				TargetObject ref = (TargetObject) obj;
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
			if (obj instanceof TargetObject) {
				TargetObject ref = (TargetObject) obj;
				ref.fetchAttributes(true).thenAccept(attrs -> {
					table.setColumns();
					// TODO: What with attrs?
				}).exceptionally(ex -> {
					Msg.error(this, "Failed to fetch attributes", ex);
					return null;
				});
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
		if (targetObject != null && !container.isLink()) {
			String key = targetObject.getJoinedPath(PATH_JOIN_CHAR);
			container.subscribe();
			synchronized (targetMap) {
				targetMap.put(key, container);
				refSet.add(targetObject);
			}
			if (targetObject instanceof TargetInterpreter) {
				TargetInterpreter interpreter = (TargetInterpreter) targetObject;
				getPlugin().showConsole(interpreter);
				DebugModelConventions.findSuitable(TargetFocusScope.class, targetObject)
						.thenAccept(f -> {
							setFocus(f, targetObject);
						});
			}
			if (targetObject instanceof TargetConfigurable) {
				configurables.add((TargetConfigurable) targetObject);
			}
		}
	}

	public void deleteFromMap(ObjectContainer container) {
		TargetObject targetObject = container.getTargetObject();
		if (targetObject != null) {
			synchronized (targetMap) {
				targetMap.remove(targetObject.getJoinedPath(PATH_JOIN_CHAR));
				refSet.remove(targetObject);
				if (targetObject instanceof TargetConfigurable) {
					configurables.remove(targetObject);
				}
			}
		}
	}

	public ObjectContainer getContainerByPath(List<String> path) {
		return targetMap.get(PathUtils.toString(path));
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
		if (val instanceof TargetObject) {
			TargetObject to = (TargetObject) val;
			List<String> path = to.getPath();
			boolean isLink = PathUtils.isLink(parent.getPath(), xkey, path);
			boolean isMethod = false;
			isMethod = to instanceof TargetMethod;
			if (!(val instanceof DummyTargetObject) && !isMethod) {
				return new ObjectContainer(to, isLink ? xkey : null);
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
			targetObject.removeListener(getListener());
		}
		super.closeComponent();
	}

	public void signalDataChanged(ObjectContainer container) {
		if (pane != null) {
			pane.signalDataChanged(container);
		}
	}

	public void signalContentsChanged(ObjectContainer container) {
		if (pane != null) {
			pane.signalContentsChanged(container);
		}
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
		TargetObject result = null;
		try {
			result =
				DebugModelConventions.findSuitable(clazz, object).get(100, TimeUnit.MILLISECONDS);
		}
		catch (Exception e) {
			// IGNORE
		}
		return result != null;
	}

	public TargetObject getAncestor(ActionContext context, Class<? extends TargetObject> clazz) {
		TargetObject object = this.getObjectFromContext(context);
		TargetObject ref = object;
		while (ref != null) {
			if (clazz.isInstance(ref)) {
				return ref;
			}
			ref = ref.getParent();
		}
		return null;
	}

	public boolean descendsFrom(ActionContext context, Class<? extends TargetObject> clazz) {
		TargetObject ref = getAncestor(context, clazz);
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

		actionToggleBase = new ToggleActionBuilder("Toggle Base", plugin.getName())
			.keyBinding("B")
			.menuPath("&Toggle base")
			.menuGroup(DebuggerResources.GROUP_TARGET, "M" + groupTargetIndex)
			.helpLocation(new HelpLocation(plugin.getName(), "toggle_base"))
			.onAction(ctx -> performToggleBase(ctx))
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

		actionToggleSelectionOnly = new ToggleActionBuilder("Enable By Selection Only", plugin.getName())
			.menuPath("Maintenance","Enable By &Selection Only")
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
			.enabledWhen(ctx -> isInstance(ctx, TargetLauncher.class))
			.popupWhen(ctx -> isInstance(ctx, TargetLauncher.class))
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
			.enabledWhen(ctx -> isInstance(ctx, TargetAttachable.class))
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
			.enabledWhen(ctx -> isInstance(ctx, TargetAttachable.class) && isStopped(ctx))
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
			.enabledWhen(ctx -> isInstance(ctx, TargetAttachable.class) || isInstance(ctx, TargetAttacher.class))
			.popupWhen(ctx -> isInstance(ctx, TargetAttachable.class)  || isInstance(ctx, TargetAttacher.class))
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
			.popupWhen(ctx -> isInstance(ctx, TargetDetachable.class) && isStopped(ctx))
			.enabledWhen(ctx -> isInstance(ctx, TargetDetachable.class) && isStopped(ctx))
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
			.enabledWhen(ctx -> isInstance(ctx, TargetKillable.class) && isStopped(ctx))
			.popupWhen(ctx -> isInstance(ctx, TargetKillable.class) && isStopped(ctx))
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
			.enabledWhen(ctx -> isInstance(ctx, TargetProcess.class))
			.popupWhen(ctx -> isInstance(ctx, TargetProcess.class))
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
				isInstance(ctx, TargetResumable.class) && isStopped(ctx))
			.popupWhen(ctx -> 
				isInstance(ctx, TargetResumable.class) && isStopped(ctx))
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
				isInstance(ctx, TargetInterruptible.class) && (!isStopped(ctx) || ignoreState))
			.popupWhen(ctx -> 
				isInstance(ctx, TargetInterruptible.class) && (!isStopped(ctx) || ignoreState))
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
				isInstance(ctx, TargetSteppable.class) && isStopped(ctx))
			.popupWhen(ctx -> 
				isInstance(ctx, TargetSteppable.class) && isStopped(ctx))
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
				isInstance(ctx, TargetSteppable.class) && isStopped(ctx))
			.popupWhen(ctx -> 
				isInstance(ctx, TargetSteppable.class) && isStopped(ctx))
			.onAction(ctx -> performStepOver(ctx))
			.enabled(false)
			.buildAndInstallLocal(this);
		
		groupTargetIndex++;

		new ActionBuilder("Finish", plugin.getName())
		.keyBinding("F12")
		.toolBarGroup(DebuggerResources.GROUP_CONTROL, "C" + groupTargetIndex)
		.toolBarIcon(AbstractStepFinishAction.ICON)
		.popupMenuPath("&Finish")
		.popupMenuGroup(DebuggerResources.GROUP_CONTROL, "C" + groupTargetIndex)
		.popupMenuIcon(AbstractStepFinishAction.ICON)
		.helpLocation(AbstractStepFinishAction.help(plugin))
		//.withContext(ObjectActionContext.class)
		.enabledWhen(ctx -> 
			isInstance(ctx, TargetSteppable.class) && isStopped(ctx))
		.popupWhen(ctx -> 
			isInstance(ctx, TargetSteppable.class) && isStopped(ctx))
		.onAction(ctx -> performStepFinish(ctx))
		.enabled(false)
		.buildAndInstallLocal(this);
	
	groupTargetIndex++;
	
	new ActionBuilder("Step Last", plugin.getName())
		.keyBinding("ALT F8")
		.toolBarGroup(DebuggerResources.GROUP_CONTROL, "C" + groupTargetIndex)
		.toolBarIcon(AbstractStepLastAction.ICON)
		.popupMenuPath("&Step Last")
		.popupMenuGroup(DebuggerResources.GROUP_CONTROL, "C" + groupTargetIndex)
		.popupMenuIcon(AbstractStepLastAction.ICON)
		.helpLocation(AbstractStepLastAction.help(plugin))
		//.withContext(ObjectActionContext.class)
		.enabledWhen(ctx -> 
			isInstance(ctx, TargetSteppable.class) && isStopped(ctx))
		.popupWhen(ctx -> 
			isInstance(ctx, TargetSteppable.class) && isStopped(ctx))
		.onAction(ctx -> performStepLast(ctx))
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
				isInstance(ctx, TargetBreakpointSpecContainer.class) && isStopped(ctx))
			.popupWhen(ctx -> 
				isInstance(ctx, TargetBreakpointSpecContainer.class) && isStopped(ctx))
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
			.enabledWhen(ctx -> isInstance(ctx, TargetInterpreter.class))
			.popupWhen(ctx -> isInstance(ctx, TargetInterpreter.class))
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

	public void performToggleBase(ActionContext context) {
		//Object contextObject = context.getContextObject();
		for (TargetConfigurable configurable : configurables) {
			Object value = configurable.getCachedAttribute(TargetConfigurable.BASE_ATTRIBUTE_NAME);
			if (value != null) {
				Integer base = (Integer) value;
				base = base == 10 ? 16 : 10;
				configurable.writeConfigurationOption(TargetConfigurable.BASE_ATTRIBUTE_NAME, base);
			}
		}
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

	protected <T extends TargetObject> void performAction(ActionContext context,
			boolean fallbackRoot, Class<T> cls,
			Function<T, CompletableFuture<Void>> func, String errorMsg) {
		TargetObject obj = getObjectFromContext(context);
		if (obj == null && fallbackRoot) {
			obj = root.getTargetObject();
		}
		if (!isLocalOnly()) {
			DebugModelConventions.findSuitable(cls, obj).thenCompose(t -> {
				return func.apply(t);
			}).exceptionally(DebuggerResources.showError(getComponent(), errorMsg));
		}
		else {
			T t = cls.cast(obj);
			func.apply(t).exceptionally(DebuggerResources.showError(getComponent(), errorMsg));
		}
	}

	public void performQuickLaunch(ActionContext context) {
		if (currentProgram == null) {
			return;
		}
		performAction(context, true, TargetLauncher.class, launcher -> {
			// TODO: A generic or pluggable way of deriving the launch arguments
			return launcher.launch(Map.of(
				TargetCmdLineLauncher.CMDLINE_ARGS_NAME, currentProgram.getExecutablePath()));
		}, "Couldn't launch");
	}

	public void performLaunch(ActionContext context) {
		performAction(context, true, TargetLauncher.class, launcher -> {
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
		}, "Couldn't launch");
	}

	public void performAttach(ActionContext context) {
		TargetObject obj = getObjectFromContext(context);
		performAction(context, false, TargetAttacher.class, attacher -> {
			attachDialog.setAttacher(attacher);
			if (obj instanceof TargetAttachable) {
				return attacher.attach((TargetAttachable) obj);
			}
			else {
				attachDialog.fetchAndDisplayAttachable();
				tool.showDialog(attachDialog);
				return AsyncUtils.NIL;
			}
		}, "Couldn't attach");
	}

	public void performReattach(ActionContext context) {
		TargetObject obj = getObjectFromContext(context);
		if (!(obj instanceof TargetAttachable)) {
			return;
		}
		// NB. This doesn't really mean anything in local-only actions mode
		DebugModelConventions.findSuitable(TargetAttacher.class, obj).thenCompose(attacher -> {
			return attacher.attach((TargetAttachable) obj);
		}).exceptionally(DebuggerResources.showError(getComponent(), "Couldn't re-attach"));
	}

	public void startRecording(TargetProcess targetObject, boolean prompt) {
		TraceRecorder rec;
		if (prompt) {
			rec = modelService.recordTargetPromptOffers(targetObject);
		}
		else {
			rec = modelService.recordTargetBestOffer(targetObject);
		}
		if (rec == null) {
			return; // Cancelled
		}
		//this.recorder = rec;
		Trace trace = rec.getTrace();
		traceManager.openTrace(trace);
		traceManager.activateTrace(trace);
	}

	public void stopRecording(TargetObject targetObject) {
		// TODO: Do `this.recorder = ...` on every object selection change?
		TraceRecorder rec = modelService.getRecorderForSuccessor(targetObject);
		if (rec != null) {
			rec.stopRecording();
		}
	}

	public void performDetach(ActionContext context) {
		performAction(context, false, TargetDetachable.class, TargetDetachable::detach,
			"Couldn't detach");
	}

	public void performKill(ActionContext context) {
		performAction(context, false, TargetKillable.class, TargetKillable::kill, "Couldn't kill");
	}

	public void performStartRecording(ActionContext context) {
		performAction(context, false, TargetProcess.class, proc -> {
			TargetProcess valid = DebugModelConventions.liveProcessOrNull(proc);
			if (valid != null) {
				startRecording(valid, true);
			}
			return AsyncUtils.NIL;
		}, "Couldn't record");
	}

	public void performResume(ActionContext context) {
		performAction(context, false, TargetResumable.class, TargetResumable::resume,
			"Couldn't resume");
	}

	public void performInterrupt(ActionContext context) {
		performAction(context, false, TargetInterruptible.class, TargetInterruptible::interrupt,
			"Couldn't interrupt");
	}

	public void performStepInto(ActionContext context) {
		performAction(context, false, TargetSteppable.class, TargetSteppable::step,
			"Couldn't step into");
	}

	public void performStepOver(ActionContext context) {
		performAction(context, false, TargetSteppable.class, s -> s.step(TargetStepKind.OVER),
			"Couldn't step over");
	}

	public void performStepFinish(ActionContext context) {
		performAction(context, false, TargetSteppable.class, s -> s.step(TargetStepKind.FINISH),
			"Couldn't step finish");
	}

	public void performStepLast(ActionContext context) {
		performAction(context, false, TargetSteppable.class, s -> {
			if (extendedStep.equals("")) {
				return s.step(TargetStepKind.EXTENDED);
			}
			else {
				return s.step(Map.of("Command", extendedStep));
			}
		}, "Couldn't step extended(" + extendedStep + ")");
	}

	public void performSetBreakpoint(ActionContext context) {
		performAction(context, false, TargetBreakpointSpecContainer.class, container -> {
			breakpointDialog.setContainer(container);
			tool.showDialog(breakpointDialog);
			return AsyncUtils.NIL;
		}, "Couldn't set breakpoint");
	}

	public void initiateConsole(ActionContext context) {
		performAction(context, false, TargetInterpreter.class, interpreter -> {
			getPlugin().showConsole(interpreter);
			return AsyncUtils.NIL;
		}, "Couldn't show interpreter");
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
			if (object instanceof TargetExecutionStateful) {
				TargetExecutionStateful stateful = (TargetExecutionStateful) object;
				TargetExecutionState executionState = stateful.getExecutionState();
				//System.err.println(stateful + ":" + executionState);
				return !executionState.equals(TargetExecutionState.RUNNING);
			}
			return false;
		}
		TargetObject result = null;
		try {
			result = DebugModelConventions.findSuitable(TargetExecutionStateful.class, object)
					.get(100, TimeUnit.MILLISECONDS);
		}
		catch (Exception e) {
			// IGNORE
		}
		if (result != null) {
			TargetExecutionStateful stateful = (TargetExecutionStateful) result;
			TargetExecutionState executionState = stateful.getExecutionState();
			return !executionState.equals(TargetExecutionState.RUNNING);
		}
		return false;
	}

	class MyObjectListener extends AnnotatedDebuggerAttributeListener {
		protected final DebuggerCallbackReorderer reorderer = new DebuggerCallbackReorderer(this);
		protected final PrivatelyQueuedListener<DebuggerModelListener> queue =
			new PrivatelyQueuedListener<>(DebuggerModelListener.class, "ObjectsProvider-EventQueue",
				reorderer);

		public MyObjectListener() {
			super(MethodHandles.lookup());
		}

		@AttributeCallback(TargetAccessConditioned.ACCESSIBLE_ATTRIBUTE_NAME)
		public void accessibilityChanged(TargetObject object, boolean accessible) {
			//this.access = accessibility.equals(TargetAccessibility.ACCESSIBLE);
			plugin.getTool().contextChanged(DebuggerObjectsProvider.this);
		}

		@Override
		public void consoleOutput(TargetObject console, Channel channel, String out) {
			//getPlugin().showConsole((TargetInterpreter) console);
			System.err.println("consoleOutput: " + out);
		}

		@AttributeCallback(TargetObject.DISPLAY_ATTRIBUTE_NAME)
		public void displayChanged(TargetObject object, String display) {
			//System.err.println("displayChanged: " + display);
			if (ObjectContainer.visibleByDefault(object.getName())) {
				pane.signalDataChanged(getContainerByPath(object.getPath()));
			}
		}

		@AttributeCallback(TargetObject.MODIFIED_ATTRIBUTE_NAME)
		public void modifiedChanged(TargetObject object, boolean modified) {
			//System.err.println("modifiedChanged: " + display);
			if (ObjectContainer.visibleByDefault(object.getName())) {
				pane.signalDataChanged(getContainerByPath(object.getPath()));
			}
		}

		@AttributeCallback(TargetExecutionStateful.STATE_ATTRIBUTE_NAME)
		public void executionStateChanged(TargetObject object, TargetExecutionState state) {
			//this.state = state;
			plugin.getTool().contextChanged(DebuggerObjectsProvider.this);
		}

		@AttributeCallback(TargetFocusScope.FOCUS_ATTRIBUTE_NAME)
		public void focusChanged(TargetObject object, TargetObject focused) {
			plugin.setFocus(object, focused);
			plugin.getTool().contextChanged(DebuggerObjectsProvider.this);
		}

		@Override
		public void memoryUpdated(TargetObject memory, Address address, byte[] data) {
			//System.err.println("memoryUpdated");
		}

		@Override
		public void memoryReadError(TargetObject memory, AddressRange range,
				DebuggerMemoryAccessException e) {
			System.err.println("memoryReadError");
		}

		@AttributeCallback(TargetInterpreter.PROMPT_ATTRIBUTE_NAME)
		public void promptChanged(TargetObject interpreter, String prompt) {
			//System.err.println("promptChanged: " + prompt);
		}

		@Override
		public void registersUpdated(TargetObject bank, Map<String, byte[]> updates) {
			Map<String, ? extends TargetObject> cachedElements = bank.getCachedElements();
			for (String key : cachedElements.keySet()) {
				TargetObject ref = cachedElements.get(key);
				displayChanged(ref, "registersUpdated");
			}
			Map<String, ?> cachedAttributes = bank.getCachedAttributes();
			for (String key : cachedAttributes.keySet()) {
				Object obj = cachedAttributes.get(key);
				if (obj instanceof TargetObject) {
					displayChanged((TargetObject) obj, "registersUpdated");
				}
			}
		}

		@Override
		public void elementsChanged(TargetObject parent, Collection<String> removed,
				Map<String, ? extends TargetObject> added) {
			//System.err.println("local EC: " + parent);
			ObjectContainer container =
				parent == null ? null : getContainerByPath(parent.getPath());
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
					container.propagateProvider(DebuggerObjectsProvider.this);
					update(container);
					getComponent().repaint();
				}
			}
		}

		@Override
		public void attributesChanged(TargetObject parent, Collection<String> removed,
				Map<String, ?> added) {
			super.attributesChanged(parent, removed, added);
			//System.err.println("local AC: " + parent + ":" + removed + ":" + added);
			ObjectContainer container =
				parent == null ? null : getContainerByPath(parent.getPath());
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
					container.propagateProvider(DebuggerObjectsProvider.this);
					update(container);
					getComponent().repaint();
				}
			}
			if (parent != null && isAutorecord() &&
				parent.getCachedAttribute(TargetExecutionStateful.STATE_ATTRIBUTE_NAME) != null) {
				TargetProcess proc = DebugModelConventions.liveProcessOrNull(parent);
				if (proc != null) {
					startRecording(proc, false);
				}
			}
		}
	}

	public void setFocus(TargetObject object, TargetObject focused) {
		if (focused.getModel() != currentModel) {
			return;
		}
		pane.setFocus(object, focused);
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
			case OPTION_NAME_INVALIDATED_FOREGROUND_COLOR:
				return invalidatedForegroundColor;
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

	public DebuggerModelListener getListener() {
		return listener.queue.in;
	}

}
