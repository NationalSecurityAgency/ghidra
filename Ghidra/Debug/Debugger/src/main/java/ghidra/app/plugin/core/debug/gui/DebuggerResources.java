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
package ghidra.app.plugin.core.debug.gui;

import java.awt.Color;
import java.awt.Component;
import java.awt.event.*;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CancellationException;
import java.util.function.Function;

import javax.swing.*;

import docking.action.DockingAction;
import docking.action.ToggleDockingAction;
import docking.action.builder.*;
import docking.widgets.table.*;
import docking.widgets.tree.GTreeNode;
import ghidra.app.plugin.core.debug.DebuggerPluginPackage;
import ghidra.app.plugin.core.debug.gui.breakpoint.DebuggerBreakpointsPlugin;
import ghidra.app.plugin.core.debug.gui.console.DebuggerConsolePlugin;
import ghidra.app.plugin.core.debug.gui.listing.DebuggerListingPlugin;
import ghidra.app.plugin.core.debug.gui.memory.DebuggerRegionsPlugin;
import ghidra.app.plugin.core.debug.gui.modules.DebuggerModulesPlugin;
import ghidra.app.plugin.core.debug.gui.modules.DebuggerStaticMappingPlugin;
import ghidra.app.plugin.core.debug.gui.objects.DebuggerObjectsPlugin;
import ghidra.app.plugin.core.debug.gui.pcode.DebuggerPcodeStepperPlugin;
import ghidra.app.plugin.core.debug.gui.register.DebuggerRegistersPlugin;
import ghidra.app.plugin.core.debug.gui.stack.DebuggerStackPlugin;
import ghidra.app.plugin.core.debug.gui.target.DebuggerTargetsPlugin;
import ghidra.app.plugin.core.debug.gui.thread.DebuggerThreadsPlugin;
import ghidra.app.plugin.core.debug.gui.time.DebuggerTimePlugin;
import ghidra.app.plugin.core.debug.gui.watch.DebuggerWatchesPlugin;
import ghidra.app.plugin.core.debug.service.model.launch.DebuggerProgramLaunchOffer;
import ghidra.app.services.DebuggerTraceManagerService.BooleanChangeAdapter;
import ghidra.app.services.MarkerService;
import ghidra.async.AsyncUtils;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.util.PluginUtils;
import ghidra.program.database.ProgramContentHandler;
import ghidra.trace.model.Trace;
import ghidra.util.*;
import ghidra.util.exception.CancelledException;
import resources.MultiIcon;
import resources.ResourceManager;
import resources.icons.RotateIcon;

public interface DebuggerResources {
	String OPTIONS_CATEGORY_WORKFLOW = "Debugger.Workflow";

	ImageIcon ICON_DEBUGGER = ResourceManager.loadImage("images/debugger.png");

	ImageIcon ICON_CONNECTION = ResourceManager.loadImage("images/connect.png");
	ImageIcon ICON_DISCONNECT = ResourceManager.loadImage("images/disconnect.png");

	ImageIcon ICON_PROCESS = ResourceManager.loadImage("images/process.png");
	ImageIcon ICON_TRACE = Trace.TRACE_ICON;
	ImageIcon ICON_THREAD = ResourceManager.loadImage("images/thread.png");
	ImageIcon ICON_PROGRAM = ProgramContentHandler.PROGRAM_ICON;

	ImageIcon ICON_LAUNCH = ResourceManager.loadImage("images/launch.png");
	ImageIcon ICON_ATTACH = ResourceManager.loadImage("images/attach.png");
	ImageIcon ICON_RESUME = ResourceManager.loadImage("images/continue.png");
	ImageIcon ICON_TERMINATE = ResourceManager.loadImage("images/stop.png");
	ImageIcon ICON_KILL = ResourceManager.loadImage("images/kill.png");
	ImageIcon ICON_DETACH = ResourceManager.loadImage("images/detach.png");
	ImageIcon ICON_RECORD = ResourceManager.loadImage("images/record.png");

	ImageIcon ICON_STEP_INTO = ResourceManager.loadImage("images/stepinto.png");
	ImageIcon ICON_STEP_OVER = ResourceManager.loadImage("images/stepover.png");
	ImageIcon ICON_STEP_FINISH = ResourceManager.loadImage("images/stepout.png");
	ImageIcon ICON_STEP_BACK = ResourceManager.loadImage("images/stepback.png");
	// TODO: Draw new icons?
	ImageIcon ICON_SNAP_FORWARD = ResourceManager.loadImage("images/2rightarrow.png");
	ImageIcon ICON_SNAP_BACKWARD = ResourceManager.loadImage("images/2leftarrow.png");
	ImageIcon ICON_SEEK_PRESENT = ICON_RESUME;

	boolean altIcons = Boolean.getBoolean("debugger.breakpoints.alt.icons");

	ImageIcon ICON_SET_BREAKPOINT =
		altIcons ? ResourceManager.loadImage("images/alt-breakpoint-set.png")
				: ResourceManager.loadImage("images/breakpoint-set.png");
	ImageIcon ICON_CLEAR_BREAKPOINT =
		altIcons ? ResourceManager.loadImage("images/alt-breakpoint-clear.png")
				: ResourceManager.loadImage("images/breakpoint-clear.png");
	ImageIcon ICON_ENABLE_BREAKPOINT =
		altIcons ? ResourceManager.loadImage("images/alt-breakpoint-enable.png")
				: ResourceManager.loadImage("images/breakpoint-enable.png");
	ImageIcon ICON_ENABLE_ALL_BREAKPOINTS =
		altIcons ? ResourceManager.loadImage("images/alt-breakpoints-enable-all.png")
				: ResourceManager.loadImage("images/breakpoints-enable-all.png");
	ImageIcon ICON_DISABLE_BREAKPOINT =
		altIcons ? ResourceManager.loadImage("images/alt-breakpoint-disable.png")
				: ResourceManager.loadImage("images/breakpoint-disable.png");
	ImageIcon ICON_DISABLE_ALL_BREAKPOINTS =
		altIcons ? ResourceManager.loadImage("images/alt-breakpoints-disable-all.png")
				: ResourceManager.loadImage("images/breakpoints-disable-all.png");
	ImageIcon ICON_CLEAR_ALL_BREAKPOINTS =
		altIcons ? ResourceManager.loadImage("images/alt-breakpoints-clear-all.png")
				: ResourceManager.loadImage("images/breakpoints-clear-all.png");
	ImageIcon ICON_MAKE_BREAKPOINTS_EFFECTIVE =
		altIcons ? ResourceManager.loadImage("images/alt-breakpoints-make-effective.png")
				: ResourceManager.loadImage("images/breakpoints-make-effective.png");

	// TODO: Some overlay to indicate dynamic, or new icon altogether
	ImageIcon ICON_LISTING = ResourceManager.loadImage("images/Browser.gif");
	ImageIcon ICON_CONSOLE = ResourceManager.loadImage("images/console.png");
	ImageIcon ICON_REGISTERS = ResourceManager.loadImage("images/registers.png");
	ImageIcon ICON_STACK = ResourceManager.loadImage("images/stack.png");
	ImageIcon ICON_BREAKPOINTS = ResourceManager.loadImage("images/breakpoints.png");
	ImageIcon ICON_MODULES = ResourceManager.loadImage("images/modules.png");
	ImageIcon ICON_MAPPINGS = ICON_PROGRAM; // TODO: A better icon 
	ImageIcon ICON_PCODE = ResourceManager.loadImage("images/stepinto.png"); // TODO
	//ResourceManager.loadImage("images/mappings.png");
	ImageIcon ICON_REGIONS = ResourceManager.loadImage("images/memory16.gif");
	ImageIcon ICON_TIME = ResourceManager.loadImage("images/time.png");
	// TODO: Draw a real icon. object-populated duplicates breakpoint-enabled
	ImageIcon ICON_OBJECTS = ResourceManager.loadImage("images/object-populated.png");

	ImageIcon ICON_SAVE = ResourceManager.loadImage("images/disk.png");
	ImageIcon ICON_CLOSE = ResourceManager.loadImage("images/x.gif");
	ImageIcon ICON_ADD = ResourceManager.loadImage("images/add.png");
	ImageIcon ICON_DELETE = ResourceManager.loadImage("images/delete.png");
	ImageIcon ICON_CLEAR = ResourceManager.loadImage("images/erase16.png");
	ImageIcon ICON_REFRESH = ResourceManager.loadImage("images/view-refresh.png");
	ImageIcon ICON_FILTER = ResourceManager.loadImage("images/filter_off.png"); // Eww.
	ImageIcon ICON_SELECT_ROWS = ResourceManager.loadImage("images/table_go.png");
	ImageIcon ICON_AUTOREAD = ResourceManager.loadImage("images/autoread.png");

	// TODO: Draw a real icon.
	ImageIcon ICON_CAPTURE_MEMORY = ICON_REGIONS;
	//ResourceManager.loadImage("images/capture-memory.png");

	// TODO: Draw an icon
	ImageIcon ICON_MAP_IDENTICALLY = ResourceManager.loadImage("images/doubleArrow.png");
	ImageIcon ICON_MAP_MODULES = ResourceManager.loadImage("images/modules.png");
	ImageIcon ICON_MAP_SECTIONS = ICON_MAP_MODULES; // TODO
	ImageIcon ICON_BLOCK = ICON_MAP_SECTIONS; // TODO
	// TODO: Draw an icon
	ImageIcon ICON_SELECT_ADDRESSES = ResourceManager.loadImage("images/NextSelectionBlock16.gif");
	// TODO: Draw an icon?
	ImageIcon ICON_DATA_TYPES = ResourceManager.loadImage("images/dataTypes.png");
	// TODO: Draw an icon?
	ImageIcon ICON_CAPTURE_SYMBOLS = ResourceManager.loadImage("images/closedFolderLabels.png");

	ImageIcon ICON_LOG_FATAL = ResourceManager.loadImage("images/edit-bomg.png");
	ImageIcon ICON_LOG_ERROR = ResourceManager.loadImage("images/dialog-warning_red.png");
	ImageIcon ICON_LOG_WARN = ResourceManager.loadImage("images/dialog-warning.png");

	ImageIcon ICON_SYNC = ResourceManager.loadImage("images/sync_enabled.png");
	ImageIcon ICON_VISIBILITY = ResourceManager.loadImage("images/format-text-bold.png");

	ImageIcon ICON_PIN = ResourceManager.loadImage("images/pin.png");
	// TODO: Find better icon?
	ImageIcon ICON_IMPORT = ResourceManager.loadImage("images/imported_bookmark.gif");
	ImageIcon ICON_BLANK = ResourceManager.loadImage("images/blank.png");
	ImageIcon ICON_PACKAGE = ResourceManager.loadImage("images/debugger32.png");
	ImageIcon ICON_EMULATE = ICON_PROCESS; // TODO
	ImageIcon ICON_CONFIG = ResourceManager.loadImage("images/conf.png");
	ImageIcon ICON_TOGGLE = ResourceManager.loadImage("images/system-switch-user.png");

	HelpLocation HELP_PACKAGE = new HelpLocation("Debugger", "package");

	String HELP_ANCHOR_PLUGIN = "plugin";

	String TITLE_PROVIDER_BREAKPOINTS = "Breakpoints";
	ImageIcon ICON_PROVIDER_BREAKPOINTS = ICON_BREAKPOINTS;
	HelpLocation HELP_PROVIDER_BREAKPOINTS = new HelpLocation(
		PluginUtils.getPluginNameFromClass(DebuggerBreakpointsPlugin.class), HELP_ANCHOR_PLUGIN);

	String TITLE_PROVIDER_CONSOLE = "Debug Console";
	ImageIcon ICON_PROVIDER_CONSOLE = ICON_CONSOLE;
	HelpLocation HELP_PROVIDER_CONSOLE = new HelpLocation(
		PluginUtils.getPluginNameFromClass(DebuggerConsolePlugin.class), HELP_ANCHOR_PLUGIN);

	String TITLE_PROVIDER_LISTING = "Dynamic";
	ImageIcon ICON_PROVIDER_LISTING = ICON_LISTING;
	HelpLocation HELP_PROVIDER_LISTING = new HelpLocation(
		PluginUtils.getPluginNameFromClass(DebuggerListingPlugin.class), HELP_ANCHOR_PLUGIN);

	String TITLE_PROVIDER_MAPPINGS = "Static Mappings";
	ImageIcon ICON_PROVIDER_MAPPINGS = ICON_MAPPINGS;
	HelpLocation HELP_PROVIDER_MAPPINGS = new HelpLocation(
		PluginUtils.getPluginNameFromClass(DebuggerStaticMappingPlugin.class), HELP_ANCHOR_PLUGIN);

	String TITLE_PROVIDER_MODULES = "Modules";
	ImageIcon ICON_PROVIDER_MODULES = ICON_MODULES;
	HelpLocation HELP_PROVIDER_MODULES = new HelpLocation(
		PluginUtils.getPluginNameFromClass(DebuggerModulesPlugin.class), HELP_ANCHOR_PLUGIN);

	String TITLE_PROVIDER_PCODE = "Pcode Stepper";
	ImageIcon ICON_PROVIDER_PCODE = ICON_PCODE;
	HelpLocation HELP_PROVIDER_PCODE = new HelpLocation(
		PluginUtils.getPluginNameFromClass(DebuggerPcodeStepperPlugin.class), HELP_ANCHOR_PLUGIN);

	String TITLE_PROVIDER_REGIONS = "Regions";
	ImageIcon ICON_PROVIDER_REGIONS = ICON_REGIONS;
	HelpLocation HELP_PROVIDER_REGIONS = new HelpLocation(
		PluginUtils.getPluginNameFromClass(DebuggerRegionsPlugin.class), HELP_ANCHOR_PLUGIN);

	String TITLE_PROVIDER_REGISTERS = "Registers";
	ImageIcon ICON_PROVIDER_REGISTERS = ICON_REGISTERS;
	HelpLocation HELP_PROVIDER_REGISTERS = new HelpLocation(
		PluginUtils.getPluginNameFromClass(DebuggerRegistersPlugin.class), HELP_ANCHOR_PLUGIN);

	String TITLE_PROVIDER_TARGETS = "Debugger Targets";
	ImageIcon ICON_PROVIDER_TARGETS = ICON_CONNECTION; // TODO: Same icon as action
	HelpLocation HELP_PROVIDER_TARGETS = new HelpLocation(
		PluginUtils.getPluginNameFromClass(DebuggerTargetsPlugin.class), HELP_ANCHOR_PLUGIN);

	String TITLE_PROVIDER_STACK = "Stack";
	ImageIcon ICON_PROVIDER_STACK = ICON_STACK;
	HelpLocation HELP_PROVIDER_STACK = new HelpLocation(
		PluginUtils.getPluginNameFromClass(DebuggerStackPlugin.class), HELP_ANCHOR_PLUGIN);

	String TITLE_PROVIDER_THREADS = "Threads";
	ImageIcon ICON_PROVIDER_THREADS = ICON_DEBUGGER;
	HelpLocation HELP_PROVIDER_THREADS = new HelpLocation(
		PluginUtils.getPluginNameFromClass(DebuggerThreadsPlugin.class), HELP_ANCHOR_PLUGIN);

	String TITLE_PROVIDER_TIME = "Time";
	ImageIcon ICON_PROVIDER_TIME = ICON_TIME;
	HelpLocation HELP_PROVIDER_TIME = new HelpLocation(
		PluginUtils.getPluginNameFromClass(DebuggerTimePlugin.class), HELP_ANCHOR_PLUGIN);

	String TITLE_PROVIDER_OBJECTS = "Objects";
	ImageIcon ICON_PROVIDER_OBJECTS = ResourceManager.loadImage("images/time.png");
	HelpLocation HELP_PROVIDER_OBJECTS = new HelpLocation(
		PluginUtils.getPluginNameFromClass(DebuggerObjectsPlugin.class), HELP_ANCHOR_PLUGIN);

	String TITLE_PROVIDER_WATCHES = "Watches";
	ImageIcon ICON_PROVIDER_WATCHES = ICON_AUTOREAD; // TODO: Another icon?
	HelpLocation HELP_PROVIDER_WATCHES = new HelpLocation(
		PluginUtils.getPluginNameFromClass(DebuggerWatchesPlugin.class), HELP_ANCHOR_PLUGIN);

	String TITLE_PROVIDER_INTERPRETER = "Interpreter";

	String BOOKMARK_CATEGORY_MEMORY_READ_ERROR = "Debugger Memory Read Error";

	String OPTION_NAME_COLORS_STALE_MEMORY = "Colors.Stale Memory";
	Color DEFAULT_COLOR_BACKGROUND_STALE = Color.LIGHT_GRAY;

	String OPTION_NAME_COLORS_ERROR_MEMORY = "Colors.Error Memory";
	Color DEFAULT_COLOR_BACKGROUND_ERROR = new Color(1.0f, 0.75f, 0.75f);

	int PRIORITY_REGISTER_MARKER = 10;
	String OPTION_NAME_COLORS_TRACKING_MARKERS = "Colors.Tracking Markers";
	Color DEFAULT_COLOR_REGISTER_MARKERS = new Color(0.75f, 0.875f, 0.75f);
	ImageIcon ICON_REGISTER_MARKER = ResourceManager.loadImage("images/register-marker.png");

	String OPTION_NAME_COLORS_REGISTER_STALE = "Colors.Stale Registers";
	Color DEFAULT_COLOR_REGISTER_STALE = Color.GRAY;
	String OPTION_NAME_COLORS_REGISTER_STALE_SEL = "Colors.Stale Registers (selected)";
	Color DEFAULT_COLOR_REGISTER_STALE_SEL = Color.LIGHT_GRAY;
	String OPTION_NAME_COLORS_REGISTER_CHANGED = "Colors.Changed Registers";
	Color DEFAULT_COLOR_REGISTER_CHANGED = Color.RED;
	String OPTION_NAME_COLORS_REGISTER_CHANGED_SEL = "Colors.Changed Registers (selected)";
	Color DEFAULT_COLOR_REGISTER_CHANGED_SEL = ColorUtils.blend(Color.RED, Color.WHITE, 0.5f);

	String OPTION_NAME_COLORS_WATCH_STALE = "Colors.Stale Watches";
	Color DEFAULT_COLOR_WATCH_STALE = Color.GRAY;
	String OPTION_NAME_COLORS_WATCH_STALE_SEL = "Colors.Stale Watches (selected)";
	Color DEFAULT_COLOR_WATCH_STALE_SEL = Color.LIGHT_GRAY;
	String OPTION_NAME_COLORS_WATCH_CHANGED = "Colors.Changed Watches";
	Color DEFAULT_COLOR_WATCH_CHANGED = Color.RED;
	String OPTION_NAME_COLORS_WATCH_CHANGED_SEL = "Colors.Changed Watches (selected)";
	Color DEFAULT_COLOR_WATCH_CHANGED_SEL = ColorUtils.blend(Color.RED, Color.WHITE, 0.5f);

	String OPTION_NAME_COLORS_PCODE_COUNTER = "Colors.Pcode Counter";
	Color DEFAULT_COLOR_PCODE_COUNTER = new Color(0.75f, 0.875f, 0.75f);

	String MARKER_NAME_BREAKPOINT_ENABLED = "Enabled Breakpoint";
	String MARKER_NAME_BREAKPOINT_DISABLED = "Disabled Breakpoint";
	String MARKER_NAME_BREAKPOINT_INEFFECTIVE_E = "Ineffective Enabled Breakpoint";
	String MARKER_NAME_BREAKPOINT_INEFFECTIVE_D = "Ineffective Disabled Breakpoint";
	String MARKER_NAME_BREAKPOINT_MIXED_ED = "Mixed Enabled-Disabled Breakpont";
	String MARKER_NAME_BREAKPOINT_MIXED_DE = "Mixed Disabled-Enabled Breakpont";
	int PRIORITY_BREAKPOINT_ENABLED_MARKER = MarkerService.BREAKPOINT_PRIORITY;
	int PRIORITY_BREAKPOINT_DISABLED_MARKER = MarkerService.BREAKPOINT_PRIORITY;
	int PRIORITY_BREAKPOINT_INEFFECTIVE_E_MARKER = MarkerService.BREAKPOINT_PRIORITY;
	int PRIORITY_BREAKPOINT_INEFFECTIVE_D_MARKER = MarkerService.BREAKPOINT_PRIORITY;
	int PRIORITY_BREAKPOINT_MIXED_ED_MARKER = MarkerService.BREAKPOINT_PRIORITY;
	int PRIORITY_BREAKPOINT_MIXED_DE_MARKER = MarkerService.BREAKPOINT_PRIORITY;

	ImageIcon ICON_BREAKPOINT_ENABLED_MARKER = ICON_ENABLE_BREAKPOINT;
	ImageIcon ICON_BREAKPOINT_DISABLED_MARKER = ICON_DISABLE_BREAKPOINT;
	ImageIcon ICON_BREAKPOINT_MIXED_ED_MARKER =
		altIcons ? ResourceManager.loadImage("images/alt-breakpoint-mixed-ed.png")
				: ResourceManager.loadImage("images/breakpoint-mixed-ed.png");
	ImageIcon ICON_BREAKPOINT_MIXED_DE_MARKER =
		altIcons ? ResourceManager.loadImage("images/alt-breakpoint-mixed-de.png")
				: ResourceManager.loadImage("images/breakpoint-mixed-de.png");
	ImageIcon ICON_BREAKPOINT_INEFFECTIVE_E_MARKER =
		altIcons ? ResourceManager.loadImage("images/alt-breakpoint-ineffective-e.png")
				: ResourceManager.loadImage("images/breakpoint-ineffective-e.png");
	ImageIcon ICON_BREAKPOINT_INEFFECTIVE_D_MARKER =
		altIcons ? ResourceManager.loadImage("images/alt-breakpoint-ineffective-d.png")
				: ResourceManager.loadImage("images/breakpoint-ineffective-d.png");

	Icon ICON_UNIQUE_REF_READ =
		new RotateIcon(ResourceManager.loadImage("images/cursor_arrow.gif"), 180); // TODO
	ImageIcon ICON_UNIQUE_REF_WRITE = ResourceManager.loadImage("images/cursor_arrow.gif"); // TODO
	Icon ICON_UNIQUE_REF_RW = new MultiIcon(ICON_UNIQUE_REF_READ, ICON_UNIQUE_REF_WRITE); // TODO

	String OPTION_NAME_COLORS_ENABLED_BREAKPOINT_MARKERS = "Colors.Enabled Breakpoint Markers";
	Color DEFAULT_COLOR_ENABLED_BREAKPOINT_MARKERS = new Color(0.875f, 0.75f, 0.75f);
	String OPTION_NAME_COLORS_DISABLED_BREAKPOINT_MARKERS = "Colors.Disabled Breakpoint Markers";
	Color DEFAULT_COLOR_DISABLED_BREAKPOINT_MARKERS = DEFAULT_COLOR_ENABLED_BREAKPOINT_MARKERS;
	String OPTION_NAME_COLORS_INEFFECTIVE_E_BREAKPOINT_MARKERS =
		"Colors.Ineffective Enabled Breakpoint Markers";
	Color DEFAULT_COLOR_INEFFECTIVE_E_BREAKPOINT_MARKERS = new Color(0.75f, 0.75f, 0.75f);
	String OPTION_NAME_COLORS_INEFFECTIVE_D_BREAKPOINT_MARKERS =
		"Colors.Ineffective Disabled Breakpoint Markers";
	Color DEFAULT_COLOR_INEFFECTIVE_D_BREAKPOINT_MARKERS =
		DEFAULT_COLOR_INEFFECTIVE_E_BREAKPOINT_MARKERS;

	String OPTION_NAME_COLORS_ENABLED_BREAKPOINT_COLORING_BACKGROUND =
		"Colors.Enabled Breakpoint Markers Have Background";
	boolean DEFAULT_COLOR_ENABLED_BREAKPOINT_COLORING_BACKGROUND = true;

	String OPTION_NAME_COLORS_DISABLED_BREAKPOINT_COLORING_BACKGROUND =
		"Colors.Disabled Breakpoint Markers Have Background";
	boolean DEFAULT_COLOR_DISABLED_BREAKPOINT_COLORING_BACKGROUND = false;

	String OPTION_NAME_COLORS_INEFFECTIVE_E_BREAKPOINT_COLORING_BACKGROUND =
		"Colors.Ineffective Enabled Breakpoint Markers Have Background";
	boolean DEFAULT_COLOR_INEFFECTIVE_E_BREAKPOINT_COLORING_BACKGROUND = true;

	String OPTION_NAME_COLORS_INEFFECTIVE_D_BREAKPOINT_COLORING_BACKGROUND =
		"Colors.Ineffective Disabled Breakpoint Markers Have Background";
	boolean DEFAULT_COLOR_INEFFECTIVE_D_BREAKPOINT_COLORING_BACKGROUND = false;

	String OPTION_NAME_LOG_BUFFER_LIMIT = "Log Buffer Size";
	int DEFAULT_LOG_BUFFER_LIMIT = 100;

	// TODO: Re-assign/name groups
	String GROUP_GENERAL = "Dbg1. General";
	String GROUP_CONNECTION = "Dbg2. Connection";
	String GROUP_VIEWS = "Dbg3. Views";
	String GROUP_TRANSIENT_VIEWS = "Dbg3a. Transient Views";
	String GROUP_CONTROL = "Dbg4. Control";
	String GROUP_TARGET = "Dbg5. Target";
	String GROUP_BREAKPOINTS = "Dbg6. Breakpoints";
	String GROUP_TRACE = "Dbg7. Trace";
	String GROUP_TRACE_TOGGLES = "Dbg7.a. Trace Toggles";
	String GROUP_TRACE_CLOSE = "Dbg7.b. Trace Close";
	String GROUP_MAINTENANCE = "Dbg8. Maintenance";
	String GROUP_MAPPING = "Dbg9. Map Modules/Sections";

	static void tableRowActivationAction(GTable table, Runnable runnable) {
		table.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				if (e.getButton() != MouseEvent.BUTTON1) {
					return;
				}
				if (e.getClickCount() != 2) {
					return;
				}
				runnable.run();
			}
		});
		table.addKeyListener(new KeyAdapter() {
			@Override
			public void keyPressed(KeyEvent e) {
				if (e.getKeyCode() == KeyEvent.VK_ENTER && e.getModifiersEx() == 0) {
					runnable.run();
				}
			}
		});
	}

	abstract class AbstractFlushCachesAction extends DockingAction {
		public static final String NAME = "Flush Caches";
		public static final String HELP_ANCHOR = "flush_caches";

		public AbstractFlushCachesAction(Plugin owner) {
			super(NAME, owner.getName());
			setDescription("Flush the targets' client-side caches");
			setHelpLocation(new HelpLocation(owner.getName(), HELP_ANCHOR));
		}
	}

	interface SaveTraceAction {
		String NAME_PREFIX = "Save ";
		String DESCRIPTION = "Save the selected trace";
		Icon ICON = ICON_SAVE;
		String GROUP = GROUP_TRACE;
		String HELP_ANCHOR = "save_trace";

		static ActionBuilder builder(Plugin owner) {
			String ownerName = owner.getName();
			return new ActionBuilder(NAME_PREFIX, ownerName).description(DESCRIPTION)
					.menuPath(DebuggerPluginPackage.NAME, NAME_PREFIX + "...")
					.menuIcon(ICON)
					.menuGroup(GROUP)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
		}
	}

	abstract class AbstractConnectAction extends DockingAction {
		public static final String NAME = "Connect";
		public static final Icon ICON = ICON_CONNECTION;
		public static final String HELP_ANCHOR = "connect";

		public static void styleButton(JButton button) {
			button.setText(NAME);
			button.setIcon(ICON);
		}

		public AbstractConnectAction(Plugin owner) {
			super(NAME, owner.getName());
			setDescription("Create a new connection to an debugging agent");
			setHelpLocation(new HelpLocation(owner.getName(), HELP_ANCHOR));
		}
	}

	abstract class AbstractConsoleAction extends DockingAction {
		public static final String NAME = "Console";
		public static final Icon ICON = ICON_CONSOLE;
		public static final String HELP_ANCHOR = "console";

		public static HelpLocation help(Plugin owner) {
			return new HelpLocation(owner.getName(), HELP_ANCHOR);
		}

		public AbstractConsoleAction(Plugin owner) {
			super(NAME, owner.getName());
			setDescription("Issue commands to the debugger's interpreter");
			setHelpLocation(help(owner));
		}
	}

	abstract class AbstractLaunchAction extends DockingAction {
		public static final String NAME = "Launch";
		public static final Icon ICON = ICON_LAUNCH;
		public static final String HELP_ANCHOR = "launch";

		public static void styleButton(JButton button) {
			button.setText(NAME);
			button.setIcon(ICON);
		}

		public static HelpLocation help(Plugin owner) {
			return new HelpLocation(owner.getName(), HELP_ANCHOR);
		}

		public AbstractLaunchAction(Plugin owner) {
			super(NAME, owner.getName());
			setDescription("Launch a target");
			setHelpLocation(help(owner));
		}
	}

	interface DebugProgramAction {
		String NAME = "Debug Program";
		Icon ICON = ICON_DEBUGGER;
		String GROUP = GROUP_GENERAL;
		String HELP_ANCHOR = "debug_program";

		static <T> MultiStateActionBuilder<T> buttonBuilder(Plugin owner, Plugin helpOwner) {
			return new MultiStateActionBuilder<T>(NAME, owner.getName())
					.toolBarIcon(ICON)
					.toolBarGroup(GROUP)
					.helpLocation(new HelpLocation(helpOwner.getName(), HELP_ANCHOR));
		}

		static ActionBuilder menuBuilder(DebuggerProgramLaunchOffer offer, Plugin owner,
				Plugin helpOwner) {
			return new ActionBuilder(offer.getConfigName(), owner.getName())
					.description(offer.getButtonTitle())
					.menuPath(DebuggerPluginPackage.NAME, offer.getMenuParentTitle(),
						offer.getMenuTitle())
					.menuIcon(offer.getIcon())
					.menuGroup(GROUP)
					.helpLocation(new HelpLocation(helpOwner.getName(), HELP_ANCHOR));
		}
	}

	interface EmulateProgramAction {
		String NAME = "Emulate Program in new Trace";
		String DESCRIPTION = "Emulate the current program in a new trace starting at the cursor";
		Icon ICON = ICON_EMULATE;
		String GROUP = GROUP_GENERAL;
		String HELP_ANCHOR = "emulate_program";

		static ActionBuilder builder(Plugin owner) {
			String ownerName = owner.getName();
			return new ActionBuilder(NAME, ownerName)
					.description(DESCRIPTION)
					.toolBarIcon(ICON)
					.toolBarGroup(GROUP)
					.menuPath(DebuggerPluginPackage.NAME, NAME)
					.menuIcon(ICON)
					.menuGroup(GROUP)
					.popupMenuPath(NAME)
					.popupMenuIcon(ICON)
					.popupMenuGroup(GROUP)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
		}
	}

	interface EmulateAddThreadAction {
		String NAME = "Add Emulated Thread to Trace";
		String DESCRIPTION = "Add an emulated thread to the current trace starting here";
		Icon ICON = ICON_THREAD;
		String GROUP = GROUP_GENERAL;
		String HELP_ANCHOR = "add_emulated_thread";

		static ActionBuilder builder(Plugin owner) {
			String ownerName = owner.getName();
			return new ActionBuilder(NAME, ownerName)
					.description(DESCRIPTION)
					.menuPath(DebuggerPluginPackage.NAME, NAME)
					.menuIcon(ICON)
					.menuGroup(GROUP)
					.popupMenuPath(NAME)
					.popupMenuIcon(ICON)
					.popupMenuGroup(GROUP)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
		}
	}

	abstract class AbstractQuickLaunchAction extends DockingAction {
		public static final String NAME = "Quick Launch";
		public static final Icon ICON = ICON_DEBUGGER; // TODO: A different icon?
		public static final String HELP_ANCHOR = "quick_launch";

		public static HelpLocation help(Plugin owner) {
			return new HelpLocation(owner.getName(), HELP_ANCHOR);
		}

		public AbstractQuickLaunchAction(Plugin owner) {
			super(NAME, owner.getName());
			setDescription("Load a trace in a local or selected connection");
			setHelpLocation(help(owner));
		}
	}

	abstract class AbstractAttachAction extends DockingAction {
		public static final String NAME = "Attach";
		public static final Icon ICON = ICON_ATTACH;
		public static final String DESCRIPTION =
			"Attach to an existing target accessible to the agent";
		public static final String HELP_ANCHOR = "attach";

		public static void styleButton(JButton button) {
			button.setText(NAME);
			button.setIcon(ICON);
		}

		public static HelpLocation help(Plugin owner) {
			return new HelpLocation(owner.getName(), HELP_ANCHOR);
		}

		public AbstractAttachAction(Plugin owner) {
			super(NAME, owner.getName());
			setDescription(DESCRIPTION);
			setHelpLocation(help(owner));
		}
	}

	abstract class AbstractResumeAction extends DockingAction {
		public static final String NAME = "Resume";
		public static final Icon ICON = ICON_RESUME;
		public static final String HELP_ANCHOR = "resume";

		public static HelpLocation help(Plugin owner) {
			return new HelpLocation(owner.getName(), HELP_ANCHOR);
		}

		public AbstractResumeAction(Plugin owner) {
			super(NAME, owner.getName());
			setDescription("Resume, i.e., go or continue execution of, the target");
			setHelpLocation(help(owner));
		}
	}

	abstract class AbstractStepIntoAction extends DockingAction {
		public static final String NAME = "Step Into";
		public static final Icon ICON = ICON_STEP_INTO;
		public static final String HELP_ANCHOR = "step_into";

		public static HelpLocation help(Plugin owner) {
			return new HelpLocation(owner.getName(), HELP_ANCHOR);
		}

		public AbstractStepIntoAction(Plugin owner) {
			super(NAME, owner.getName());
			setDescription("Step the target a single instruction, descending into calls");
			setHelpLocation(help(owner));
		}
	}

	abstract class AbstractStepOverAction extends DockingAction {
		public static final String NAME = "Step Over";
		public static final Icon ICON = ICON_STEP_OVER;
		public static final String HELP_ANCHOR = "step_over";

		public static HelpLocation help(Plugin owner) {
			return new HelpLocation(owner.getName(), HELP_ANCHOR);
		}

		public AbstractStepOverAction(Plugin owner) {
			super(NAME, owner.getName());
			setDescription("Step the target a single instruction, without following calls");
			setHelpLocation(help(owner));
		}
	}

	abstract class AbstractStepFinishAction extends DockingAction {
		public static final String NAME = "Step Finish";
		public static final Icon ICON = ICON_STEP_FINISH;
		public static final String HELP_ANCHOR = "step_finish";

		public static HelpLocation help(Plugin owner) {
			return new HelpLocation(owner.getName(), HELP_ANCHOR);
		}

		public AbstractStepFinishAction(Plugin owner) {
			super(NAME, owner.getName());
			setDescription("Step the target out of the current frame");
			setHelpLocation(help(owner));
		}
	}

	abstract class AbstractStepLastAction extends DockingAction {
		public static final String NAME = "Step Last";
		public static final Icon ICON = ICON_STEP_FINISH; // TODO: Draw one
		public static final String HELP_ANCHOR = "step_last";

		public static HelpLocation help(Plugin owner) {
			return new HelpLocation(owner.getName(), HELP_ANCHOR);
		}

		public AbstractStepLastAction(Plugin owner) {
			super(NAME, owner.getName());
			setDescription("Repeat the last stepping action");
			setHelpLocation(help(owner));
		}
	}

	abstract class AbstractInterruptAction extends DockingAction {
		public static final String NAME = "Interrupt";
		public static final Icon ICON = ICON_TERMINATE;
		public static final String HELP_ANCHOR = "interrupt";

		public static HelpLocation help(Plugin owner) {
			return new HelpLocation(owner.getName(), HELP_ANCHOR);
		}

		public AbstractInterruptAction(Plugin owner) {
			super(NAME, owner.getName());
			setDescription("Interrupt, i.e., suspend, the target");
			setHelpLocation(help(owner));
		}
	}

	abstract class AbstractKillAction extends DockingAction {
		public static final String NAME = "Kill";
		public static final Icon ICON = ICON_KILL;
		public static final String HELP_ANCHOR = "kill";

		public static HelpLocation help(Plugin owner) {
			return new HelpLocation(owner.getName(), HELP_ANCHOR);
		}

		public AbstractKillAction(Plugin owner) {
			super(NAME, owner.getName());
			setDescription("Kill, i.e., forcibly terminate, the target");
			setHelpLocation(help(owner));
		}
	}

	abstract class AbstractDetachAction extends DockingAction {
		public static final String NAME = "Detach";
		public static final Icon ICON = ICON_DETACH;
		public static final String HELP_ANCHOR = "detach";

		public static HelpLocation help(Plugin owner) {
			return new HelpLocation(owner.getName(), HELP_ANCHOR);
		}

		public AbstractDetachAction(Plugin owner) {
			super(NAME, owner.getName());
			setDescription("Detach from the target (this may cause it to resume)");
			setHelpLocation(help(owner));
		}
	}

	abstract class AbstractDisconnectAction extends DockingAction {
		public static final String NAME = "Disconnect";
		public static final Icon ICON = ICON_DISCONNECT;
		public static final String HELP_ANCHOR = "disconnect";

		public AbstractDisconnectAction(Plugin owner) {
			super(NAME, owner.getName());
			setDescription("Close the connection to the debugging agent");
			setHelpLocation(new HelpLocation(owner.getName(), HELP_ANCHOR));
		}
	}

	interface DisconnectAllAction {
		String NAME = "Disconnect All";
		String DESCRIPTION = "Close and Debugger Model Connections";
		Icon ICON = ICON_DISCONNECT;
		String HELP_ANCHOR = "disconnect_all";

		public static ActionBuilder builder(Plugin owner, Plugin helpOwner) {
			return new ActionBuilder(owner.getName(), NAME)
					.description(DESCRIPTION)
					.menuIcon(ICON)
					.helpLocation(new HelpLocation(helpOwner.getName(), HELP_ANCHOR));
		}
	}

	interface PinInterpreterAction {
		String NAME = "Pin Interpreter";
		String DESCRIPTION = "Prevent this Interpreter from closing automatically";
		Icon ICON = ICON_PIN;
		String HELP_ANCHOR = "pin";

		public static ToggleActionBuilder builder(Plugin owner) {
			String ownerName = owner.getName();
			return new ToggleActionBuilder(ownerName, NAME)
					.description(DESCRIPTION)
					.toolBarIcon(ICON)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
		}
	}

	interface InterpreterInterruptAction {
		String NAME = "Interpreter Interrupt";
		String DESCRIPTION = "Send an interrupt through this Interpreter";
		Icon ICON = ICON_TERMINATE;
		String HELP_ANCHOR = "interrupt";

		public static ActionBuilder builder(Plugin owner) {
			String ownerName = owner.getName();
			return new ActionBuilder(ownerName, NAME)
					.description(DESCRIPTION)
					.toolBarIcon(ICON)
					.keyBinding("CTRL I")
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
		}
	}

	abstract class AbstractRecordAction extends DockingAction {
		public static final String NAME = "Record";
		public static final Icon ICON = ICON_TRACE;

		public AbstractRecordAction(Plugin owner) {
			super(NAME, owner.getName());
			setDescription("Record the process into a trace and open it (live trace)");
			setHelpLocation(new HelpLocation(owner.getName(), "record"));
		}
	}

	abstract class AbstractCaptureSelectedMemoryAction extends DockingAction {
		public static final String NAME = "Capture Selected Memory";
		public static final Icon ICON = ICON_CAPTURE_MEMORY;
		public static final String HELP_ANCHOR = "capture_memory";

		public AbstractCaptureSelectedMemoryAction(Plugin owner) {
			super(NAME, owner.getName());
			setDescription("Capture memory for the selected addresses into the trace database");
			setHelpLocation(new HelpLocation(owner.getName(), HELP_ANCHOR));
		}
	}

	interface TrackLocationAction {
		String NAME = "Track Location";
		String DESCRIPTION = "Follow a location in this view";
		String HELP_ANCHOR = "track_location";

		String NAME_PC = "Track Program Counter";
		String NAME_SP = "Track Stack Pointer";
		String NAME_NONE = "Do Not Track";

		// TODO: Separate icons for Program Counter and Stack Pointer
		Icon ICON_PC = ICON_REGISTER_MARKER;
		Icon ICON_SP = ICON_REGISTER_MARKER;
		// TODO: Consider sync_disabled icon
		Icon ICON_NONE = ICON_DELETE;

		static <T> MultiStateActionBuilder<T> builder(Plugin owner) {
			String ownerName = owner.getName();
			return new MultiStateActionBuilder<T>(NAME, ownerName).description(DESCRIPTION)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
		}
	}

	interface GoToAction {
		String NAME = "Go To";
		String DESCRIPTION = "Seek this listing to an arbitrary expression";
		String HELP_ANCHOR = "go_to";

		static ActionBuilder builder(Plugin owner) {
			String ownerName = owner.getName();
			return new ActionBuilder(NAME, ownerName).description(DESCRIPTION)
					.menuPath(NAME)
					.keyBinding(KeyStroke.getKeyStroke(KeyEvent.VK_G, 0))
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
		}
	}

	abstract class AbstractSyncToStaticListingAction extends ToggleDockingAction {
		public static final String NAME = "Sync to Static Listing";
		public static final String HELP_ANCHOR = "sync_static";

		public AbstractSyncToStaticListingAction(Plugin owner) {
			super(NAME, owner.getName());
			setDescription("Synchronize the static listing (and related providers)" +
				" to the dynamic listing (and related providers) where a mapping is" + " known");
			setHelpLocation(new HelpLocation(owner.getName(), HELP_ANCHOR));
		}
	}

	interface ImportMissingModuleAction {
		String NAME = "Import Missing Module";
		String DESCRIPTION = "Import the missing module from disk";
		Icon ICON = ICON_IMPORT;
		String HELP_ANCHOR = "import_missing_module";

		static ActionBuilder builder(Plugin owner) {
			String ownerName = owner.getName();
			return new ActionBuilder(NAME, ownerName)
					.description(DESCRIPTION)
					.toolBarIcon(ICON)
					.popupMenuIcon(ICON)
					.popupMenuPath(NAME)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
		}
	}

	interface MapMissingModuleAction {
		String NAME = "Map Missing Module";
		String DESCRIPTION = "Map the missing module to an existing import";
		Icon ICON = ICON_MAP_MODULES;
		String HELP_ANCHOR = "map_missing_module";

		static ActionBuilder builder(Plugin owner) {
			String ownerName = owner.getName();
			return new ActionBuilder(NAME, ownerName)
					.description(DESCRIPTION)
					.toolBarIcon(ICON)
					.popupMenuIcon(ICON)
					.popupMenuPath(NAME)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
		}
	}

	abstract class AbstractFollowsCurrentThreadAction extends ToggleDockingAction {
		public static final String NAME = "Follows Selected Thread";
		public static final String HELP_ANCHOR = "follows_thread";

		public AbstractFollowsCurrentThreadAction(Plugin owner) {
			super(NAME, owner.getName());
			setDescription("Register tracking follows selected thread (and contents" +
				" follow selected trace)");
			setHelpLocation(new HelpLocation(owner.getName(), HELP_ANCHOR));
		}
	}

	interface AutoReadMemoryAction {
		String NAME = "Auto-Read Target Memory";
		String DESCRIPTION = "Automatically capture visible memory from the live target";
		String HELP_ANCHOR = "auto_memory";

		String NAME_VIS_RO_ONCE = "Read Visible Memory, RO Once";
		String NAME_VISIBLE = "Read Visible Memory";
		String NAME_NONE = "Do Not Read Memory";

		// TODO: Separate icon for each
		Icon ICON_VIS_RO_ONCE = ICON_AUTOREAD;
		Icon ICON_VISIBLE = ICON_AUTOREAD;
		Icon ICON_NONE = ICON_DELETE;

		static <T> MultiStateActionBuilder<T> builder(Plugin owner) {
			String ownerName = owner.getName();
			return new MultiStateActionBuilder<T>(NAME, ownerName).description(DESCRIPTION)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
		}
	}

	abstract class AbstractRefreshAction extends DockingAction {
		public static final String NAME = "Refresh";
		public static final Icon ICON = ICON_REFRESH;

		public AbstractRefreshAction(Plugin owner) {
			super(NAME, owner.getName());
			setDescription("Refresh the view");
			setHelpLocation(new HelpLocation(owner.getName(), "refresh"));
		}
	}

	interface SelectRegistersAction {
		String NAME = "Select Registers";
		String DESCRIPTION = "Select registers to display/modify";
		String GROUP = "aa";
		Icon ICON = ResourceManager.loadImage("images/select-registers.png");
		String HELP_ANCHOR = "select_registers";

		static ActionBuilder builder(Plugin owner) {
			String ownerName = owner.getName();
			return new ActionBuilder(NAME, ownerName).description(DESCRIPTION)
					.toolBarGroup(GROUP)
					.toolBarIcon(ICON)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
		}
	}

	interface CreateSnapshotAction {
		String NAME = "Create Snapshot";
		String DESCRIPTION = "Create a (disconnected) snapshot copy of this window";
		String GROUP = "zzzz";
		Icon ICON = ResourceManager.loadImage("images/camera-photo.png");
		String HELP_ANCHOR = "snapshot_window";

		static ActionBuilder builder(Plugin owner) {
			String ownerName = owner.getName();
			return new ActionBuilder(NAME, ownerName).description(DESCRIPTION)
					.toolBarGroup(GROUP)
					.toolBarIcon(ICON)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
		}
	}

	interface EnableEditsAction {
		String NAME = "Enable Edits";
		String DESCRIPTION = "Enable editing of recorded or live values";
		String GROUP = "yyyy2";
		Icon ICON = ResourceManager.loadImage("images/editbytes.gif");
		String HELP_ANCHOR = "enable_edits";

		static ToggleActionBuilder builder(Plugin owner) {
			String ownerName = owner.getName();
			return new ToggleActionBuilder(NAME, ownerName).description(DESCRIPTION)
					.toolBarGroup(GROUP)
					.toolBarIcon(ICON)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
		}
	}

	interface DisassembleAsAction {
		String NAME = "Disassemble as";
		String DESCRIPTION = "Disassemble using an alternative language";
		Icon ICON = ResourceManager.loadImage("images/disassemble.png");
		String HELP_ANCHOR = "disassemble_as";

		static ActionBuilder builder(Plugin owner) {
			String ownerName = owner.getName();
			return new ActionBuilder(NAME, ownerName).description(DESCRIPTION)
					.menuIcon(ICON)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
		}
	}

	interface AddAction {
		String NAME = "Add";
		String GROUP = "yyyy";
		Icon ICON = ICON_ADD;
		String HELP_ANCHOR = "add";

		static ActionBuilder builder(Plugin owner) {
			String ownerName = owner.getName();
			return new ActionBuilder(NAME, ownerName)
					.toolBarGroup(GROUP)
					.toolBarIcon(ICON)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
		}
	}

	interface RemoveAction {
		String NAME = "Remove";
		String GROUP = "yyyy";
		Icon ICON = ICON_DELETE;
		String HELP_ANCHOR = "remove";

		static ActionBuilder builder(Plugin owner) {
			return builder(owner.getName());
		}

		static ActionBuilder builder(String ownerName) {
			return new ActionBuilder(NAME, ownerName)
					.toolBarGroup(GROUP)
					.toolBarIcon(ICON)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
		}
	}

	interface ClearAction {
		String NAME = "Clear";
		String GROUP = "yyyy";
		Icon ICON = ICON_CLEAR;
		String HELP_ANCHOR = "clear";

		static ActionBuilder builder(Plugin owner) {
			return builder(owner.getName());
		}

		static ActionBuilder builder(String ownerName) {
			return new ActionBuilder(NAME, ownerName)
					.toolBarGroup(GROUP)
					.toolBarIcon(ICON)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
		}
	}

	interface FilterAction {
		String NAME = "Filter";
		String GROUP = "yyyy";
		Icon ICON = ICON_FILTER;

		static ToggleActionBuilder builder(Plugin owner) {
			String ownerName = owner.getName();
			return new ToggleActionBuilder(NAME, ownerName)
					.toolBarGroup(GROUP)
					.toolBarIcon(ICON);
		}
	}

	interface SelectNoneAction {
		String NAME = "Select None";
		String GROUP = "Select";
		String HELP_ANCHOR = "select_none";

		static ActionBuilder builder(Plugin owner) {
			String ownerName = owner.getName();
			return new ActionBuilder(NAME, ownerName)
					.popupMenuGroup(GROUP)
					.popupMenuPath(NAME)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
		}
	}

	interface SelectRowsAction {
		String NAME = "Select Rows";
		Icon ICON = ICON_SELECT_ROWS;
		String GROUP = GROUP_GENERAL;
		String HELP_ANCHOR = "select_rows";

		static ActionBuilder builder(Plugin owner) {
			String ownerName = owner.getName();
			return new ActionBuilder(NAME, ownerName)
					.toolBarGroup(GROUP)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR))
					.toolBarIcon(ICON);
		}
	}

	interface ExportTraceViewAction {
		String NAME = "Export Trace View";
		String DESCRIPTION = "Export the current view as if a Ghidra program";
		String GROUP = GROUP_MAINTENANCE;
		String HELP_ANCHOR = "export_view";

		static ActionBuilder builder(Plugin owner) {
			String ownerName = owner.getName();
			return new ActionBuilder(NAME, ownerName)
					.description(DESCRIPTION)
					.menuGroup(GROUP)
					.menuPath(NAME)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
		}
	}

	interface OpenProgramAction {
		String NAME = "Open Program";
		Icon ICON = ICON_PROGRAM;
		String DESCRIPTION = "Open the program";
		String HELP_ANCHOR = "open_program";

		static ActionBuilder builder(Plugin owner) {
			String ownerName = owner.getName();
			return new ActionBuilder(NAME, ownerName)
					.description(DESCRIPTION)
					.toolBarIcon(ICON)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
		}
	}

	abstract class AbstractToggleBreakpointAction extends DockingAction {
		public static final String NAME = "Toggle Breakpoint";
		// TODO: A "toggle breakpoint" icon
		public static final Icon ICON = ICON_BREAKPOINT_MIXED_ED_MARKER;
		public static final String HELP_ANCHOR = "toggle_breakpoint";

		public AbstractToggleBreakpointAction(Plugin owner) {
			super(NAME, owner.getName());
			setDescription("Set, enable, or disable a breakpoint");
			setHelpLocation(new HelpLocation(owner.getName(), HELP_ANCHOR));
		}
	}

	abstract class AbstractSetBreakpointAction extends DockingAction {
		public static final String NAME = "Set Breakpoint";
		public static final Icon ICON = ICON_SET_BREAKPOINT;
		public static final String HELP_ANCHOR = "set_breakpoint";

		public static void styleButton(JButton button) {
			button.setText(NAME);
			button.setIcon(ICON);
		}

		public static HelpLocation help(Plugin owner) {
			return new HelpLocation(owner.getName(), HELP_ANCHOR);
		}

		public AbstractSetBreakpointAction(Plugin owner) {
			super(NAME, owner.getName());
			setDescription("Trap execution");
			setHelpLocation(help(owner));
		}
	}

	abstract class AbstractEnableBreakpointAction extends DockingAction {
		public static final String NAME = "Enable Breakpoint";
		public static final Icon ICON = ICON_ENABLE_BREAKPOINT;
		public static final String HELP_ANCHOR = "enable_breakpoint";

		public AbstractEnableBreakpointAction(Plugin owner) {
			super(NAME, owner.getName());
			setDescription("Enable this breakpoint");
			// NOTE: Same as disable by listing.
			setHelpLocation(new HelpLocation(owner.getName(), HELP_ANCHOR));
		}
	}

	abstract class AbstractEnableSelectedBreakpointsAction extends DockingAction {
		public static final String NAME = "Enable Breakpoints";
		public static final Icon ICON = ICON_ENABLE_BREAKPOINT;
		public static final String HELP_ANCHOR = "enable_breakpoints";

		public AbstractEnableSelectedBreakpointsAction(Plugin owner) {
			super(NAME, owner.getName());
			setDescription("Enabled the selected breakpoints");
			setHelpLocation(new HelpLocation(owner.getName(), HELP_ANCHOR));
		}
	}

	abstract class AbstractEnableAllBreakpointsAction extends DockingAction {
		public static final String NAME = "Enable All Breakpoints";
		public static final Icon ICON = ICON_ENABLE_ALL_BREAKPOINTS;
		public static final String HELP_ANCHOR = "enable_all_breakpoints";

		public AbstractEnableAllBreakpointsAction(Plugin owner) {
			super(NAME, owner.getName());
			setDescription("Enable all breakpoints in the table");
			setHelpLocation(new HelpLocation(owner.getName(), HELP_ANCHOR));
		}
	}

	abstract class AbstractDisableBreakpointAction extends DockingAction {
		public static final String NAME = "Disable Breakpoint";
		public static final Icon ICON = ICON_DISABLE_BREAKPOINT;
		public static final String HELP_ANCHOR = "disable_breakpoint";

		public AbstractDisableBreakpointAction(Plugin owner) {
			super(NAME, owner.getName());
			setDescription("Disable this breakpoint");
			// NOTE: Same as disable by listing.
			setHelpLocation(new HelpLocation(owner.getName(), HELP_ANCHOR));
		}
	}

	abstract class AbstractDisableSelectedBreakpointsAction extends DockingAction {
		public static final String NAME = "Disable Breakpoints";
		public static final Icon ICON = ICON_DISABLE_BREAKPOINT;
		public static final String HELP_ANCHOR = "disable_breakpoints";

		public AbstractDisableSelectedBreakpointsAction(Plugin owner) {
			super(NAME, owner.getName());
			setDescription("Disable the selected breakpoints");
			// NOTE: Same as disable by listing.
			setHelpLocation(new HelpLocation(owner.getName(), HELP_ANCHOR));
		}
	}

	abstract class AbstractDisableAllBreakpointsAction extends DockingAction {
		public static final String NAME = "Disable All Breakpoints";
		public static final Icon ICON = ICON_DISABLE_ALL_BREAKPOINTS;
		public static final String HELP_ANCHOR = "disable_all_breakpoints";

		public AbstractDisableAllBreakpointsAction(Plugin owner) {
			super(NAME, owner.getName());
			setDescription("Disable all breakpoints in the table");
			// TODO: Should combine help with other disable actions?
			setHelpLocation(new HelpLocation(owner.getName(), HELP_ANCHOR));
		}
	}

	abstract class AbstractClearBreakpointAction extends DockingAction {
		public static final String NAME = "Clear Breakpoint";
		public static final Icon ICON = ICON_CLEAR_BREAKPOINT;
		public static final String HELP_ANCHOR = "clear_breakpoint";

		public AbstractClearBreakpointAction(Plugin owner) {
			super(NAME, owner.getName());
			setDescription("Clear this breakpoint");
			// NOTE: Same as clear by selection.
			setHelpLocation(new HelpLocation(owner.getName(), HELP_ANCHOR));
		}
	}

	abstract class AbstractClearSelectedBreakpointsAction extends DockingAction {
		public static final String NAME = "Clear Breakpoints";
		public static final Icon ICON = ICON_CLEAR_BREAKPOINT;
		public static final String HELP_ANCHOR = "clear_breakpoints";

		public AbstractClearSelectedBreakpointsAction(Plugin owner) {
			super(NAME, owner.getName());
			setDescription("Clear the selected breakpoints");
			// NOTE: Same as clear by listing.
			setHelpLocation(new HelpLocation(owner.getName(), HELP_ANCHOR));
		}
	}

	abstract class AbstractClearAllBreakpointsAction extends DockingAction {
		public static final String NAME = "Clear All Breakpoints";
		public static final Icon ICON = ICON_CLEAR_ALL_BREAKPOINTS;
		public static final String HELP_ANCHOR = "clear_all_breakpoints";

		public AbstractClearAllBreakpointsAction(Plugin owner) {
			super(NAME, owner.getName());
			setDescription("Clear all breakpoints in the table");
			// TODO: Should combine help with other clear actions?
			setHelpLocation(new HelpLocation(owner.getName(), HELP_ANCHOR));
		}
	}

	abstract class AbstractMakeBreakpointsEffectiveAction extends DockingAction {
		public static final String NAME = "Make Breakpoints Effective";
		public static final Icon ICON = ICON_MAKE_BREAKPOINTS_EFFECTIVE;
		public static final String HELP_ANCHOR = "make_breakpoints_effective";

		public AbstractMakeBreakpointsEffectiveAction(Plugin owner) {
			super(NAME, owner.getName());
			setDescription("Place enabled but ineffective breakpoints where possible");
			setHelpLocation(new HelpLocation(owner.getName(), HELP_ANCHOR));
		}
	}

	abstract class AbstractToggleAction extends DockingAction {
		public static final String NAME = "Toggle";
		public static final Icon ICON = ICON_TOGGLE;
		public static final String HELP_ANCHOR = "toggle_option";

		public static HelpLocation help(Plugin owner) {
			return new HelpLocation(owner.getName(), HELP_ANCHOR);
		}

		public AbstractToggleAction(Plugin owner) {
			super(NAME, owner.getName());
			setDescription("Enable or disable an option");
			setHelpLocation(new HelpLocation(owner.getName(), HELP_ANCHOR));
		}
	}

	interface MapIdenticallyAction {
		String NAME = "Map Identically";
		String DESCRIPTION =
			"Map the current trace to the current program using identical addresses";
		Icon ICON = ICON_MAP_IDENTICALLY;
		String GROUP = GROUP_MAPPING;
		String HELP_ANCHOR = "map_identically";

		static ActionBuilder builder(Plugin owner) {
			String ownerName = owner.getName();
			return new ActionBuilder(NAME, ownerName).description(DESCRIPTION)
					.toolBarIcon(ICON)
					.toolBarGroup(GROUP)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
		}
	}

	interface MapModulesAction {
		String NAME = "Map Modules";
		String DESCRIPTION = "Map selected modules to program images";
		Icon ICON = ICON_MAP_MODULES; // TODO: Probably no icon
		String GROUP = GROUP_MAPPING;
		String HELP_ANCHOR = "map_modules";

		static ActionBuilder builder(Plugin owner) {
			String ownerName = owner.getName();
			return new ActionBuilder(NAME, ownerName).description(DESCRIPTION)
					//.toolBarIcon(ICON)
					//.toolBarGroup(GROUP)
					//.popupMenuIcon(ICON)
					.popupMenuPath(NAME)
					.popupMenuGroup(GROUP)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
		}
	}

	interface MapModuleToAction {
		String NAME_PREFIX = "Map Module to ";
		String DESCRIPTION = "Map the selected module to the current program";
		Icon ICON = ICON_MAP_MODULES; // TODO: Probably no icon
		String GROUP = GROUP_MAPPING;
		String HELP_ANCHOR = "map_module_to";

		static ActionBuilder builder(Plugin owner) {
			String ownerName = owner.getName();
			return new ActionBuilder(NAME_PREFIX, ownerName).description(DESCRIPTION)
					.popupMenuPath(NAME_PREFIX + "...")
					.popupMenuGroup(GROUP)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
		}
	}

	interface MapSectionsAction {
		String NAME = "Map Sections";
		String DESCRIPTION = "Map selected sections to program memory blocks";
		Icon ICON = ICON_MAP_SECTIONS; // TODO: Probably no icon
		String GROUP = GROUP_MAPPING;
		String HELP_ANCHOR = "map_sections";

		static ActionBuilder builder(Plugin owner) {
			String ownerName = owner.getName();
			return new ActionBuilder(NAME, ownerName).description(DESCRIPTION)
					//.toolBarIcon(ICON)
					//.toolBarGroup(GROUP)
					//.popupMenuIcon(ICON)
					.popupMenuPath(NAME)
					.popupMenuGroup(GROUP)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
		}
	}

	interface MapSectionToAction {
		String NAME_PREFIX = "Map Section to ";
		String DESCRIPTION = "Map the selected module to the current program";
		Icon ICON = ICON_MAP_SECTIONS; // TODO: Probably no icon
		String GROUP = GROUP_MAPPING;
		String HELP_ANCHOR = "map_section_to";

		static ActionBuilder builder(Plugin owner) {
			String ownerName = owner.getName();
			return new ActionBuilder(NAME_PREFIX, ownerName).description(DESCRIPTION)
					.popupMenuPath(NAME_PREFIX + "...")
					.popupMenuGroup(GROUP)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
		}
	}

	interface MapSectionsToAction {
		String NAME_PREFIX = "Map Sections to ";
		String DESCRIPTION = "Map the selected module sections to the current program";
		Icon ICON = ICON_MAP_SECTIONS;
		String GROUP = GROUP_MAPPING;
		String HELP_ANCHOR = "map_sections_to";

		static ActionBuilder builder(Plugin owner) {
			String ownerName = owner.getName();
			return new ActionBuilder(NAME_PREFIX, ownerName).description(DESCRIPTION)
					.popupMenuPath(NAME_PREFIX + "...")
					.popupMenuGroup(GROUP)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
		}
	}

	/*interface SelectAddressesAction { // TODO: Finish this conversion
		String NAME = "Select Addresses";
		Icon ICON = ICON_SELECT_ADDRESSES;
		String GROUP = GROUP_GENERAL;
		String HELP_ANCHOR = "select_addresses";
	
		static ActionBuilder builder(Plugin owner) {
			String ownerName = owner.getName();
			return new ActionBuilder(NAME, ownerName)
					.toolBarIcon(ICON)
					.toolBarGroup(GROUP)
					.popupMenuPath(NAME)
					.popupMenuIcon(ICON)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
		}
	}*/

	abstract class AbstractSelectAddressesAction extends DockingAction {
		public static final String NAME = "Select Addresses";
		public static final Icon ICON = ICON_SELECT_ADDRESSES;
		public static final String HELP_ANCHOR = "select_addresses";

		public AbstractSelectAddressesAction(Plugin owner) {
			super(NAME, owner.getName());
			setHelpLocation(new HelpLocation(owner.getName(), HELP_ANCHOR));
		}
	}

	abstract class AbstractCaptureTypesAction extends DockingAction {
		public static final String NAME = "Capture Data Types";
		public static final Icon ICON = ICON_DATA_TYPES;
		public static final String HELP_ANCHOR = "capture_types";

		public AbstractCaptureTypesAction(Plugin owner) {
			super(NAME, owner.getName());
			setDescription("Capture data types from selected modules");
			setHelpLocation(new HelpLocation(owner.getName(), HELP_ANCHOR));
		}
	}

	abstract class AbstractCaptureSymbolsAction extends DockingAction {
		public static final String NAME = "Capture Symbols";
		public static final Icon ICON = ICON_CAPTURE_SYMBOLS;
		public static final String HELP_ANCHOR = "capture_symbols";

		public AbstractCaptureSymbolsAction(Plugin owner) {
			super(NAME, owner.getName());
			setDescription("Capture symbols from selected modules");
			setHelpLocation(new HelpLocation(owner.getName(), HELP_ANCHOR));
		}
	}

	abstract class AbstractImportFromFileSystemAction extends DockingAction {
		public static final String NAME = "Import From File System";
		public static final String HELP_ANCHOR = "import_from_fs";

		public AbstractImportFromFileSystemAction(Plugin owner) {
			super(NAME, owner.getName());
			setDescription("Import and map the selected module by path from the local file system");
			setHelpLocation(new HelpLocation(owner.getName(), HELP_ANCHOR));
		}
	}

	abstract class AbstractNewListingAction extends DockingAction {
		public static final String NAME = "New Dynamic Listing";
		public static final Icon ICON = ICON_LISTING;
		public static final String HELP_ANCHOR = "new_listing";

		public AbstractNewListingAction(Plugin owner) {
			super(NAME, owner.getName());
			setDescription("Open a new dynamic disassembly listing");
			setHelpLocation(new HelpLocation(owner.getName(), HELP_ANCHOR));
		}
	}

	abstract class AbstractStepSnapForwardAction extends DockingAction {
		public static final String NAME = "Step Trace Snap Forward";
		public static final Icon ICON = ICON_SNAP_FORWARD;
		public static final String HELP_ANCHOR = "step_trace_snap_forward";

		public AbstractStepSnapForwardAction(Plugin owner) {
			super(NAME, owner.getName());
			setDescription("Navigate the recording forward one snap");
			setHelpLocation(new HelpLocation(owner.getName(), HELP_ANCHOR));
		}
	}

	abstract class AbstractStepTickForwardAction extends DockingAction {
		public static final String NAME = "Step Trace Tick Forward";
		public static final Icon ICON = ICON_STEP_INTO;
		public static final String HELP_ANCHOR = "step_trace_tick_forward";

		public AbstractStepTickForwardAction(Plugin owner) {
			super(NAME, owner.getName());
			setDescription("Navigate the recording forward one tick");
			setHelpLocation(new HelpLocation(owner.getName(), HELP_ANCHOR));
		}
	}

	interface StepPcodeForwardAction {
		String NAME = "Step Trace p-code Forward";
		String DESCRIPTION = "Navigate the recording forward one p-code tick";
		Icon ICON = ICON_STEP_INTO;
		String GROUP = GROUP_CONTROL;
		String HELP_ANCHOR = "step_trace_pcode_forward";

		static ActionBuilder builder(Plugin owner) {
			String ownerName = owner.getName();
			return new ActionBuilder(NAME, ownerName)
					.description(DESCRIPTION)
					.toolBarIcon(ICON)
					.toolBarGroup(GROUP)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
		}
	}

	abstract class AbstractStepTickBackwardAction extends DockingAction {
		public static final String NAME = "Step Trace Tick Backward";
		public static final Icon ICON = ICON_STEP_BACK;
		public static final String HELP_ANCHOR = "step_trace_tick_backward";

		public AbstractStepTickBackwardAction(Plugin owner) {
			super(NAME, owner.getName());
			setDescription("Navigate the recording backward one tick");
			setHelpLocation(new HelpLocation(owner.getName(), HELP_ANCHOR));
		}
	}

	abstract class AbstractStepSnapBackwardAction extends DockingAction {
		public static final String NAME = "Step Trace Snap Backward";
		public static final Icon ICON = ICON_SNAP_BACKWARD;
		public static final String HELP_ANCHOR = "step_trace_snap_backward";

		public AbstractStepSnapBackwardAction(Plugin owner) {
			super(NAME, owner.getName());
			setDescription("Navigate the recording backward one snap");
			setHelpLocation(new HelpLocation(owner.getName(), HELP_ANCHOR));
		}
	}

	interface StepPcodeBackwardAction {
		String NAME = "Step Trace p-code Backward";
		String DESCRIPTION = "Navigate the recording backward one p-code tick";
		Icon ICON = ICON_STEP_BACK;
		String GROUP = GROUP_CONTROL;
		String HELP_ANCHOR = "step_trace_pcode_backward";

		static ActionBuilder builder(Plugin owner) {
			String ownerName = owner.getName();
			return new ActionBuilder(NAME, ownerName)
					.description(DESCRIPTION)
					.toolBarIcon(ICON)
					.toolBarGroup(GROUP)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
		}
	}

	abstract class AbstractSeekTracePresentAction extends ToggleDockingAction {
		public static final String NAME = "Seek Trace Present";
		public static final Icon ICON = ICON_SEEK_PRESENT;
		public static final String HELP_ANCHOR = "seek_trace_present";

		public AbstractSeekTracePresentAction(Plugin owner) {
			super(NAME, owner.getName());
			setDescription("Track the tool to the latest snap");
			setHelpLocation(new HelpLocation(owner.getName(), HELP_ANCHOR));
		}
	}

	interface SynchronizeFocusAction {
		String NAME = "Synchronize Focus";
		String DESCRIPTION = "Synchronize trace activation with debugger focus/select";
		String GROUP = "zz";
		Icon ICON = ICON_SYNC;
		String HELP_ANCHOR = "sync_focus";

		static ToggleActionBuilder builder(Plugin owner) {
			String ownerName = owner.getName();
			return new ToggleActionBuilder(NAME, ownerName).description(DESCRIPTION)
					.toolBarGroup(GROUP)
					.toolBarIcon(ICON)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
		}
	}

	interface SaveByDefaultAction {
		String NAME = "Save Traces By Default";
		String DESCRIPTION = "Automatically save traces to the project";
		String GROUP = GROUP_TRACE_TOGGLES;
		Icon ICON = ICON_SAVE;
		String HELP_ANCHOR = "save_by_default";

		static ToggleActionBuilder builder(Plugin owner) {
			String ownerName = owner.getName();
			return new ToggleActionBuilder(NAME, ownerName)
					.description(DESCRIPTION)
					.menuPath(DebuggerPluginPackage.NAME, NAME)
					.menuGroup(GROUP)
					.menuIcon(ICON)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
		}
	}

	interface CloseOnTerminateAction {
		String NAME = "Close Traces Upon Termination";
		String DESCRIPTION = "Close any live trace whose recording terminates";
		String GROUP = GROUP_TRACE_TOGGLES;
		Icon ICON = ICON_CLOSE;
		String HELP_ANCHOR = "auto_close_terminated";

		static ToggleActionBuilder builder(Plugin owner) {
			String ownerName = owner.getName();
			return new ToggleActionBuilder(NAME, ownerName)
					.description(DESCRIPTION)
					.menuPath(DebuggerPluginPackage.NAME, NAME)
					.menuGroup(GROUP)
					.menuIcon(ICON)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
		}
	}

	interface OpenTraceAction {
		String NAME = "Open Trace";
		String DESCRIPTION = "Open a trace from the project";
		String GROUP = GROUP_TRACE;
		Icon ICON = ICON_TRACE;
		String HELP_ANCHOR = "open_trace";

		static ActionBuilder builder(Plugin owner) {
			String ownerName = owner.getName();
			return new ActionBuilder(NAME, ownerName)
					.description(DESCRIPTION)
					.menuGroup(GROUP)
					.menuIcon(ICON)
					.menuPath(DebuggerPluginPackage.NAME, NAME)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));

		}
	}

	interface CloseTraceAction {
		String NAME_PREFIX = "Close ";
		String DESCRIPTION = "Close the current trace";
		String GROUP = GROUP_TRACE_CLOSE;
		Icon ICON = ICON_CLOSE;
		String HELP_ANCHOR = "close_trace";

		static ActionBuilder builder(Plugin owner) {
			String ownerName = owner.getName();
			return new ActionBuilder(NAME_PREFIX, ownerName)
					.description(DESCRIPTION)
					.menuGroup(GROUP)
					.menuIcon(ICON)
					.menuPath(DebuggerPluginPackage.NAME, NAME_PREFIX + "...")
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));

		}
	}

	interface CloseAllTracesAction extends CloseTraceAction {
		String NAME = NAME_PREFIX + " All Traces";
		String DESCRIPTION = "Close all traces";
		String HELP_ANCHOR = "close_all_traces";

		static ActionBuilder builder(Plugin owner) {
			String ownerName = owner.getName();
			return new ActionBuilder(NAME, ownerName)
					.description(DESCRIPTION)
					.menuGroup(GROUP)
					.menuIcon(ICON)
					.menuPath(DebuggerPluginPackage.NAME, NAME)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
		}
	}

	interface CloseOtherTracesAction extends CloseTraceAction {
		String NAME = NAME_PREFIX + " Other Traces";
		String DESCRIPTION = "Close all traces except the current one";
		String HELP_ANCHOR = "close_other_traces";

		static ActionBuilder builder(Plugin owner) {
			String ownerName = owner.getName();
			return new ActionBuilder(NAME, ownerName)
					.description(DESCRIPTION)
					.menuGroup(GROUP)
					.menuIcon(ICON)
					.menuPath(DebuggerPluginPackage.NAME, NAME)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
		}
	}

	interface CloseDeadTracesAction extends CloseTraceAction {
		String NAME = NAME_PREFIX + " Dead Traces";
		String DESCRIPTION = "Close all traces not being recorded";
		String HELP_ANCHOR = "close_dead_traces";

		static ActionBuilder builder(Plugin owner) {
			String ownerName = owner.getName();
			return new ActionBuilder(NAME, ownerName)
					.description(DESCRIPTION)
					.menuGroup(GROUP)
					.menuIcon(ICON)
					.menuPath(DebuggerPluginPackage.NAME, NAME)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
		}
	}

	interface ApplyDataTypeAction {
		String NAME = "Apply Data to Listing ";
		String DESCRIPTION =
			"Apply the selected data type at the address of this value in the listing";
		String GROUP = GROUP_GENERAL;
		Icon ICON = ICON_DATA_TYPES;
		String HELP_ANCHOR = "apply_data_type";

		static ActionBuilder builder(Plugin owner) {
			String ownerName = owner.getName();
			return new ActionBuilder(NAME, ownerName)
					.description(DESCRIPTION)
					.toolBarGroup(GROUP)
					.toolBarIcon(ICON)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
		}
	}

	interface SelectWatchRangeAction {
		String NAME = "Select Range";
		String DESCRIPTION = "For memory watches, select the range comprising the value";
		String GROUP = GROUP_GENERAL;
		Icon ICON = ICON_SELECT_ADDRESSES;
		String HELP_ANCHOR = "select_addresses";

		static ActionBuilder builder(Plugin owner) {
			String ownerName = owner.getName();
			return new ActionBuilder(NAME, ownerName)
					.description(DESCRIPTION)
					.toolBarGroup(GROUP)
					.toolBarIcon(ICON)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
		}
	}

	interface SelectWatchReadsAction {
		String NAME = "Select Reads";
		String DESCRIPTION = "Select every memory range read evaluating this watch";
		String GROUP = GROUP_GENERAL;
		Icon ICON = ICON_REGIONS; // TODO: Meh. Better icon.
		String HELP_ANCHOR = "select_reads";

		static ActionBuilder builder(Plugin owner) {
			String ownerName = owner.getName();
			return new ActionBuilder(NAME, ownerName)
					.description(DESCRIPTION)
					.toolBarGroup(GROUP)
					.toolBarIcon(ICON)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
		}
	}

	interface HideScratchSnapshotsAction {
		String NAME = "Hide Scratch";
		String DESCRIPTION = "Hide negative snaps, typically used as emulation scratch space";
		String GROUP = GROUP_GENERAL;
		String HELP_ANCHOR = "hide_scratch";

		static ToggleActionBuilder builder(Plugin owner) {
			String ownerName = owner.getName();
			return new ToggleActionBuilder(NAME, ownerName)
					.description(DESCRIPTION)
					.menuGroup(GROUP_GENERAL)
					.menuPath(NAME)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
		}
	}

	public abstract class AbstractDebuggerConnectionsNode extends GTreeNode {
		@Override
		public String getName() {
			return "Connections";
		}

		@Override
		public Icon getIcon(boolean expanded) {
			return ICON_DEBUGGER; // Hidden anyway
		}

		@Override
		public String getToolTip() {
			return "Established debugger connections";
		}
	}

	public abstract class AbstractDebuggerModelNode extends GTreeNode {
		@Override
		public Icon getIcon(boolean expanded) {
			return ICON_CONNECTION;
		}

		@Override
		public String getToolTip() {
			return "A connected debugger client";
		}
	}

	static <T> Function<Throwable, T> showError(Component parent, String message) {
		return e -> {
			Throwable t = AsyncUtils.unwrapThrowable(e);
			if (t instanceof CancelledException || t instanceof CancellationException) {
				Msg.error(parent, "Cancelled: " + message);
			}
			else {
				Msg.showError(parent, parent, DebuggerPluginPackage.NAME, message, e);
			}
			return null;
		};
	}

	static <V, R> void setSelectedRows(Set<V> sel, Function<V, R> rowMapper, GTable table,
			RowObjectTableModel<R> model, GTableFilterPanel<R> filterPanel) {
		table.clearSelection();
		for (V v : sel) {
			R row = rowMapper.apply(v);
			if (row == null) {
				continue;
			}
			int modelRow = model.getRowIndex(row);
			int viewRow = filterPanel.getViewRow(modelRow);
			table.getSelectionModel().addSelectionInterval(viewRow, viewRow);
		}
		table.scrollToSelectedRow();
	}

	static <V, R> void setSelectedRows(Set<V> sel, Function<R, V> getter, GTable table,
			GTableFilterPanel<R> filterPanel) {
		List<R> data = filterPanel.getTableFilterModel().getModelData();
		for (int i = 0; i < data.size(); i++) {
			if (sel.contains(getter.apply(data.get(i)))) {
				table.getSelectionModel().addSelectionInterval(i, i);
			}
		}
		table.scrollToSelectedRow();
	}

	public static class ToToggleSelectionListener implements BooleanChangeAdapter {
		private final ToggleDockingAction action;

		public ToToggleSelectionListener(ToggleDockingAction action) {
			this.action = action;
		}

		@Override
		public void changed(Boolean value) {
			if (action.isSelected() == value) {
				return;
			}
			action.setSelected(value);
		}
	}

}
