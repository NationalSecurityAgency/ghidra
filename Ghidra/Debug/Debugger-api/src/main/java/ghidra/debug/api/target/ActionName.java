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
package ghidra.debug.api.target;

import java.awt.event.InputEvent;
import java.util.*;

import javax.swing.Icon;

import docking.ActionContext;
import generic.theme.GIcon;
import ghidra.app.context.ProgramLocationActionContext;
import ghidra.trace.model.TraceExecutionState;
import ghidra.trace.model.target.TraceObject;

/**
 * A name for a commonly-recognized target action.
 * 
 * <p>
 * Many common commands/actions have varying names across different back-end debuggers. We'd like to
 * present common idioms for these common actions, but allow them to keep the names used by the
 * back-end, because those names are probably better known to users of that back-end than Ghidra's
 * action names are known. The action hints will affect the icon and placement of the action in the
 * UI, but the display name will still reflect the name given by the back-end. Note that the "stock"
 * action names are not a fixed enumeration. These are just the ones that might get special
 * treatment from Ghidra. All methods should appear somewhere (at least, e.g., in context menus for
 * applicable objects), even if the action name is unspecified or does not match a stock name. This
 * list may change over time, but that shouldn't matter much. Each back-end should make its best
 * effort to match its methods to these stock actions where applicable, but ultimately, it is up to
 * the UI to decide what is presented where.
 * 
 * @param name the name of the action (given as the action attribute on method annotations)
 * @param show when to show the general UI action for this debugger action
 * @param enabler determines when the action is enabled, based on the object
 * @param display the default text to display
 * @param icon the default icon for menus and dialogs
 * @param okText the default text for confirm buttons in dialogs
 */
public record ActionName(String name, Show show, Enabler enabler, String display, Icon icon,
		String okText) {

	private static final Icon ICON_ATTACH = new GIcon("icon.debugger.attach");
	private static final Icon ICON_CONNECT = new GIcon("icon.debugger.connect");
	private static final Icon ICON_DETACH = new GIcon("icon.debugger.detach");
	private static final Icon ICON_INTERRUPT = new GIcon("icon.debugger.interrupt");
	private static final Icon ICON_KILL = new GIcon("icon.debugger.kill");
	private static final Icon ICON_LAUNCH = new GIcon("icon.debugger.launch");
	private static final Icon ICON_REFRESH = new GIcon("icon.debugger.refresh");
	private static final Icon ICON_RESUME = new GIcon("icon.debugger.resume");
	private static final Icon ICON_STEP_BACK = new GIcon("icon.debugger.step.back");
	private static final Icon ICON_STEP_INTO = new GIcon("icon.debugger.step.into");
	private static final Icon ICON_STEP_LAST = new GIcon("icon.debugger.step.last");
	private static final Icon ICON_STEP_OUT = new GIcon("icon.debugger.step.finish");
	private static final Icon ICON_STEP_OVER = new GIcon("icon.debugger.step.over");
	private static final Icon ICON_SKIP_OVER = new GIcon("icon.debugger.skip.over");
	private static final Icon ICON_SET_BREAKPOINT = new GIcon("icon.debugger.breakpoint.set");

	private static final Map<String, ActionName> NAMES = new HashMap<>();

	/**
	 * Specifies when an action should appear in the menus. For diagnostics, a user may override
	 * this by holding SHIFT when right-clicking, causing all applicable general actions to appear.
	 */
	public enum Show {
		/**
		 * Don't show general actions. The tool has built-in actions that already know how to invoke
		 * this.
		 */
		BUILTIN {
			@Override
			boolean doIsShowing(ActionContext context) {
				return false;
			}
		},
		/**
		 * Only show general actions in address-based context, e.g., when right-clicking in the
		 * listing.
		 */
		ADDRESS {
			@Override
			boolean doIsShowing(ActionContext context) {
				return context instanceof ProgramLocationActionContext;
			}
		},
		/**
		 * Show in all contexts. This is the default.
		 */
		EXTENDED {
			@Override
			boolean doIsShowing(ActionContext context) {
				return true;
			}
		};

		public boolean isShowing(ActionContext context) {
			if (isOverriden(context)) {
				return true;
			}
			return doIsShowing(context);
		}

		abstract boolean doIsShowing(ActionContext context);

		private boolean isOverriden(ActionContext context) {
			return (context.getEventClickModifiers() & InputEvent.SHIFT_DOWN_MASK) != 0;
		}
	}

	public enum Enabler {
		ALWAYS {
			@Override
			public boolean isEnabled(TraceObject obj, long snap) {
				return true;
			}
		},
		NOT_RUNNING {
			@Override
			boolean doIsEnabled(TraceExecutionState state) {
				return state != null && state != TraceExecutionState.RUNNING;
			}
		},
		NOT_STOPPED {
			@Override
			boolean doIsEnabled(TraceExecutionState state) {
				return state != TraceExecutionState.STOPPED;
			}
		},
		NOT_DEAD {
			@Override
			boolean doIsEnabled(TraceExecutionState state) {
				return state != TraceExecutionState.TERMINATED;
			}
		};

		private TraceExecutionState getState(TraceObject obj, long snap) {
			try {
				return obj.getExecutionState(snap);
			}
			catch (NoSuchElementException e) {
				return TraceExecutionState.TERMINATED;
			}
		}

		boolean doIsEnabled(TraceExecutionState state) {
			return true;
		}

		public boolean isEnabled(TraceObject obj, long snap) {
			return doIsEnabled(getState(obj, snap));
		}
	}

	public static ActionName name(String name) {
		synchronized (NAMES) {
			return NAMES.computeIfAbsent(name,
				n -> new ActionName(n, Show.EXTENDED, Enabler.ALWAYS, n, null, "OK"));
		}
	}

	private static ActionName create(String name, Show show, Enabler enabler, String display,
			Icon icon, String okText) {
		synchronized (NAMES) {
			ActionName action = new ActionName(name, show, enabler, display, icon, okText);
			if (NAMES.put(name, action) != null) {
				throw new AssertionError();
			}
			return action;
		}
	}

	public static final ActionName REFRESH =
		create("refresh", Show.EXTENDED, Enabler.ALWAYS, "Refresh", ICON_REFRESH, "Refresh");

	/**
	 * Activate a given object and optionally a time
	 * 
	 * <p>
	 * Forms: (focus:Object), (focus:Object, snap:LONG), (focus:Object, time:STR)
	 */
	public static final ActionName ACTIVATE =
		create("activate", Show.BUILTIN, Enabler.ALWAYS, "Activate", null, "Activate");

	/**
	 * A weaker form of activate.
	 * 
	 * <p>
	 * The user has expressed interest in an object, but has not activated it yet. This is often
	 * used to communicate selection (i.e., highlight) of the object. Whereas, double-clicking or
	 * pressing enter would more likely invoke 'activate.'
	 */
	public static final ActionName FOCUS =
		create("focus", Show.BUILTIN, Enabler.ALWAYS, "Focus", null, "Focus");
	public static final ActionName TOGGLE =
		create("toggle", Show.BUILTIN, Enabler.ALWAYS, "Toggle", null, "Toggle");
	public static final ActionName DELETE =
		create("delete", Show.BUILTIN, Enabler.ALWAYS, "Delete", null, "Delete");

	/**
	 * Execute a CLI command
	 * 
	 * <p>
	 * Forms: (cmd:STRING):STRING; Optional arguments: capture:BOOL
	 */
	public static final ActionName EXECUTE =
		create("execute", Show.BUILTIN, Enabler.ALWAYS, "Execute", null, "Execute");

	/**
	 * Connect the back-end to a (usually remote) target
	 * 
	 * <p>
	 * Forms: (spec:STRING)
	 */
	public static final ActionName CONNECT =
		create("connect", Show.EXTENDED, Enabler.ALWAYS, "Connect", ICON_CONNECT, "Connect");

	/**
	 * Forms: (target:Attachable), (pid:INT), (spec:STRING)
	 */
	public static final ActionName ATTACH =
		create("attach", Show.EXTENDED, Enabler.ALWAYS, "Attach", ICON_ATTACH, "Attach");
	public static final ActionName DETACH =
		create("detach", Show.EXTENDED, Enabler.ALWAYS, "Detach", ICON_DETACH, "Detach");

	/**
	 * Forms: (command_line:STRING), (file:STRING,args:STRING), (file:STRING,args:STRING_ARRAY),
	 * (ANY*)
	 */
	public static final ActionName LAUNCH =
		create("launch", Show.EXTENDED, Enabler.ALWAYS, "Launch", ICON_LAUNCH, "Launch");
	public static final ActionName KILL =
		create("kill", Show.BUILTIN, Enabler.NOT_DEAD, "Kill", ICON_KILL, "Kill");

	public static final ActionName RESUME =
		create("resume", Show.BUILTIN, Enabler.NOT_RUNNING, "Resume", ICON_RESUME, "Resume");
	public static final ActionName INTERRUPT =
		create("interrupt", Show.BUILTIN, Enabler.NOT_STOPPED, "Interrupt", ICON_INTERRUPT,
			"Interrupt");

	/**
	 * All of these will show in the "step" portion of the control toolbar, if present. The
	 * difference in each "step_x" is minor. The icon will indicate which form, and the positions
	 * will be shifted so they appear in a consistent order. The display name is determined by the
	 * method name, not the action name. For stepping actions that don't fit the standards, use
	 * {@link #STEP_EXT}. There should be at most one of each standard applicable for any given
	 * context. (Multiple will appear, but may confuse the user.) You can have as many extended step
	 * actions as you like. They will be ordered lexicographically by name.
	 */
	public static final ActionName STEP_INTO =
		create("step_into", Show.BUILTIN, Enabler.NOT_RUNNING, "Step Into", ICON_STEP_INTO, "Step");
	public static final ActionName STEP_OVER =
		create("step_over", Show.BUILTIN, Enabler.NOT_RUNNING, "Step Over", ICON_STEP_OVER, "Step");
	public static final ActionName STEP_OUT =
		create("step_out", Show.BUILTIN, Enabler.NOT_RUNNING, "Step Out", ICON_STEP_OUT, "Step");

	/**
	 * Skip is not typically available, except in emulators. If the back-end debugger does not have
	 * a command for this action out-of-the-box, we do not recommend trying to implement it
	 * yourself. The purpose of these actions just to expose/map each command to the UI, not to
	 * invent new features for the back-end debugger.
	 */
	public static final ActionName STEP_SKIP =
		create("step_skip", Show.BUILTIN, Enabler.NOT_RUNNING, "Skip Over", ICON_SKIP_OVER, "Skip");

	/**
	 * Step back is not typically available, except in emulators and timeless (or time-travel)
	 * debuggers.
	 */
	public static final ActionName STEP_BACK =
		create("step_back", Show.BUILTIN, Enabler.NOT_RUNNING, "Step Back", ICON_STEP_BACK, "Back");

	/**
	 * The action for steps that don't fit one of the common stepping actions.
	 */
	public static final ActionName STEP_EXT =
		create("step_ext", Show.ADDRESS, Enabler.NOT_RUNNING, null, ICON_STEP_LAST, "Step");

	/**
	 * Forms: (addr:ADDRESS), R/W(rng:RANGE), (expr:STRING)
	 * 
	 * <p>
	 * Optional arguments: condition:STRING, commands:STRING
	 * 
	 * <p>
	 * The client may pass either null or "" for condition and/or commands to indicate omissions of
	 * those arguments.
	 */
	public static final ActionName BREAK_SW_EXECUTE =
		create("break_sw_execute", Show.BUILTIN, Enabler.ALWAYS, "Set Software Breakpoint",
			ICON_SET_BREAKPOINT, "Set");
	public static final ActionName BREAK_HW_EXECUTE =
		create("break_hw_execute", Show.BUILTIN, Enabler.ALWAYS, "Set Hardware Breakpoint",
			ICON_SET_BREAKPOINT, "Set");
	public static final ActionName BREAK_READ =
		create("break_read", Show.BUILTIN, Enabler.ALWAYS, "Set Read Breakpoint",
			ICON_SET_BREAKPOINT, "Set");
	public static final ActionName BREAK_WRITE =
		create("break_write", Show.BUILTIN, Enabler.ALWAYS, "Set Write Breakpoint",
			ICON_SET_BREAKPOINT, "Set");
	public static final ActionName BREAK_ACCESS =
		create("break_access", Show.BUILTIN, Enabler.ALWAYS, "Set Access Breakpont",
			ICON_SET_BREAKPOINT, "Set");
	public static final ActionName BREAK_EXT =
		create("break_ext", Show.BUILTIN, Enabler.ALWAYS, null, ICON_SET_BREAKPOINT, "Set");

	/**
	 * Forms: (rng:RANGE)
	 */
	public static final ActionName READ_MEM =
		create("read_mem", Show.BUILTIN, Enabler.ALWAYS, "Read Memory", null, "Read");

	/**
	 * Forms: (addr:ADDRESS,data:BYTES)
	 */
	public static final ActionName WRITE_MEM =
		create("write_mem", Show.BUILTIN, Enabler.ALWAYS, "Write Memory", null, "Write");

	// NOTE: no read_reg. Use refresh(RegContainer), refresh(RegGroup), refresh(Register)
	/**
	 * Forms: (frame:Frame,name:STRING,value:BYTES), (register:Register,value:BYTES)
	 */
	public static final ActionName WRITE_REG =
		create("write_reg", Show.BUILTIN, Enabler.NOT_RUNNING, "Write Register", null, "Write");
}
