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
 */
public record ActionName(String name) {
	public static final ActionName REFRESH = new ActionName("refresh");
	/**
	 * Activate a given object and optionally a time
	 * 
	 * <p>
	 * Forms: (focus:Object), (focus:Object, snap:LONG), (focus:Object, time:STR)
	 */
	public static final ActionName ACTIVATE = new ActionName("activate");
	/**
	 * A weaker form of activate.
	 * 
	 * <p>
	 * The user has expressed interest in an object, but has not activated it yet. This is often
	 * used to communicate selection (i.e., highlight) of the object. Whereas, double-clicking or
	 * pressing enter would more likely invoke 'activate.'
	 */
	public static final ActionName FOCUS = new ActionName("focus");
	public static final ActionName TOGGLE = new ActionName("toggle");
	public static final ActionName DELETE = new ActionName("delete");

	/**
	 * Execute a CLI command
	 * 
	 * <p>
	 * Forms: (cmd:STRING):STRING; Optional arguments: capture:BOOL
	 */
	public static final ActionName EXECUTE = new ActionName("execute");

	/**
	 * Connect the back-end to a (usually remote) target
	 * 
	 * <p>
	 * Forms: (spec:STRING)
	 */
	public static final ActionName CONNECT = new ActionName("connect");

	/**
	 * Forms: (target:Attachable), (pid:INT), (spec:STRING)
	 */
	public static final ActionName ATTACH = new ActionName("attach");
	public static final ActionName DETACH = new ActionName("detach");

	/**
	 * Forms: (command_line:STRING), (file:STRING,args:STRING), (file:STRING,args:STRING_ARRAY),
	 * (ANY*)
	 */
	public static final ActionName LAUNCH = new ActionName("launch");
	public static final ActionName KILL = new ActionName("kill");

	public static final ActionName RESUME = new ActionName("resume");
	public static final ActionName INTERRUPT = new ActionName("interrupt");

	/**
	 * All of these will show in the "step" portion of the control toolbar, if present. The
	 * difference in each "step_x" is minor. The icon will indicate which form, and the positions
	 * will be shifted so they appear in a consistent order. The display name is determined by the
	 * method name, not the action name. For stepping actions that don't fit the standards, use
	 * {@link #STEP_EXT}. There should be at most one of each standard applicable for any given
	 * context. (Multiple will appear, but may confuse the user.) You can have as many extended step
	 * actions as you like. They will be ordered lexicographically by name.
	 */
	public static final ActionName STEP_INTO = new ActionName("step_into");
	public static final ActionName STEP_OVER = new ActionName("step_over");
	public static final ActionName STEP_OUT = new ActionName("step_out");
	/**
	 * Skip is not typically available, except in emulators. If the back-end debugger does not have
	 * a command for this action out-of-the-box, we do not recommend trying to implement it
	 * yourself. The purpose of these actions just to expose/map each command to the UI, not to
	 * invent new features for the back-end debugger.
	 */
	public static final ActionName STEP_SKIP = new ActionName("step_skip");
	/**
	 * Step back is not typically available, except in emulators and timeless (or time-travel)
	 * debuggers.
	 */
	public static final ActionName STEP_BACK = new ActionName("step_back");
	/**
	 * The action for steps that don't fit one of the common stepping actions.
	 */
	public static final ActionName STEP_EXT = new ActionName("step_ext");

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
	public static final ActionName BREAK_SW_EXECUTE = new ActionName("break_sw_execute");
	public static final ActionName BREAK_HW_EXECUTE = new ActionName("break_hw_execute");
	public static final ActionName BREAK_READ = new ActionName("break_read");
	public static final ActionName BREAK_WRITE = new ActionName("break_write");
	public static final ActionName BREAK_ACCESS = new ActionName("break_access");
	public static final ActionName BREAK_EXT = new ActionName("break_ext");

	/**
	 * Forms: (rng:RANGE)
	 */
	public static final ActionName READ_MEM = new ActionName("read_mem");
	/**
	 * Forms: (addr:ADDRESS,data:BYTES)
	 */
	public static final ActionName WRITE_MEM = new ActionName("write_mem");

	// NOTE: no read_reg. Use refresh(RegContainer), refresh(RegGroup), refresh(Register)
	/**
	 * Forms: (frame:Frame,name:STRING,value:BYTES), (register:Register,value:BYTES)
	 */
	public static final ActionName WRITE_REG = new ActionName("write_reg");
}
