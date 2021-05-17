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
package ghidra.app.services;

import javax.swing.Icon;

import docking.ActionContext;
import docking.action.DockingActionIf;
import ghidra.app.plugin.core.debug.gui.console.DebuggerConsolePlugin;
import ghidra.dbg.DebuggerConsoleLogger;
import ghidra.framework.plugintool.ServiceInfo;
import ghidra.util.HTMLUtilities;

@ServiceInfo(defaultProvider = DebuggerConsolePlugin.class)
public interface DebuggerConsoleService extends DebuggerConsoleLogger {

	/**
	 * Log a message to the console
	 * 
	 * <p>
	 * <b>WARNING:</b> See {@link #log(Icon, String, ActionContext)} regarding HTML.
	 * 
	 * @param icon an icon for the message
	 * @param message the HTML-formatted message
	 */
	void log(Icon icon, String message);

	/**
	 * Log an actionable message to the console
	 * 
	 * <p>
	 * <b>WARNING:</b> The log accepts and will interpret HTML in its messages, allowing a rich and
	 * flexible display; however, you MUST sanitize any content derived from the user or target. We
	 * recommend using {@link HTMLUtilities#escapeHTML(String)}.
	 * 
	 * @param icon an icon for the message
	 * @param message the HTML-formatted message
	 * @param context an (immutable) context for actions
	 */
	void log(Icon icon, String message, ActionContext context);

	/**
	 * Remove an actionable message from the console
	 * 
	 * <p>
	 * It is common courtesy to remove the entry when the user has resolved the issue, whether via
	 * the presented actions, or some other means. The framework does not do this automatically,
	 * because simply activating an action does not imply the issue will be resolved.
	 * 
	 * @param context the context of the entry to remove
	 */
	void removeFromLog(ActionContext context);

	/**
	 * Check if the console contains an actionable message for the given context
	 * 
	 * @param context the context to check for
	 * @return true if present, false if absent
	 */
	boolean logContains(ActionContext context);

	/**
	 * Add an action which might be applied to an actionable log message
	 * 
	 * <p>
	 * Please invoke this method from the Swing thread. Only toolbar and pop-up menu placement is
	 * considered. Toolbar actions are placed as icon-only buttons in the "Actions" column for any
	 * log message where the action is applicable to the context given for that message. Pop-up
	 * actions are placed in the context menu when a single message is selected and the action is
	 * applicable to its given context. In most cases, the action should be presented both as a
	 * button and as a pop-up menu. Less commonly, an action may be presented only as a pop-up,
	 * likely because it is an uncommon resolution, or because you don't want the user to activated
	 * it accidentally. Rarely, if ever, should an action be a button, but not in the menu. The user
	 * may expect the menu to give more complete descriptions of actions presented as buttons.
	 * 
	 * <p>
	 * <b>IMPORTANT:</b> Unlike other action managers, you are required to remove your actions upon
	 * plugin disposal.
	 * 
	 * @param action the action
	 */
	void addResolutionAction(DockingActionIf action);

	/**
	 * Remove an action
	 * 
	 * <p>
	 * Please invoke this method from the Swing thread.
	 * 
	 * @param action the action
	 */
	void removeResolutionAction(DockingActionIf action);
}
