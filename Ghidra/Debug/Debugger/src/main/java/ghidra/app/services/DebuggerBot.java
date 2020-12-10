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

import ghidra.app.plugin.core.debug.service.workflow.DebuggerWorkflowServicePlugin;
import ghidra.dbg.DebuggerObjectModel;
import ghidra.framework.options.AutoOptions;
import ghidra.framework.plugintool.PluginTool;
import ghidra.lifecycle.Internal;
import ghidra.program.model.listing.Program;
import ghidra.trace.model.Trace;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.classfinder.ExtensionPoint;
import ghidra.util.datastruct.CollectionChangeListener;

/**
 * A bot (or analyzer) that aids the user in the debugging workflow
 * 
 * <p>
 * These are a sort of miniature front-end plugin (TODO: consider tool-only bots) with a number of
 * conveniences allowing the specification of automatic actions taken under given circumstances,
 * e.g., "Open the interpreter for new debugger connections." Such actions may include analysis of
 * open traces, e.g., "Disassemble memory at the Program Counter."
 * 
 * <p>
 * Bots which react to target state changes should take care to act quickly in most, if not all,
 * circumstances. Otherwise, the UI could become sluggish. It is vitally important that the UI not
 * become sluggish when the user is stepping a target. Bots should also be wary of prompts. If too
 * many bots are prompting the user for input, they may collectively become a source of extreme
 * annoyance. In most cases, the bot should use its best judgment and just perform the action, so
 * long as it's not potentially destructive. That way, the user can undo the action and/or disable
 * the bot. For cases where the bot, in its best judgment, cannot make a decision, it's probably
 * best to simply log an informational message and do nothing. There are exceptions, just consider
 * them carefully, and be mindful of prompting the user unexpectedly or incessantly.
 */
public interface DebuggerBot extends ExtensionPoint {

	/**
	 * Log a missing-info-annotation error
	 * 
	 * @param cls the bot's class missing the annotation
	 * @param methodName the name of the method requesting the info
	 */
	@Internal
	static void noAnnot(Class<?> cls, String methodName) {
		Msg.error(DebuggerBot.class, "Debugger bot " + cls + " must apply @" +
			DebuggerBotInfo.class.getSimpleName() + " or override getDescription()");
	}

	/**
	 * Utility for obtaining and bot's info annotation
	 * 
	 * <p>
	 * If the annotation is not present, an error is logged for the developer's sake.
	 * 
	 * @param cls the bot's class
	 * @param methodName the name of the method requesting the info, for error-reporting purposes
	 * @return the annotation, or {@code null}
	 */
	@Internal
	static DebuggerBotInfo getInfo(Class<?> cls, String methodName) {
		DebuggerBotInfo info = cls.getAnnotation(DebuggerBotInfo.class);
		if (info == null) {
			noAnnot(cls, methodName);
		}
		return info;
	}

	/**
	 * Get a description of the bot
	 * 
	 * @see DebuggerBotInfo#description()
	 * @return the description
	 */
	default String getDescription() {
		DebuggerBotInfo info = getInfo(getClass(), "getDescription");
		if (info == null) {
			return "<NO DESCRIPTION>";
		}
		return info.description();
	}

	/**
	 * Get a detailed description of the bot
	 * 
	 * @see DebuggerBotInfo#details()
	 * @return the details
	 */
	default String getDetails() {
		DebuggerBotInfo info = getInfo(getClass(), "getDetails");
		if (info == null) {
			return "";
		}
		return info.details();
	}

	/**
	 * Get the help location for information about the bot
	 * 
	 * @see DebuggerBotInfo#help()
	 * @return the help location
	 */
	default HelpLocation getHelpLocation() {
		DebuggerBotInfo info = getInfo(getClass(), "getHelpLocation");
		if (info == null) {
			return null;
		}
		return AutoOptions.getHelpLocation("DebuggerBots", info.help());
	}

	/**
	 * Check whether this bot is enabled by default
	 * 
	 * <p>
	 * Assuming the user has never configured this bot before, determine whether it should be
	 * enabled.
	 * 
	 * @return true if enabled by default, false otherwise
	 */
	default boolean isEnabledByDefault() {
		DebuggerBotInfo info = getInfo(getClass(), "isEnabledByDefault");
		if (info == null) {
			return false;
		}
		return info.enabledByDefault();
	}

	/**
	 * Check if this bot is enabled
	 * 
	 * @return true if enabled, false otherwise
	 */
	boolean isEnabled();

	/**
	 * Enable or disable the bot
	 * 
	 * <p>
	 * If {@link #isEnabled()} is already equal to the given -enabled- value, this method has no
	 * effect.
	 * 
	 * @param plugin the front-end plugin, required if -enabled- is set
	 * @param enabled true to enable, false to disable
	 */
	default void setEnabled(DebuggerWorkflowServicePlugin plugin, boolean enabled) {
		if (isEnabled() == enabled) {
			return;
		}
		if (enabled) {
			enable(plugin);
		}
		else {
			disable();
		}
	}

	/**
	 * Enable and initialize the bot
	 * 
	 * @param plugin the front-end plugin
	 */
	void enable(DebuggerWorkflowServicePlugin plugin);

	/**
	 * Disable and dispose the bot
	 * 
	 * <p>
	 * Note the bot must be prepared to be enabled again. In other words, it will not be
	 * re-instantiated. It should return to the same state after construction but before being
	 * enabled the first time.
	 */
	void disable();

	/**
	 * A model has been added to the model service
	 * 
	 * @see DebuggerModelService#addModelsChangedListener(CollectionChangeListener)
	 * @param model the new model
	 */
	default void modelAdded(DebuggerObjectModel model) {
	}

	/**
	 * A model has been removed from the model service
	 * 
	 * @see DebuggerModelService#addModelsChangedListener(CollectionChangeListener)
	 * @param model the removed model
	 */
	default void modelRemoved(DebuggerObjectModel model) {
	}

	/**
	 * A program has been opened in a tool
	 * 
	 * @param tool the tool which opened the program
	 * @param program the program that was opened
	 */
	default void programOpened(PluginTool tool, Program program) {
	}

	/**
	 * A program has been closed in a tool
	 * 
	 * @param tool the tool which closed the program
	 * @param program the program that was closed
	 */
	default void programClosed(PluginTool tool, Program program) {
	}

	/**
	 * A trace has been opened in a tool
	 * 
	 * @param tool the tool which opened the trace
	 * @param trace the trace that was opened
	 */
	default void traceOpened(PluginTool tool, Trace trace) {
	}

	/**
	 * A trace has been closed in a tool
	 * 
	 * @param tool the tool which closed the trace
	 * @param trace the trace that was closed
	 */
	default void traceClosed(PluginTool tool, Trace trace) {
	}
}
