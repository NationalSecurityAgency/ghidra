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
package ghidra.app.plugin.core.debug.gui.console;

import javax.swing.Icon;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.Logger;
import org.apache.logging.log4j.core.appender.AbstractAppender;
import org.apache.logging.log4j.core.config.Property;
import org.apache.logging.log4j.core.filter.LevelRangeFilter;

import docking.ActionContext;
import docking.action.DockingActionIf;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.core.debug.DebuggerPluginPackage;
import ghidra.app.plugin.core.debug.gui.console.DebuggerConsoleProvider.LogRow;
import ghidra.app.services.DebuggerConsoleService;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;

@PluginInfo(
	shortDescription = "Debugger console panel plugin",
	description = "A tool-global console for controlling a debug/trace session",
	category = PluginCategoryNames.DEBUGGER,
	packageName = DebuggerPluginPackage.NAME,
	status = PluginStatus.RELEASED,
	servicesRequired = {},
	servicesProvided = {
		DebuggerConsoleService.class,
	})
public class DebuggerConsolePlugin extends Plugin implements DebuggerConsoleService {
	protected static final String APPENDER_NAME = "debuggerAppender";

	protected class ConsolePluginAppender extends AbstractAppender {

		public ConsolePluginAppender() {
			super(APPENDER_NAME, null, null, true, Property.EMPTY_ARRAY);

			addFilter(LevelRangeFilter.createFilter(Level.FATAL, Level.INFO, null, null));
		}

		@Override
		public void append(LogEvent event) {
			String loggerName = event.getLoggerName();
			if (loggerName.contains(".debug") ||
				loggerName.contains(".dbg.") ||
				loggerName.contains("agent.")) {
				provider.logEvent(event);
			}
		}
	}

	protected DebuggerConsoleProvider provider;

	protected final ConsolePluginAppender appender;

	protected Logger rootLogger;

	public DebuggerConsolePlugin(PluginTool tool) {
		super(tool);

		appender = new ConsolePluginAppender();
	}

	@Override
	protected void init() {
		super.init();
		provider = new DebuggerConsoleProvider(this);

		rootLogger = (Logger) LogManager.getRootLogger();
		appender.start();
		rootLogger.addAppender(appender);
	}

	@Override
	protected void dispose() {
		if (rootLogger != null) {
			rootLogger.removeAppender(appender);
			appender.stop();

			provider.dispose();
			tool.removeComponentProvider(provider);
		}
		super.dispose();
	}

	@Override
	public void log(Icon icon, String message) {
		provider.log(icon, message);
	}

	@Override
	public void log(Icon icon, String message, ActionContext context) {
		provider.log(icon, message, context);
	}

	@Override
	public void removeFromLog(ActionContext context) {
		provider.removeFromLog(context);
	}

	@Override
	public boolean logContains(ActionContext context) {
		return provider.logContains(context);
	}

	@Override
	public void addResolutionAction(DockingActionIf action) {
		provider.addResolutionAction(action);
	}

	@Override
	public void removeResolutionAction(DockingActionIf action) {
		provider.removeResolutionAction(action);
	}

	/**
	 * For testing: get the number of rows having a given class of action context
	 * 
	 * @param ctxCls the context class
	 */
	public long getRowCount(Class<? extends ActionContext> ctxCls) {
		return provider.getRowCount(ctxCls);
	}

	/**
	 * For testing: to verify the contents of a message delivered to the console log
	 * 
	 * @param ctx the context
	 * @return the the log entry
	 */
	public LogRow getLogRow(ActionContext ctx) {
		return provider.getLogRow(ctx);
	}
}
