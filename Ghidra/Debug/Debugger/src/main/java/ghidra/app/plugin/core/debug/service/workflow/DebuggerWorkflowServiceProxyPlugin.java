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
package ghidra.app.plugin.core.debug.service.workflow;

import java.util.Set;

import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.core.debug.DebuggerPluginPackage;
import ghidra.app.services.DebuggerBot;
import ghidra.app.services.DebuggerWorkflowService;
import ghidra.framework.main.AppInfo;
import ghidra.framework.main.FrontEndTool;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.*;

@PluginInfo( //
		shortDescription = "Debugger workflow service (proxy to front-end)", //
		description = "Manage automatic debugging actions and analysis", //
		category = PluginCategoryNames.DEBUGGER, //
		packageName = DebuggerPluginPackage.NAME, //
		status = PluginStatus.RELEASED, //
		servicesProvided = { //
			DebuggerWorkflowService.class, //
		} //
)
public class DebuggerWorkflowServiceProxyPlugin extends Plugin implements DebuggerWorkflowService {

	protected static DebuggerWorkflowServicePlugin getOrCreateFrontEndDelegate() {
		FrontEndTool frontEnd = AppInfo.getFrontEndTool();
		for (Plugin plugin : frontEnd.getManagedPlugins()) {
			if (plugin instanceof DebuggerWorkflowServicePlugin) {
				return (DebuggerWorkflowServicePlugin) plugin;
			}
		}
		try {
			DebuggerWorkflowServicePlugin plugin =
				PluginUtils.instantiatePlugin(DebuggerWorkflowServicePlugin.class, frontEnd);
			frontEnd.addPlugin(plugin);
			return plugin;
		}
		catch (PluginException e) {
			throw new AssertionError(e);
		}
	}

	protected DebuggerWorkflowServicePlugin delegate;

	public DebuggerWorkflowServiceProxyPlugin(PluginTool tool) {
		super(tool);
	}

	@Override
	protected void init() {
		super.init();
		delegate = getOrCreateFrontEndDelegate();
		// TODO: Proxy listeners
		delegate.pluginToolAdded(tool);
	}

	@Override
	protected void dispose() {
		super.dispose();
		if (delegate != null) {
			// TODO: Proxy listeners
			delegate.pluginToolRemoved(tool);
		}
	}

	@Override
	public Set<DebuggerBot> getAllBots() {
		return delegate.getAllBots();
	}

	@Override
	public Set<DebuggerBot> getEnabledBots() {
		return delegate.getEnabledBots();
	}

	@Override
	public Set<DebuggerBot> getDisabledBots() {
		return delegate.getDisabledBots();
	}

	@Override
	public void enableBots(Set<DebuggerBot> actors) {
		delegate.enableBots(actors);
	}

	@Override
	public void disableBots(Set<DebuggerBot> actors) {
		delegate.disableBots(actors);
	}
}
