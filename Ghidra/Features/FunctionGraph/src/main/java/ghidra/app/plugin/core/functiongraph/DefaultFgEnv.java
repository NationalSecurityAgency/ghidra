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
package ghidra.app.plugin.core.functiongraph;

import java.util.List;
import java.util.Objects;

import docking.action.DockingAction;
import ghidra.app.nav.Navigatable;
import ghidra.app.plugin.core.functiongraph.graph.layout.FGLayoutProvider;
import ghidra.app.plugin.core.functiongraph.mvc.*;
import ghidra.app.util.viewer.format.FormatManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;

public class DefaultFgEnv implements FgEnv {

	private FGProvider provider;
	private FunctionGraphPlugin plugin;

	public DefaultFgEnv(FGProvider provider, FunctionGraphPlugin plugin) {
		this.provider = Objects.requireNonNull(provider);
		this.plugin = Objects.requireNonNull(plugin);
	}

	@Override
	public PluginTool getTool() {
		return plugin.getTool();
	}

	@Override
	public Program getProgram() {
		return provider.getProgram();
	}

	@Override
	public FunctionGraphOptions getOptions() {
		return plugin.getFunctionGraphOptions();
	}

	@Override
	public FGColorProvider getColorProvider() {
		return plugin.getColorProvider();
	}

	@Override
	public List<FGLayoutProvider> getLayoutProviders() {
		return plugin.getLayoutProviders();
	}

	@Override
	public void addLocalAction(DockingAction action) {
		provider.addLocalAction(action);
	}

	@Override
	public FormatManager getUserDefinedFormat() {
		return plugin.getUserDefinedFormat();
	}

	@Override
	public void setUserDefinedFormat(FormatManager format) {
		plugin.setUserDefinedFormat(format);
	}

	@Override
	public Navigatable getNavigatable() {
		return provider;
	}

	@Override
	public ProgramLocation getToolLocation() {
		return plugin.getProgramLocation();
	}

	@Override
	public void setSelection(ProgramSelection selection) {
		// 
		// The connected provider will synchronize the tool selection with its selection.  
		// Non-connected providers will ignore selection updates, since users have made a snapshot
		// that should no longer respond to selection changes from the tool.  We still want actions
		// that manipulate selection the graph to work for snapshots.  To do this, we can call the
		// controller directly (which is what the connected provider does).
		//
		if (provider.isConnected()) {
			provider.setSelection(selection);
		}
		else {
			FGController controller = provider.getController();
			controller.setSelection(selection);
		}
	}

	@Override
	public ProgramLocation getGraphLocation() {
		return provider.getLocation();
	}
}
