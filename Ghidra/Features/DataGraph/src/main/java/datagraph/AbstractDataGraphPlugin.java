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
package datagraph;

import java.util.HashSet;
import java.util.Set;

import docking.action.builder.ActionBuilder;
import ghidra.app.context.ListingActionContext;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Data;
import ghidra.program.util.ProgramLocation;
import ghidra.util.HelpLocation;

/**
 * Base class for plugins that show a graph of data from program.
 */

public abstract class AbstractDataGraphPlugin extends ProgramPlugin {
	private Set<DataGraphProvider> activeProviders = new HashSet<>();

	public AbstractDataGraphPlugin(PluginTool plugintool) {
		super(plugintool);
		createActions();
	}

	public void goTo(ProgramLocation location) {
		activeProviders.forEach(p -> p.goTo(location));
	}

	private void createActions() {

		new ActionBuilder("Display Data Graph", getName())
				.popupMenuPath("Data", "Display Data Graph")
				.keyBinding("ctrl G")
				.helpLocation(new HelpLocation("DataGraphPlugin", "Data_Graph"))
				.withContext(ListingActionContext.class)
				.enabledWhen(this::isGraphActionEnabled)
				.onAction(this::showDataGraph)
				.buildAndInstall(tool);
	}

	protected boolean isGraphActionEnabled(ListingActionContext context) {
		return context.getCodeUnit() instanceof Data;
	}

	private void showDataGraph(ListingActionContext context) {
		Data data = (Data) context.getCodeUnit();
		// the data from the context may be an internal sub-data, we want the outermost data.
		data = getTopLevelData(data);
		DataGraphProvider provider = new DataGraphProvider(this, data);
		activeProviders.add(provider);
		tool.showComponentProvider(provider, true);
	}

	private Data getTopLevelData(Data data) {
		Data parent = data.getParent();
		while (parent != null) {
			data = parent;
			parent = data.getParent();
		}
		return data;
	}

	void removeProvider(DataGraphProvider provider) {
		activeProviders.remove(provider);
	}

	public abstract void fireLocationEvent(ProgramLocation location);
}
