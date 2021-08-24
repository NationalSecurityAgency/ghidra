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
package ghidra.app.plugin.core.graph;

import java.util.*;

import docking.ActionContext;
import docking.action.MenuData;
import docking.action.ToggleDockingAction;
import docking.tool.ToolConstants;
import ghidra.app.CorePluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.services.GraphDisplayBroker;
import ghidra.framework.options.*;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.service.graph.*;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.exception.GraphException;
import ghidra.util.task.TaskMonitor;

//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.GRAPH,
	shortDescription = "Manages the active Graph Display Service",
	description = "This plugin searches for available graph display providers and if it finds more" +
		"than one, it provides menu options for the user to choose the active provider.",
	servicesProvided = { GraphDisplayBroker.class }
)
//@formatter:on
public class GraphDisplayBrokerPlugin extends Plugin
		implements GraphDisplayBroker, OptionsChangeListener {
	private static final String ACTIVE_GRAPH_PROVIDER = "ACTIVE_GRAPH_PROVIDER";
	private List<GraphDisplayProvider> graphDisplayProviders = new ArrayList<>();
	private GraphDisplayProvider defaultGraphDisplayProvider;
	private List<GraphDisplayBrokerListener> listeners = new ArrayList<>();
	private List<GraphSelectionAction> actions = new ArrayList<>();
	private List<AttributedGraphExporter> exporters;

	public GraphDisplayBrokerPlugin(PluginTool tool) {
		super(tool);
		loadServices();
		buildActions();
	}

	@Override
	public void writeConfigState(SaveState saveState) {
		if (defaultGraphDisplayProvider != null) {
			saveState.putString(ACTIVE_GRAPH_PROVIDER, defaultGraphDisplayProvider.getName());
		}
	}

	@Override
	public void readConfigState(SaveState saveState) {
		String active = saveState.getString(ACTIVE_GRAPH_PROVIDER, null);
		if (active != null) {
			for (GraphDisplayProvider provider : graphDisplayProviders) {
				if (provider.getName().equals(active)) {
					setDefaultGraphDisplayProvider(provider);
					return;
				}
			}
		}
	}

	private void loadServices() {
		Set<GraphDisplayProvider> instances =
			new HashSet<>(ClassSearcher.getInstances(GraphDisplayProvider.class));
		graphDisplayProviders = new ArrayList<>(instances);
		Collections.sort(graphDisplayProviders, (s1, s2) -> s1.getName().compareTo(s2.getName()));
		initializeServices();
		if (!graphDisplayProviders.isEmpty()) {
			defaultGraphDisplayProvider = graphDisplayProviders.get(0);
		}
	}

	private void initializeServices() {
		for (GraphDisplayProvider service : graphDisplayProviders) {
			ToolOptions options = tool.getOptions(ToolConstants.GRAPH_OPTIONS);
			options.addOptionsChangeListener(this);
			service.initialize(tool, options);
		}
	}

	private void buildActions() {
		if (graphDisplayProviders.size() <= 1) {
			return;
		}
		for (GraphDisplayProvider graphDisplayProvider : graphDisplayProviders) {
			createAction(graphDisplayProvider);
		}
		updateActions();
	}

	private void createAction(GraphDisplayProvider provider) {
		GraphSelectionAction action = new GraphSelectionAction(getName(), provider);
		actions.add(action);
		tool.addAction(action);
	}

	private void updateActions() {
		for (GraphSelectionAction action : actions) {
			action.setSelected(defaultGraphDisplayProvider == action.provider);
		}
	}

	protected void notifyListeners() {
		for (GraphDisplayBrokerListener listener : listeners) {
			listener.providersChanged();
		}
	}

	@Override
	public GraphDisplayProvider getDefaultGraphDisplayProvider() {
		return defaultGraphDisplayProvider;
	}

	@Override
	public void addGraphDisplayBrokerListener(GraphDisplayBrokerListener listener) {
		listeners.add(listener);
	}

	@Override
	public void removeGraphDisplayBrokerLisetener(GraphDisplayBrokerListener listener) {
		listeners.remove(listener);
	}

	@Override
	public void dispose() {
		for (GraphDisplayProvider graphService : graphDisplayProviders) {
			graphService.dispose();
		}
	}

	@Override
	public GraphDisplay getDefaultGraphDisplay(boolean reuseGraph, TaskMonitor monitor)
			throws GraphException {
		if (defaultGraphDisplayProvider != null) {
			return defaultGraphDisplayProvider.getGraphDisplay(reuseGraph, monitor);
		}
		return null;
	}

	public void setDefaultGraphDisplayProvider(GraphDisplayProvider provider) {
		defaultGraphDisplayProvider = provider;
		notifyListeners();
		updateActions();
	}

	@Override
	public boolean hasDefaultGraphDisplayProvider() {
		return !graphDisplayProviders.isEmpty();
	}

	/**
	 * Action for selecting a {@link GraphDisplayProvider} to be the currently active provider
	 */
	private class GraphSelectionAction extends ToggleDockingAction {

		private GraphDisplayProvider provider;

		public GraphSelectionAction(String owner, GraphDisplayProvider provider) {
			super(provider.getName(), owner);
			this.provider = provider;
			setMenuBarData(
				new MenuData(
					new String[] { ToolConstants.MENU_GRAPH, "Graph Output", provider.getName() },
					"z"));
			setHelpLocation(provider.getHelpLocation());
		}

		@Override
		public void actionPerformed(ActionContext context) {
			setDefaultGraphDisplayProvider(provider);
		}
	}

	@Override
	public void optionsChanged(ToolOptions options, String optionName, Object oldValue,
			Object newValue) {

		for (GraphDisplayProvider graphService : graphDisplayProviders) {
			graphService.optionsChanged(options);
		}
	}

	@Override
	public GraphDisplayProvider getGraphDisplayProvider(String providerName) {
		for (GraphDisplayProvider provider : graphDisplayProviders) {
			if (provider.getName().equals(providerName)) {
				return provider;
			}
		}
		return null;
	}

	@Override
	public List<AttributedGraphExporter> getGraphExporters() {
		if (exporters == null) {
			exporters = ClassSearcher.getInstances(AttributedGraphExporter.class);
		}
		return Collections.unmodifiableList(exporters);
	}

	@Override
	public AttributedGraphExporter getGraphExporters(String exporterName) {
		List<AttributedGraphExporter> graphExporters = getGraphExporters();
		for (AttributedGraphExporter exporter : graphExporters) {
			if (exporter.getName().equals(exporterName)) {
				return exporter;
			}
		}
		return null;
	}

}
