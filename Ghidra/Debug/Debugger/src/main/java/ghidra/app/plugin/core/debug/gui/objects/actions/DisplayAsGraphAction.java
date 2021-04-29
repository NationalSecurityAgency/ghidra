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
package ghidra.app.plugin.core.debug.gui.objects.actions;

import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.util.*;

import javax.swing.ImageIcon;

import docking.action.KeyBindingData;
import docking.action.MenuData;
import ghidra.app.plugin.core.debug.gui.objects.DebuggerObjectsProvider;
import ghidra.app.plugin.core.debug.gui.objects.ObjectContainer;
import ghidra.app.services.GraphDisplayBroker;
import ghidra.framework.plugintool.PluginTool;
import ghidra.service.graph.*;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.GraphException;
import ghidra.util.task.TaskMonitor;
import resources.ResourceManager;

public class DisplayAsGraphAction extends DisplayAsAction {

	protected GraphDisplayBroker graphBroker;

	protected static ImageIcon ICON_GRAPH = ResourceManager.loadImage("images/breakpoints.png");

	public DisplayAsGraphAction(PluginTool tool, String owner, DebuggerObjectsProvider provider) {
		super("DisplayGraph", tool, owner, provider);
		String[] path = new String[] { "Display as...", "Graph" };
		setPopupMenuData(new MenuData(path, ICON_GRAPH));
		setKeyBindingData(new KeyBindingData(KeyEvent.VK_G, InputEvent.CTRL_DOWN_MASK));
		setHelpLocation(new HelpLocation(owner, "display_as_graph"));
		provider.addLocalAction(this);
	}

	@Override
	protected void doAction(ObjectContainer container) {
		graphBroker = provider.getGraphBroker();
		if (graphBroker == null) {
			Msg.showError(this, tool.getToolFrame(), "DisplayAsGraph Error",
				"GraphBroker not found: Please add a graph provider to your tool");
			return;
		}
		addGraph(container);
	}

	public void addGraph(ObjectContainer container) {
		GraphDisplayProvider graphProvider = graphBroker.getDefaultGraphDisplayProvider();
		AttributedGraph graph = new AttributedGraph();
		AttributedVertex start = graph.addVertex(container.toString(), container.getName());
		graphContainer(container, graph, start);
		try {
			GraphDisplay graphDisplay = graphProvider.getGraphDisplay(true, TaskMonitor.DUMMY);
			graphDisplay.setGraph(graph, container.getName(), false, TaskMonitor.DUMMY);
		}
		catch (GraphException e) {
			e.printStackTrace();
		}
		catch (CancelledException e) {
			//DO NOTHING
		}
	}

	private void graphContainer(ObjectContainer container, AttributedGraph graph,
			AttributedVertex start) {
		Map<ObjectContainer, AttributedVertex> starts = new HashMap<>();
		Set<ObjectContainer> children = container.getCurrentChildren();
		for (ObjectContainer c : children) {
			if (!c.isVisible()) {
				continue;
			}
			AttributedVertex end = graph.addVertex(c.toString(), c.getName());
			graph.addEdge(start, end, start + ":" + end);
			starts.put(c, end);
		}
		for (ObjectContainer c : starts.keySet()) {
			AttributedVertex s = starts.get(c);
			graphContainer(c, graph, s);
		}
	}

}
