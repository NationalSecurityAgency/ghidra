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

import java.awt.Dimension;
import java.awt.event.MouseEvent;

import javax.swing.Icon;
import javax.swing.JComponent;

import docking.*;
import ghidra.app.plugin.core.functiongraph.mvc.FGController;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.util.HelpLocation;
import resources.ResourceManager;

public class FGSatelliteUndockedProvider extends ComponentProviderAdapter {

	static final String NAME = "Function Graph Satellite";
	private static final Icon ICON = ResourceManager.loadImage("images/network-wireless-16.png");

	private FGController controller;
	private JComponent satelliteComponent;

	public FGSatelliteUndockedProvider(FunctionGraphPlugin plugin, FGController controller,
			JComponent satelliteComponent) {
		super(plugin.getTool(), NAME, plugin.getName());
		this.controller = controller;
		this.satelliteComponent = satelliteComponent;
		satelliteComponent.setMinimumSize(new Dimension(400, 400));

		setHelpLocation(new HelpLocation("FunctionGraphPlugin", "Satellite_View_Dock"));

		setIcon(ICON);
		setDefaultWindowPosition(WindowPosition.WINDOW);
		setWindowMenuGroup(FunctionGraphPlugin.FUNCTION_GRAPH_NAME);

		addToTool();
	}

	@Override
	public ActionContext getActionContext(MouseEvent event) {
		ComponentProvider primaryProvider = controller.getProvider();
		return primaryProvider.getActionContext(event);
	}

	@Override
	public JComponent getComponent() {
		return satelliteComponent;
	}

	@Override
	public void componentShown() {
		controller.satelliteProviderShown();
	}
}
