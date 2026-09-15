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
package ghidra.features.codecompare.functiongraph.actions;

import java.util.ArrayList;
import java.util.List;

import docking.ActionContext;
import docking.action.*;
import docking.widgets.dialogs.ObjectChooserDialog;
import ghidra.app.plugin.core.functiongraph.graph.layout.FGLayoutProvider;
import ghidra.app.plugin.core.functiongraph.mvc.FGController;
import ghidra.app.plugin.core.functiongraph.mvc.FgEnv;
import ghidra.features.codecompare.functiongraph.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.HelpLocation;
import ghidra.util.datastruct.Duo;
import ghidra.util.datastruct.Duo.Side;

public class FgRelayoutAction extends DockingAction {

	private FunctionGraphCodeComparisonView fgProvider;

	public FgRelayoutAction(FunctionGraphCodeComparisonView fgProvider) {
		super("Relayout Graph", fgProvider.getOwner(), KeyBindingType.SHARED);
		this.fgProvider = fgProvider;

		setPopupMenuData(new MenuData(new String[] { "Relayout Graph" }));

		setHelpLocation(new HelpLocation("FunctionGraphPlugin", "Function_Graph_Action_Layout"));
	}

	@Override
	public void actionPerformed(ActionContext context) {

		Duo<FgDisplay> displays = fgProvider.getDisplays();
		FgDisplay leftDisplay = displays.get(Side.LEFT);
		FGController leftController = leftDisplay.getController();
		FgEnv env = leftController.getEnv();
		List<FGLayoutProvider> layoutProviders = new ArrayList<>(env.getLayoutProviders());
		ObjectChooserDialog<FGLayoutProvider> dialog =
			new ObjectChooserDialog<>("Choose Layout", FGLayoutProvider.class, layoutProviders,
				"getLayoutName");
		FGLayoutProvider currentLayout = leftController.getLayoutProvider();
		dialog.setSelectedObject(currentLayout);
		PluginTool tool = env.getTool();
		tool.showDialog(dialog);

		FGLayoutProvider layoutProvider = dialog.getSelectedObject();
		if (layoutProvider == null) {
			return; // cancelled
		}
		leftController.changeLayout(layoutProvider);

		FgDisplay rightDisplay = displays.get(Side.RIGHT);
		FGController rightController = rightDisplay.getController();
		rightController.changeLayout(layoutProvider);

		fgProvider.stateChanged();
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		return context instanceof FgComparisonContext;
	}
}
