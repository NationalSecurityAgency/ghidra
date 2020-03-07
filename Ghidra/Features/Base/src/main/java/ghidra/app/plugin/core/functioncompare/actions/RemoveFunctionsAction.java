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
package ghidra.app.plugin.core.functioncompare.actions;

import java.awt.Component;
import java.awt.event.InputEvent;
import java.util.Arrays;
import java.util.HashSet;

import javax.swing.Icon;
import javax.swing.JComboBox;

import docking.ActionContext;
import docking.action.*;
import ghidra.app.plugin.core.functioncompare.MultiFunctionComparisonPanel;
import ghidra.app.plugin.core.functioncompare.MultiFunctionComparisonProvider;
import ghidra.program.model.listing.Function;
import ghidra.util.HelpLocation;
import resources.MultiIcon;
import resources.ResourceManager;
import resources.icons.TranslateIcon;

/**
 * Removes the currently-selected function from the comparison panel. If no 
 * functions are enabled, the action will be disabled.
 */
public class RemoveFunctionsAction extends DockingAction {

	private static final Icon FUNCTION_ICON =
		new TranslateIcon(ResourceManager.loadImage("images/FunctionScope.gif"), -5, -2);
	private static final Icon REMOVE_ICON =
		new TranslateIcon(ResourceManager.loadImage("images/edit-delete.png"), 3, 3);
	private static final String REMOVE_FUNCTION_GROUP = "A9_RemoveFunctions";
	private static final Icon REMOVE_FUNCTION_ICON = new MultiIcon(REMOVE_ICON, FUNCTION_ICON);

	/**
	 * Constructor
	 * 
	 * @param provider the function comparison provider
	 */
	public RemoveFunctionsAction(MultiFunctionComparisonProvider provider) {
		super("Remove Functions", provider.getOwner());

		setKeyBindingData(
			new KeyBindingData('R', InputEvent.CTRL_DOWN_MASK | InputEvent.SHIFT_DOWN_MASK));
		setDescription("Removes function in the focused comparison panel");
		setPopupMenuData(new MenuData(new String[] { "Remove Function" },
			REMOVE_FUNCTION_ICON, REMOVE_FUNCTION_GROUP));

		ToolBarData newToolBarData =
			new ToolBarData(REMOVE_FUNCTION_ICON, REMOVE_FUNCTION_GROUP);
		setToolBarData(newToolBarData);

		HelpLocation helpLocation =
			new HelpLocation(MultiFunctionComparisonPanel.HELP_TOPIC, "Remove_From_Comparison");
		setHelpLocation(helpLocation);
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		if (!(context.getComponentProvider() instanceof MultiFunctionComparisonProvider)) {
			return false;
		}
		MultiFunctionComparisonProvider provider =
			(MultiFunctionComparisonProvider) context.getComponentProvider();

		Component comp = provider.getComponent();
		if (!(comp instanceof MultiFunctionComparisonPanel)) {
			return false;
		}
		MultiFunctionComparisonPanel panel = (MultiFunctionComparisonPanel) comp;
		JComboBox<Function> focusedComponent = panel.getFocusedComponent();

		return focusedComponent.getSelectedIndex() != -1;
	}

	@Override
	public void actionPerformed(ActionContext context) {
		MultiFunctionComparisonProvider provider =
			(MultiFunctionComparisonProvider) context.getComponentProvider();
		JComboBox<Function> focusedComponent =
			((MultiFunctionComparisonPanel) provider.getComponent()).getFocusedComponent();
		Function selectedFunction = (Function) focusedComponent.getSelectedItem();
		provider.removeFunctions(new HashSet<>(Arrays.asList(selectedFunction)));
		provider.contextChanged();
	}
}
