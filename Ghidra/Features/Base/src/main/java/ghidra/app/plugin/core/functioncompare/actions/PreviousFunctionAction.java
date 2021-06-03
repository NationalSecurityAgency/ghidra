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

import javax.swing.Icon;
import javax.swing.JComboBox;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.*;
import ghidra.app.plugin.core.functioncompare.MultiFunctionComparisonPanel;
import ghidra.app.plugin.core.functioncompare.MultiFunctionComparisonProvider;
import ghidra.program.model.listing.Function;
import ghidra.util.HelpLocation;
import resources.MultiIcon;
import resources.ResourceManager;
import resources.icons.TranslateIcon;

/**
 * Displays the previous function in the function comparison panel. If 
 * already at the beginning of the list, the action will not be enabled.
 */
public class PreviousFunctionAction extends DockingAction {

	private static final String FUNCTION_NAVIGATE_GROUP = "A9_FunctionNavigate";
	private static final Icon PREVIOUS_ICON =
		new TranslateIcon(ResourceManager.loadImage("images/arrow_up.png"), 3, 1);
	private static final Icon FUNCTION_ICON =
		new TranslateIcon(ResourceManager.loadImage("images/FunctionScope.gif"), -5, -2);
	private static final Icon PREVIOUS_FUNCTION_ICON = new MultiIcon(PREVIOUS_ICON, FUNCTION_ICON);

	/**
	 * Constructor
	 * 
	 * @param provider the function comparison provider
	 */
	public PreviousFunctionAction(MultiFunctionComparisonProvider provider) {
		super("Compare Previous Function", provider.getOwner());

		setKeyBindingData(
			new KeyBindingData('P', InputEvent.CTRL_DOWN_MASK | InputEvent.SHIFT_DOWN_MASK));
		setDescription("Compare the previous function for the side with focus.");
		setPopupMenuData(new MenuData(new String[] { "Compare The Previous Function" },
			PREVIOUS_FUNCTION_ICON, FUNCTION_NAVIGATE_GROUP));

		ToolBarData newToolBarData =
			new ToolBarData(PREVIOUS_FUNCTION_ICON, FUNCTION_NAVIGATE_GROUP);
		setToolBarData(newToolBarData);

		HelpLocation helpLocation =
			new HelpLocation(MultiFunctionComparisonPanel.HELP_TOPIC,
				"Navigate Previous");
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
		return focusedComponent.getSelectedIndex() > 0;
	}

	@Override
	public void actionPerformed(ActionContext context) {
		ComponentProvider provider = context.getComponentProvider();
		MultiFunctionComparisonPanel panel = (MultiFunctionComparisonPanel) provider.getComponent();
		JComboBox<Function> focusedComponent = panel.getFocusedComponent();
		focusedComponent.setSelectedIndex(focusedComponent.getSelectedIndex() - 1);
	}
}
