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

import java.awt.event.InputEvent;
import java.util.Set;

import javax.swing.Icon;
import javax.swing.ImageIcon;

import docking.ActionContext;
import docking.action.*;
import ghidra.app.services.FunctionComparisonService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Function;
import ghidra.util.HelpLocation;
import resources.MultiIcon;
import resources.ResourceManager;
import resources.icons.ScaledImageIconWrapper;
import resources.icons.TranslateIcon;

/**
 * Creates a new comparison between a set of functions, launching a new 
 * comparison provider in the process
 * <p>
 * This class is abstract to force implementors to supply the source of the 
 * functions (may be the listing, a table, etc...) 
 * 
 * @see #getSelectedFunctions(ActionContext)
 */
public abstract class CompareFunctionsAction extends DockingAction {

	protected FunctionComparisonService comparisonService;

	private static final ImageIcon COMPARISON_ICON =
		ResourceManager.loadImage("images/page_white_c.png");
	private static final Icon NEW_ICON = ResourceManager.loadImage("images/bullet_star.png");
	private static final Icon SCALED_NEW_ICON = new ScaledImageIconWrapper(NEW_ICON, 16, 16);
	private static final Icon TRANSLATED_NEW_ICON = new TranslateIcon(SCALED_NEW_ICON, 4, -4);
	private static final Icon CREATE_NEW_COMPARISON_ICON =
		new MultiIcon(COMPARISON_ICON, TRANSLATED_NEW_ICON);
	private static final String CREATE_COMPARISON_GROUP = "A9_CreateComparison";
	static final String POPUP_MENU_NAME = "Compare Selected Functions";

	/**
	 * Constructor
	 * 
	 * @param tool the plugin tool
	 * @param owner the action owner (usually the plugin name)
	 */
	public CompareFunctionsAction(PluginTool tool, String owner) {
		super("Compare Functions", owner, KeyBindingType.SHARED);
		this.comparisonService = tool.getService(FunctionComparisonService.class);
		setActionAttributes();
	}

	@Override
	public void actionPerformed(ActionContext context) {
		Set<Function> functions = getSelectedFunctions(context);
		comparisonService.compareFunctions(functions);
	}

	@Override
	public boolean isEnabledForContext(ActionContext actionContext) {
		Set<Function> functions = getSelectedFunctions(actionContext);
		return !functions.isEmpty();
	}

	/**
	 * Returns the icon to use for the action
	 * 
	 * @return the icon
	 */
	protected Icon getToolBarIcon() {
		return CREATE_NEW_COMPARISON_ICON;
	}

	/**
	 * Returns the set of functions that will be sent to the comparison service
	 * 
	 * @param actionContext the current action context
	 * @return set of functions to be compared
	 */
	protected abstract Set<Function> getSelectedFunctions(ActionContext actionContext);

	private void setActionAttributes() {
		setDescription("Create Function Comparison");
		setPopupMenuData(new MenuData(new String[] { "Compare Selected Functions" },
			getToolBarIcon(), CREATE_COMPARISON_GROUP));

		ToolBarData newToolBarData =
			new ToolBarData(getToolBarIcon(), CREATE_COMPARISON_GROUP);
		setToolBarData(newToolBarData);

		setHelpLocation(new HelpLocation("FunctionComparison", "Function_Comparison"));

		KeyBindingData data = new KeyBindingData('C', InputEvent.SHIFT_DOWN_MASK);
		setKeyBindingData(data);
	}
}
