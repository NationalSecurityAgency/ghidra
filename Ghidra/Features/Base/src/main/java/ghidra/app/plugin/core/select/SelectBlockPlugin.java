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
package ghidra.app.plugin.core.select;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.tool.ToolConstants;
import ghidra.app.CorePluginPackage;
import ghidra.app.context.NavigatableActionContext;
import ghidra.app.context.NavigatableContextAction;
import ghidra.app.nav.Navigatable;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.HelpLocation;

/**
 * This plugin class contains the structure needed for the user to
 * select blocks of data anywhere inside of the Code Browser and Byte Viewer.
 * <p>
 * Note:  This plugin used to refer to selections as blocks instead of lengths
 * of bytes.  The GUI has been changed, but the internal comments and 
 * variable names have not.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.COMMON,
	shortDescription = "Select Bytes",
	description = "Allows the user to select different size "
			+ "lengths of bytes from the Byte Viewer "
			+ "generally starting from the cursor position or entire file"
)
//@formatter:on
public class SelectBlockPlugin extends Plugin {
	private DockingAction toolBarAction;
	private SelectBlockDialog dialog;

	public SelectBlockPlugin(PluginTool tool) {
		super(tool);
		createActions();
	}

	private void createActions() {

		toolBarAction = new NavigatableContextAction("SelectBlock", getName()) {
			@Override
			public void actionPerformed(NavigatableActionContext context) {
				showDialog(context.getComponentProvider(), context.getNavigatable());
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				updateNavigatable(context);
				return super.isEnabledForContext(context);
			}
		};
		MenuData menuData =
			new MenuData(new String[] { ToolConstants.MENU_SELECTION, "Bytes..." }, null,
				"Select Group 2");
		menuData.setMenuSubGroup("1");
		toolBarAction.setMenuBarData(menuData);
		toolBarAction.addToWindowWhen(NavigatableActionContext.class);

		toolBarAction.setEnabled(false);
		toolBarAction.setDescription("Allows user to select blocks of data.");
		toolBarAction.setHelpLocation(new HelpLocation("SelectBlockPlugin", "Select_Block_Help"));
		tool.addAction(toolBarAction);
	}

	protected void updateNavigatable(ActionContext context) {
		if (dialog == null) {
			return;
		}
		if (context instanceof NavigatableActionContext) {
			dialog.setNavigatable(((NavigatableActionContext) context).getNavigatable());
		}
		else {
			dialog.setNavigatable(null);
		}
	}

	private void showDialog(ComponentProvider provider, Navigatable navigatable) {
		if (dialog != null) {
			dialog.close();
		}
		dialog = new SelectBlockDialog(tool, navigatable);
		dialog.show(provider);
	}

}
