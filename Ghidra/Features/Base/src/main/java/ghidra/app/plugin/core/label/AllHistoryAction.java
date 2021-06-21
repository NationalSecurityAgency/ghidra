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
package ghidra.app.plugin.core.label;

import java.awt.event.KeyEvent;

import docking.action.KeyBindingData;
import docking.action.MenuData;
import docking.tool.ToolConstants;
import ghidra.app.context.ListingActionContext;
import ghidra.app.context.ListingContextAction;
import ghidra.framework.plugintool.PluginTool;

public class AllHistoryAction extends ListingContextAction {

	private final PluginTool tool;

	public AllHistoryAction(PluginTool tool, String owner) {
		super("Show All History", owner);
		this.tool = tool;
		setMenuBarData(new MenuData(new String[] { ToolConstants.MENU_SEARCH, "Label History..." },
			null, "Search"));

		setKeyBindingData(new KeyBindingData(KeyEvent.VK_H, 0));
		addToWindowWhen(ListingActionContext.class);
	}

	@Override
	protected boolean isEnabledForContext(ListingActionContext context) {
		return context.getAddress() != null;
	}

	@Override
	protected void actionPerformed(ListingActionContext context) {
		LabelHistoryInputDialog dialog = new LabelHistoryInputDialog(tool, context.getProgram());
		dialog.showDialog();
	}

}
