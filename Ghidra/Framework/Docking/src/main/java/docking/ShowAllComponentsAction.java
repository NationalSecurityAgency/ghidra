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
package docking;

import java.util.List;

import docking.action.MenuData;
import ghidra.util.HelpLocation;

public class ShowAllComponentsAction extends ShowComponentAction {

	private final List<ComponentPlaceholder> infoList;

	public ShowAllComponentsAction(DockingWindowManager winMgr, List<ComponentPlaceholder> infoList,
			String subMenuName) {
		super(winMgr, "Show All", subMenuName);
		this.infoList = infoList;

		String group = "Z";

		setMenuBarData(
			new MenuData(new String[] { MENU_WINDOW, subMenuName, "Show All" }, EMPTY_ICON, group));
		winMgr.doSetMenuGroup(new String[] { MENU_WINDOW, subMenuName }, "Permanent");

		setHelpLocation(new HelpLocation("DockingWindows", "Windows_Menu"));
	}

	@Override
	public void actionPerformed(ActionContext context) {
		boolean focusMe = true;
		for (ComponentPlaceholder info : infoList) {
			winMgr.showComponent(info, true, focusMe, true);
			focusMe = false;
		}
	}
}
