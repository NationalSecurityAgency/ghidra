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
package ghidra.base.actions;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.util.HTMLUtilities;

/**
 * An action that can be added to a menu in order to separate menu items into groups
 */
public class HorizontalRuleAction extends DockingAction {

	private static int idCount = 0;

	/**
	 * Constructor
	 * 
	 * @param owner the action owner
	 * @param topName the name that will appear above the separator bar
	 * @param bottomName the name that will appear below the separator bar
	 */
	public HorizontalRuleAction(String owner, String topName, String bottomName) {
		super("HorizontalRuleAction: " + ++idCount, owner, false);
		setEnabled(false);

		// The menu name is both names, one over the other, in a small, light grayish font.
		setMenuBarData(new MenuData(new String[] { "<HTML><CENTER><FONT SIZE=2 COLOR=SILVER>" +
			fixupFirstAmp(
				HTMLUtilities.escapeHTML(topName) + "<BR>" + HTMLUtilities.escapeHTML(bottomName)) +
			"</FONT></CENTER>" }));

		// the description is meant to be used for the tooltip and is larger
		String padding = "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;";
		setDescription("<HTML><CENTER><B>" + padding + HTMLUtilities.escapeHTML(topName) + padding +
			"<B><HR><B>" + padding + HTMLUtilities.escapeHTML(bottomName) + padding +
			"</B></CENTER>");
	}

	private String fixupFirstAmp(String text) {
		// add an extra & to replace the one that the MenuData will eat
		int index = text.indexOf('&');
		return index < 0 ? text : text.substring(0, index) + "&" + text.substring(index);
	}

	@Override
	public void actionPerformed(ActionContext context) {
		// this does't actually do anything
	}

}
