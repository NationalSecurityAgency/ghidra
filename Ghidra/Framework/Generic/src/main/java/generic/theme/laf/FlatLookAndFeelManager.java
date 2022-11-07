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
package generic.theme.laf;

import javax.swing.UIManager;

import generic.theme.*;

public class FlatLookAndFeelManager extends LookAndFeelManager {

	public FlatLookAndFeelManager(LafType laf, ApplicationThemeManager themeManager) {
		super(laf, themeManager);

		// establish system color to LookAndFeel colors
		systemToLafMap.addColor(new ColorValue(SYSTEM_WIDGET_BACKGROUND_COLOR_ID, "text"));
		systemToLafMap.addColor(new ColorValue(SYSTEM_TOOLTIP_BACKGROUND_COLOR_ID, "info"));
	}

	@Override
	protected void fixupLookAndFeelIssues() {
		super.fixupLookAndFeelIssues();

		// We have historically managed button focus-ability ourselves.  Allow this by default so
		// features continue to work as expected, such as right-clicking on ToolButtons.
		UIManager.put("ToolBar.focusableButtons", Boolean.TRUE);
	}

	@Override
	protected ThemeGrouper getThemeGrouper() {
		return new FlatThemeGrouper();
	}
}
