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

import generic.theme.GThemeValueMap;

/**
 * Adds specialized groupings unique to the Mac LookAndFeel
 */
public class MacThemeGrouper extends ThemeGrouper {

	@Override
	public void group(GThemeValueMap values) {
		// @formatter:off
		defineCustomColorGroup("color.mac.disabled.fg", "Menu.disabledForeground", values);
		defineCustomColorGroup("color.mac.button.select", "Button.select", values);
		defineCustomColorGroup("color.mac.menu.select", "Menu.selectionBackground",values);
		defineCustomColorGroup("color.mac.seletion.inactive.bg", "List.selectionInactiveBackground",values);//d4d4d4

		defineCustomFontGroup("font.mac.small.font", "IconButton.font", values);
		// @formatter:on
		super.group(values);
	}

}
