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
 * Adds specialized groupings unique to the Nimbus LookAndFeel
 */
public class NimbusThemeGrouper extends ThemeGrouper {
	public NimbusThemeGrouper() {
		// Nimbus defines a new type of button
		buttonGroup.addComponents("ArrowButton");

		// Nimbus defines some other color sources
		colorSourceProperties.add("nimbusFocus");
		colorSourceProperties.add("nimbusOrange");
		colorSourceProperties.add("nimbusBorder");

	}

	@Override
	public void group(GThemeValueMap values) {
		defineCustomColorGroup("color.nimbus.text.alt", "Menu.foreground", values);
		defineCustomFontGroup("font.titledborder", "TitledBorder.font", values);

		super.group(values);
	}

}
