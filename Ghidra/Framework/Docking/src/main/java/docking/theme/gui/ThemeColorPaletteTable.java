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
package docking.theme.gui;

import java.util.ArrayList;
import java.util.List;

import generic.theme.ColorValue;
import generic.theme.ThemeManager;

public class ThemeColorPaletteTable extends ThemeColorTable {

	public ThemeColorPaletteTable(ThemeManager themeManager, GThemeValuesCache valuesProvider) {
		super(themeManager, valuesProvider);
	}

	@Override
	ThemeColorTableModel createModel(GThemeValuesCache valuesProvider) {
		return new ThemeColorTableModel(valuesProvider) {
			@Override
			protected void filter() {

				super.filter(); // this call will update 'colors'

				List<ColorValue> filtered = new ArrayList<>();

				for (ColorValue colorValue : colors) {
					String id = colorValue.getId();
					if (id.startsWith("color.palette")) {
						filtered.add(colorValue);
					}
				}

				colors = filtered;
			}
		};
	}
}
