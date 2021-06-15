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
package ghidra.util;

import java.awt.Color;
import java.util.HashMap;
import java.util.Map;

import javax.swing.*;
import javax.swing.border.Border;

public class UIManagerWrapper {

	private static Map<String, Color> colorMap = new HashMap<>();
	private static Map<String, Border> borderMap = new HashMap<>();

	static {
		colorMap.put("Table[Enabled+Selected].textForeground", new Color(255, 255, 255));
		colorMap.put("Table[Enabled+Selected].textBackground", new Color(57, 105, 138));
		colorMap.put("Table.textForeground", new Color(35, 35, 36));
		colorMap.put("Table.alternateRowColor", new Color(237, 243, 254));
		colorMap.put("Table:\"Table.cellRenderer\".background", new Color(255, 255, 255));

		borderMap.put("Table.focusCellHighlightBorder",
			BorderFactory.createEmptyBorder(2, 5, 2, 5));
		borderMap.put("Table.cellNoFocusBorder", BorderFactory.createEmptyBorder(2, 5, 2, 5));
	}

	public static Color getColor(String text) {
		UIDefaults uiDefaults = UIManager.getDefaults();
		Color color = uiDefaults.getColor(text);
		if (color == null) {
			color = colorMap.get(text);
		}
		return color;
	}

	public static Border getBorder(String text) {
		UIDefaults uiDefaults = UIManager.getDefaults();
		Border border = uiDefaults.getBorder(text);
		if (border == null) {
			border = borderMap.get(text);
		}
		return border;
	}

}
