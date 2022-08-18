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
package generic.theme.builtin;

import static java.util.Map.*;

import java.awt.Font;
import java.util.List;
import java.util.Map;

import generic.theme.FontValue;
import generic.theme.GThemeValueMap;

/**
 * Maps Java UIDefaults color ids to parent color ids
 */
public class JavaFontMapping {
	private final static String BUTTON_GROUP = "ButtonComponents.font";
	private final static String TEXT_GROUP = "TextComponents.font";
	private final static String MENU_GROUP = "MenuComponents.font";
	private final static String MENU_ACCELERATOR_GROUP = "MenuComponents.acceleratorFont";
	private final static String DIALOG_GROUP = "Dialogs.font";
	private final static String WIDGET_GROUP = "Components.font";

	private static Map<String, String> map = Map.ofEntries(
		entry("ArrowButton.font", BUTTON_GROUP),		// nimbus
		entry("Button.font", BUTTON_GROUP),
		entry("CheckBox.font", BUTTON_GROUP),
		entry("RadioButton.font", BUTTON_GROUP),
		entry("ToggleButton.font", BUTTON_GROUP),

		entry("CheckBoxMenuItem.font", MENU_GROUP),
		entry("Menu.font", MENU_GROUP),
		entry("MenuBar.font", MENU_GROUP),
		entry("MenuItem.font", MENU_GROUP),
		entry("PopupMenu.font", MENU_GROUP),
		entry("RadioButtonMenuItem.font", MENU_GROUP),

		entry("CheckBoxMenuItem.acceleratorFont", MENU_ACCELERATOR_GROUP),	// metal, motif
		entry("Menu.acceleratorFont", MENU_ACCELERATOR_GROUP),		// metal, motif
		entry("MenuItem.acceleratorFont", MENU_ACCELERATOR_GROUP), 	// metal, motfi
		entry("RadioButtonMenuItem.acceleratorFont", MENU_ACCELERATOR_GROUP),	// metal

		entry("EditorPane.font", TEXT_GROUP),
		entry("FormattedTextField.font", TEXT_GROUP),
		entry("PasswordField.font", TEXT_GROUP),
		entry("TextArea.font", TEXT_GROUP),
		entry("TextField.font", TEXT_GROUP),
		entry("TextPane.font", TEXT_GROUP),

		entry("ColorChooser.font", DIALOG_GROUP),
		entry("FileChooser.font", DIALOG_GROUP),			// nimbus

		entry("ComboBox.font", WIDGET_GROUP),
		entry("InternalFrame.titleFont", WIDGET_GROUP),	// metal, motif, flat
		entry("Label.font", WIDGET_GROUP),
		entry("List.font", WIDGET_GROUP),
		entry("OptionPane.font", DIALOG_GROUP),
		entry("Panel.font", WIDGET_GROUP),
		entry("ProgressBar.font", WIDGET_GROUP),
		entry("RootPane.font", WIDGET_GROUP),
		entry("Scrollbar.font", WIDGET_GROUP),
		entry("ScrollBarThumb.font", WIDGET_GROUP),	// nimbus
		entry("ScrollBarTrack.font", WIDGET_GROUP),	// nimbus
		entry("ScrollPane.font", WIDGET_GROUP),
		entry("Separator.font", WIDGET_GROUP),		// nimbus
		entry("Slider.font", WIDGET_GROUP),
		entry("SliderThumb.font", WIDGET_GROUP),		// nimbus
		entry("SliderTrack.font", WIDGET_GROUP),		// nimbus
		entry("Spinner.font", WIDGET_GROUP),
		entry("SplitPane.font", WIDGET_GROUP),		// nimbus
		entry("TabbedPane.font", WIDGET_GROUP),
		entry("TitledBorder.font", WIDGET_GROUP),
		entry("ToolBar.font", WIDGET_GROUP),
		entry("ToolTip.font", TEXT_GROUP),
		entry("Viewport.font", WIDGET_GROUP),

		entry("Tree.font", WIDGET_GROUP),
		entry("Table.font", WIDGET_GROUP),
		entry("TableHeader.font", "Table.font"));

	public static void fixupJavaDefaultsInheritence(GThemeValueMap values) {
		createGroupDefaults(values);
		List<FontValue> fonts = values.getFonts();
		for (FontValue value : fonts) {
			FontValue mapped = map(values, value);
			if (mapped != null) {
				values.addFont(mapped);
			}
		}
	}

	private static FontValue map(GThemeValueMap values, FontValue value) {
		String id = value.getId();
		String refId = map.get(id);
		if (refId == null) {
			return null;
		}
		FontValue refValue = values.getFont(refId);
		if (refValue == null) {
			return null;
		}
		Font originalFont = value.get(values);
		Font refFont = refValue.get(values);
		if (originalFont == null || refFont == null) {
			return null;
		}
		if (originalFont.equals(refFont)) {
			return new FontValue(id, refId);
		}
		return null;
	}

	public static void createGroupDefaults(GThemeValueMap valuesMap) {
		addFontValue(valuesMap, BUTTON_GROUP, "Button.font");
		addFontValue(valuesMap, TEXT_GROUP, "TextField.font");
		addFontValue(valuesMap, MENU_GROUP, "Menu.font");
		addFontValue(valuesMap, MENU_ACCELERATOR_GROUP, "Menu.acceleratorFont");
		addFontValue(valuesMap, DIALOG_GROUP, "ColorChooser.font");
		addFontValue(valuesMap, WIDGET_GROUP, "Label.font");
	}

	private static void addFontValue(GThemeValueMap valuesMap, String groupId, String exemplarId) {
		FontValue font = valuesMap.getFont(exemplarId);
		if (font != null) {
			valuesMap.addFont(new FontValue(groupId, font.get(valuesMap)));
		}
	}

}
