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

import java.awt.Color;
import java.util.List;
import java.util.Map;

import generic.theme.ColorValue;
import generic.theme.GThemeValueMap;

/**
 * Maps Java UIDefaults color ids to parent color ids
 */
public class JavaColorMapping {
	private static Map<String, String> map = Map.ofEntries(
		entry("Button.background", "control"),
		entry("Button.foreground", "controlText"),
		entry("Button.shadow", "controlShadow"),
		entry("Button.darkShadow", "controlDkShadow"),
		entry("Button.light", "controlHighlight"),
		entry("Button.highlight", "controlLtHighlight"),
		entry("ToggleButton.background", "control"),
		entry("ToggleButton.foreground", "controlText"),
		entry("ToggleButton.shadow", "controlShadow"),
		entry("ToggleButton.darkShadow", "controlDkShadow"),
		entry("ToggleButton.light", "controlHighlight"),
		entry("ToggleButton.highlight", "controlLtHighlight"),
		entry("RadioButton.background", "control"),
		entry("RadioButton.foreground", "controlText"),
		entry("RadioButton.shadow", "controlShadow"),
		entry("RadioButton.darkShadow", "controlDkShadow"),
		entry("RadioButton.light", "controlHighlight"),
		entry("RadioButton.highlight", "controlLtHighlight"),
		entry("CheckBox.background", "control"),
		entry("CheckBox.foreground", "controlText"),
		entry("ColorChooser.background", "control"),
		entry("ColorChooser.foreground", "controlText"),
		entry("ColorChooser.swatchesDefaultRecentColor", "control"),
		entry("ComboBox.background", "window"),
		entry("ComboBox.foreground", "textText"),
		entry("ComboBox.buttonBackground", "control"),
		entry("ComboBox.buttonShadow", "controlShadow"),
		entry("ComboBox.buttonDarkShadow", "controlDkShadow"),
		entry("ComboBox.buttonHighlight", "controlLtHighlight"),
		entry("ComboBox.selectionBackground", "textHighlight"),
		entry("ComboBox.selectionForeground", "textHighlightText"),
		entry("ComboBox.disabledBackground", "control"),
		entry("ComboBox.disabledForeground", "textHInactiveText"),
		entry("InternalFrame.borderColor", "control"),
		entry("InternalFrame.borderShadow", "controlShadow"),
		entry("InternalFrame.borderDarkShadow", "controlDkShadow"),
		entry("InternalFrame.borderHighlight", "controlLtHighlight"),
		entry("InternalFrame.borderLight", "controlHighlight"),
		entry("InternalFrame.activeTitleBackground", "activeCaption"),
		entry("InternalFrame.activeTitleForeground", "activeCaptionText"),
		entry("InternalFrame.inactiveTitleBackground", "inactiveCaption"),
		entry("InternalFrame.inactiveTitleForeground", "inactiveCaptionText"),
		entry("Label.background", "control"),
		entry("Label.foreground", "controlText"),
		entry("Label.disabledShadow", "controlShadow"),
		entry("List.background", "window"),
		entry("List.foreground", "textText"),
		entry("List.selectionBackground", "textHighlight"),
		entry("List.selectionForeground", "textHighlightText"),
		entry("List.dropLineColor", "controlShadow"),
		entry("MenuBar.background", "menu"),
		entry("MenuBar.foreground", "menuText"),
		entry("MenuBar.shadow", "controlShadow"),
		entry("MenuBar.highlight", "controlLtHighlight"),
		entry("MenuItem.background", "menu"),
		entry("MenuItem.foreground", "menuText"),
		entry("MenuItem.selectionForeground", "textHighlightText"),
		entry("MenuItem.selectionBackground", "textHighlight"),
		entry("MenuItem.acceleratorForeground", "menuText"),
		entry("MenuItem.acceleratorSelectionForeground", "textHighlightText"),
		entry("RadioButtonMenuItem.background", "menu"),
		entry("RadioButtonMenuItem.foreground", "menuText"),
		entry("RadioButtonMenuItem.selectionForeground", "textHighlightText"),
		entry("RadioButtonMenuItem.selectionBackground", "textHighlight"),
		entry("RadioButtonMenuItem.acceleratorForeground", "menuText"),
		entry("RadioButtonMenuItem.acceleratorSelectionForeground", "textHighlightText"),
		entry("CheckBoxMenuItem.background", "menu"),
		entry("CheckBoxMenuItem.foreground", "menuText"),
		entry("CheckBoxMenuItem.selectionForeground", "textHighlightText"),
		entry("CheckBoxMenuItem.selectionBackground", "textHighlight"),
		entry("CheckBoxMenuItem.acceleratorForeground", "menuText"),
		entry("CheckBoxMenuItem.acceleratorSelectionForeground", "textHighlightText"),
		entry("Menu.background", "menu"),
		entry("Menu.foreground", "menuText"),
		entry("Menu.selectionForeground", "textHighlightText"),
		entry("Menu.selectionBackground", "textHighlight"),
		entry("Menu.acceleratorForeground", "menuText"),
		entry("Menu.acceleratorSelectionForeground", "textHighlightText"),
		entry("PopupMenu.background", "menu"),
		entry("PopupMenu.foreground", "menuText"),
		entry("OptionPane.background", "control"),
		entry("OptionPane.foreground", "controlText"),
		entry("OptionPane.messageForeground", "controlText"),
		entry("Panel.background", "control"),
		entry("Panel.foreground", "textText"),
		entry("ProgressBar.foreground", "textHighlight"),
		entry("ProgressBar.background", "control"),
		entry("ProgressBar.selectionForeground", "control"),
		entry("ProgressBar.selectionBackground", "textHighlight"),
		entry("Separator.background", "controlLtHighlight"),
		entry("Separator.foreground", "controlShadow"),
		entry("ScrollBar.foreground", "control"),
		entry("ScrollBar.track", "scrollbar"),
		entry("ScrollBar.trackHighlight", "controlDkShadow"),
		entry("ScrollBar.thumb", "control"),
		entry("ScrollBar.thumbHighlight", "controlLtHighlight"),
		entry("ScrollBar.thumbDarkShadow", "controlDkShadow"),
		entry("ScrollBar.thumbShadow", "controlShadow"),
		entry("ScrollPane.background", "control"),
		entry("ScrollPane.foreground", "controlText"),
		entry("Viewport.background", "control"),
		entry("Viewport.foreground", "textText"),
		entry("Slider.foreground", "control"),
		entry("Slider.background", "control"),
		entry("Slider.highlight", "controlLtHighlight"),
		entry("Slider.shadow", "controlShadow"),
		entry("Slider.focus", "controlDkShadow"),
		entry("Spinner.background", "control"),
		entry("Spinner.foreground", "control"),
		entry("SplitPane.background", "control"),
		entry("SplitPane.highlight", "controlLtHighlight"),
		entry("SplitPane.shadow", "controlShadow"),
		entry("SplitPane.darkShadow", "controlDkShadow"),
		entry("TabbedPane.background", "control"),
		entry("TabbedPane.foreground", "controlText"),
		entry("TabbedPane.highlight", "controlLtHighlight"),
		entry("TabbedPane.light", "controlHighlight"),
		entry("TabbedPane.shadow", "controlShadow"),
		entry("TabbedPane.darkShadow", "controlDkShadow"),
		entry("TabbedPane.focus", "controlText"),
		entry("Table.foreground", "controlText"),
		entry("Table.background", "window"),
		entry("Table.selectionForeground", "textHighlightText"),
		entry("Table.selectionBackground", "textHighlight"),
		entry("Table.dropLineColor", "controlShadow"),
		entry("Table.focusCellBackground", "window"),
		entry("Table.focusCellForeground", "controlText"),
		entry("TableHeader.foreground", "controlText"),
		entry("TableHeader.background", "control"),
		entry("TableHeader.focusCellBackground", "text"),
		entry("TextField.background", "window"),
		entry("TextField.foreground", "textText"),
		entry("TextField.shadow", "controlShadow"),
		entry("TextField.darkShadow", "controlDkShadow"),
		entry("TextField.light", "controlHighlight"),
		entry("TextField.highlight", "controlLtHighlight"),
		entry("TextField.inactiveForeground", "textHInactiveText"),
		entry("TextField.inactiveBackground", "control"),
		entry("TextField.selectionBackground", "textHighlight"),
		entry("TextField.selectionForeground", "textHighlightText"),
		entry("TextField.caretForeground", "textText"),
		entry("FormattedTextField.background", "window"),
		entry("FormattedTextField.foreground", "textText"),
		entry("FormattedTextField.inactiveForeground", "textHInactiveText"),
		entry("FormattedTextField.inactiveBackground", "control"),
		entry("FormattedTextField.selectionBackground", "textHighlight"),
		entry("FormattedTextField.selectionForeground", "textHighlightText"),
		entry("FormattedTextField.caretForeground", "textText"),
		entry("PasswordField.background", "window"),
		entry("PasswordField.foreground", "textText"),
		entry("PasswordField.inactiveForeground", "textHInactiveText"),
		entry("PasswordField.inactiveBackground", "control"),
		entry("PasswordField.selectionBackground", "textHighlight"),
		entry("PasswordField.selectionForeground", "textHighlightText"),
		entry("PasswordField.caretForeground", "textText"),
		entry("TextArea.background", "window"),
		entry("TextArea.foreground", "textText"),
		entry("TextArea.inactiveForeground", "textHInactiveText"),
		entry("TextArea.selectionBackground", "textHighlight"),
		entry("TextArea.selectionForeground", "textHighlightText"),
		entry("TextArea.caretForeground", "textText"),
		entry("TextPane.foreground", "textText"),
		entry("TextPane.selectionBackground", "textHighlight"),
		entry("TextPane.selectionForeground", "textHighlightText"),
		entry("TextPane.caretForeground", "textText"),
		entry("TextPane.inactiveForeground", "textHInactiveText"),
		entry("EditorPane.foreground", "textText"),
		entry("EditorPane.selectionBackground", "textHighlight"),
		entry("EditorPane.selectionForeground", "textHighlightText"),
		entry("EditorPane.caretForeground", "textText"),
		entry("EditorPane.inactiveForeground", "textHInactiveText"),
		entry("TitledBorder.titleColor", "controlText"),
		entry("ToolBar.background", "control"),
		entry("ToolBar.foreground", "controlText"),
		entry("ToolBar.shadow", "controlShadow"),
		entry("ToolBar.darkShadow", "controlDkShadow"),
		entry("ToolBar.light", "controlHighlight"),
		entry("ToolBar.highlight", "controlLtHighlight"),
		entry("ToolBar.dockingBackground", "control"),
		entry("ToolBar.floatingBackground", "control"),
		entry("ToolTip.background", "info"),
		entry("ToolTip.foreground", "infoText"),
		entry("Tree.background", "window"),
		entry("Tree.foreground", "textText"),
		entry("Tree.textForeground", "textText"),
		entry("Tree.textBackground", "text"),
		entry("Tree.selectionForeground", "textHighlightText"),
		entry("Tree.selectionBackground", "textHighlight"),
		entry("Tree.dropLineColor", "controlShadow"));

	public static void fixupJavaDefaultsInheritence(GThemeValueMap values) {
		List<ColorValue> colors = values.getColors();
		for (ColorValue value : colors) {
			ColorValue mapped = map(values, value);
			if (mapped != null) {
				values.addColor(mapped);
			}
		}
	}

	private static ColorValue map(GThemeValueMap values, ColorValue value) {
		String id = value.getId();
		String refId = map.get(id);
		if (refId == null) {
			return null;
		}
		ColorValue refValue = values.getColor(refId);
		if (refValue == null) {
			return null;
		}
		Color originalColor = value.get(values);
		Color refColor = refValue.get(values);
		if (originalColor == null || refColor == null) {
			return null;
		}
		if (originalColor.getRGB() == refColor.getRGB()) {
			return new ColorValue(id, refId);
		}
		return null;
	}

}
