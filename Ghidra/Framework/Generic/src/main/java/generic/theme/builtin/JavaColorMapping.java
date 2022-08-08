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

import java.awt.Color;
import java.util.HashMap;
import java.util.Map;

import generic.theme.ColorValue;
import generic.theme.GThemeValueMap;

/**
 * Maps Java UIDefaults color ids to parent color ids
 */
public class JavaColorMapping {
	private Map<String, String> map = new HashMap<>();

	public JavaColorMapping() {
		// color relationships mined from BasicLookAndFeel
		map.put("Button.background", "control");
		map.put("Button.foreground", "controlText");
		map.put("Button.shadow", "controlShadow");
		map.put("Button.darkShadow", "controlDkShadow");
		map.put("Button.light", "controlHighlight");
		map.put("Button.highlight", "controlLtHighlight");
		map.put("ToggleButton.background", "control");
		map.put("ToggleButton.foreground", "controlText");
		map.put("ToggleButton.shadow", "controlShadow");
		map.put("ToggleButton.darkShadow", "controlDkShadow");
		map.put("ToggleButton.light", "controlHighlight");
		map.put("ToggleButton.highlight", "controlLtHighlight");
		map.put("RadioButton.background", "control");
		map.put("RadioButton.foreground", "controlText");
		map.put("RadioButton.shadow", "controlShadow");
		map.put("RadioButton.darkShadow", "controlDkShadow");
		map.put("RadioButton.light", "controlHighlight");
		map.put("RadioButton.highlight", "controlLtHighlight");
		map.put("CheckBox.background", "control");
		map.put("CheckBox.foreground", "controlText");
		map.put("ColorChooser.background", "control");
		map.put("ColorChooser.foreground", "controlText");
		map.put("ColorChooser.swatchesDefaultRecentColor", "control");
		map.put("ComboBox.background", "window");
		map.put("ComboBox.foreground", "textText");
		map.put("ComboBox.buttonBackground", "control");
		map.put("ComboBox.buttonShadow", "controlShadow");
		map.put("ComboBox.buttonDarkShadow", "controlDkShadow");
		map.put("ComboBox.buttonHighlight", "controlLtHighlight");
		map.put("ComboBox.selectionBackground", "textHighlight");
		map.put("ComboBox.selectionForeground", "textHighlightText");
		map.put("ComboBox.disabledBackground", "control");
		map.put("ComboBox.disabledForeground", "textHInactiveText");
		map.put("InternalFrame.borderColor", "control");
		map.put("InternalFrame.borderShadow", "controlShadow");
		map.put("InternalFrame.borderDarkShadow", "controlDkShadow");
		map.put("InternalFrame.borderHighlight", "controlLtHighlight");
		map.put("InternalFrame.borderLight", "controlHighlight");
		map.put("InternalFrame.activeTitleBackground", "activeCaption");
		map.put("InternalFrame.activeTitleForeground", "activeCaptionText");
		map.put("InternalFrame.inactiveTitleBackground", "inactiveCaption");
		map.put("InternalFrame.inactiveTitleForeground", "inactiveCaptionText");
		map.put("Label.background", "control");
		map.put("Label.foreground", "controlText");
		map.put("Label.disabledShadow", "controlShadow");
		map.put("List.background", "window");
		map.put("List.foreground", "textText");
		map.put("List.selectionBackground", "textHighlight");
		map.put("List.selectionForeground", "textHighlightText");
		map.put("List.dropLineColor", "controlShadow");
		map.put("MenuBar.background", "menu");
		map.put("MenuBar.foreground", "menuText");
		map.put("MenuBar.shadow", "controlShadow");
		map.put("MenuBar.highlight", "controlLtHighlight");
		map.put("MenuItem.background", "menu");
		map.put("MenuItem.foreground", "menuText");
		map.put("MenuItem.selectionForeground", "textHighlightText");
		map.put("MenuItem.selectionBackground", "textHighlight");
		map.put("MenuItem.acceleratorForeground", "menuText");
		map.put("MenuItem.acceleratorSelectionForeground", "textHighlightText");
		map.put("RadioButtonMenuItem.background", "menu");
		map.put("RadioButtonMenuItem.foreground", "menuText");
		map.put("RadioButtonMenuItem.selectionForeground", "textHighlightText");
		map.put("RadioButtonMenuItem.selectionBackground", "textHighlight");
		map.put("RadioButtonMenuItem.acceleratorForeground", "menuText");
		map.put("RadioButtonMenuItem.acceleratorSelectionForeground", "textHighlightText");
		map.put("CheckBoxMenuItem.background", "menu");
		map.put("CheckBoxMenuItem.foreground", "menuText");
		map.put("CheckBoxMenuItem.selectionForeground", "textHighlightText");
		map.put("CheckBoxMenuItem.selectionBackground", "textHighlight");
		map.put("CheckBoxMenuItem.acceleratorForeground", "menuText");
		map.put("CheckBoxMenuItem.acceleratorSelectionForeground", "textHighlightText");
		map.put("Menu.background", "menu");
		map.put("Menu.foreground", "menuText");
		map.put("Menu.selectionForeground", "textHighlightText");
		map.put("Menu.selectionBackground", "textHighlight");
		map.put("Menu.acceleratorForeground", "menuText");
		map.put("Menu.acceleratorSelectionForeground", "textHighlightText");
		map.put("PopupMenu.background", "menu");
		map.put("PopupMenu.foreground", "menuText");
		map.put("OptionPane.background", "control");
		map.put("OptionPane.foreground", "controlText");
		map.put("OptionPane.messageForeground", "controlText");
		map.put("Panel.background", "control");
		map.put("Panel.foreground", "textText");
		map.put("ProgressBar.foreground", "textHighlight");
		map.put("ProgressBar.background", "control");
		map.put("ProgressBar.selectionForeground", "control");
		map.put("ProgressBar.selectionBackground", "textHighlight");
		map.put("Separator.background", "controlLtHighlight");
		map.put("Separator.foreground", "controlShadow");
		map.put("ScrollBar.foreground", "control");
		map.put("ScrollBar.track", "scrollbar");
		map.put("ScrollBar.trackHighlight", "controlDkShadow");
		map.put("ScrollBar.thumb", "control");
		map.put("ScrollBar.thumbHighlight", "controlLtHighlight");
		map.put("ScrollBar.thumbDarkShadow", "controlDkShadow");
		map.put("ScrollBar.thumbShadow", "controlShadow");
		map.put("ScrollPane.background", "control");
		map.put("ScrollPane.foreground", "controlText");
		map.put("Viewport.background", "control");
		map.put("Viewport.foreground", "textText");
		map.put("Slider.foreground", "control");
		map.put("Slider.background", "control");
		map.put("Slider.highlight", "controlLtHighlight");
		map.put("Slider.shadow", "controlShadow");
		map.put("Slider.focus", "controlDkShadow");
		map.put("Spinner.background", "control");
		map.put("Spinner.foreground", "control");
		map.put("SplitPane.background", "control");
		map.put("SplitPane.highlight", "controlLtHighlight");
		map.put("SplitPane.shadow", "controlShadow");
		map.put("SplitPane.darkShadow", "controlDkShadow");
		map.put("TabbedPane.background", "control");
		map.put("TabbedPane.foreground", "controlText");
		map.put("TabbedPane.highlight", "controlLtHighlight");
		map.put("TabbedPane.light", "controlHighlight");
		map.put("TabbedPane.shadow", "controlShadow");
		map.put("TabbedPane.darkShadow", "controlDkShadow");
		map.put("TabbedPane.focus", "controlText");
		map.put("Table.foreground", "controlText");
		map.put("Table.background", "window");
		map.put("Table.selectionForeground", "textHighlightText");
		map.put("Table.selectionBackground", "textHighlight");
		map.put("Table.dropLineColor", "controlShadow");
		map.put("Table.focusCellBackground", "window");
		map.put("Table.focusCellForeground", "controlText");
		map.put("TableHeader.foreground", "controlText");
		map.put("TableHeader.background", "control");
		map.put("TableHeader.focusCellBackground", "text");
		map.put("TextField.background", "window");
		map.put("TextField.foreground", "textText");
		map.put("TextField.shadow", "controlShadow");
		map.put("TextField.darkShadow", "controlDkShadow");
		map.put("TextField.light", "controlHighlight");
		map.put("TextField.highlight", "controlLtHighlight");
		map.put("TextField.inactiveForeground", "textHInactiveText");
		map.put("TextField.inactiveBackground", "control");
		map.put("TextField.selectionBackground", "textHighlight");
		map.put("TextField.selectionForeground", "textHighlightText");
		map.put("TextField.caretForeground", "textText");
		map.put("FormattedTextField.background", "window");
		map.put("FormattedTextField.foreground", "textText");
		map.put("FormattedTextField.inactiveForeground", "textHInactiveText");
		map.put("FormattedTextField.inactiveBackground", "control");
		map.put("FormattedTextField.selectionBackground", "textHighlight");
		map.put("FormattedTextField.selectionForeground", "textHighlightText");
		map.put("FormattedTextField.caretForeground", "textText");
		map.put("PasswordField.background", "window");
		map.put("PasswordField.foreground", "textText");
		map.put("PasswordField.inactiveForeground", "textHInactiveText");
		map.put("PasswordField.inactiveBackground", "control");
		map.put("PasswordField.selectionBackground", "textHighlight");
		map.put("PasswordField.selectionForeground", "textHighlightText");
		map.put("PasswordField.caretForeground", "textText");
		map.put("TextArea.background", "window");
		map.put("TextArea.foreground", "textText");
		map.put("TextArea.inactiveForeground", "textHInactiveText");
		map.put("TextArea.selectionBackground", "textHighlight");
		map.put("TextArea.selectionForeground", "textHighlightText");
		map.put("TextArea.caretForeground", "textText");
		map.put("TextPane.foreground", "textText");
		map.put("TextPane.selectionBackground", "textHighlight");
		map.put("TextPane.selectionForeground", "textHighlightText");
		map.put("TextPane.caretForeground", "textText");
		map.put("TextPane.inactiveForeground", "textHInactiveText");
		map.put("EditorPane.foreground", "textText");
		map.put("EditorPane.selectionBackground", "textHighlight");
		map.put("EditorPane.selectionForeground", "textHighlightText");
		map.put("EditorPane.caretForeground", "textText");
		map.put("EditorPane.inactiveForeground", "textHInactiveText");
		map.put("TitledBorder.titleColor", "controlText");
		map.put("ToolBar.background", "control");
		map.put("ToolBar.foreground", "controlText");
		map.put("ToolBar.shadow", "controlShadow");
		map.put("ToolBar.darkShadow", "controlDkShadow");
		map.put("ToolBar.light", "controlHighlight");
		map.put("ToolBar.highlight", "controlLtHighlight");
		map.put("ToolBar.dockingBackground", "control");
		map.put("ToolBar.floatingBackground", "control");
		map.put("ToolTip.background", "info");
		map.put("ToolTip.foreground", "infoText");
		map.put("Tree.background", "window");
		map.put("Tree.foreground", "textText");
		map.put("Tree.textForeground", "textText");
		map.put("Tree.textBackground", "text");
		map.put("Tree.selectionForeground", "textHighlightText");
		map.put("Tree.selectionBackground", "textHighlight");
		map.put("Tree.dropLineColor", "controlShadow");

	}

	public ColorValue map(GThemeValueMap values, ColorValue value) {
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
