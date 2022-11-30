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
 * Adds specialized groupings unique to the Flat LookAndFeels
 */
public class FlatThemeGrouper extends ThemeGrouper {

	@Override
	public void group(GThemeValueMap values) {
		// @formatter:off
		defineCustomColorGroup("color.flat.menu.hover.bg", "MenuBar.hoverBackground", values);
		defineCustomColorGroup("color.flat.button.hover.bg", "Button.hoverBackground", values);
		defineCustomColorGroup("color.flat.button.selected.bg", "Button.selectedBackground",values);
		defineCustomColorGroup("color.flat.button.toolbar.hover.bg", "Button.toolbar.hoverBackground",values);
		defineCustomColorGroup("color.flat.button.toolbar.pressed.bg", "Button.toolbar.pressedBackground",values);
		defineCustomColorGroup("color.flat.checkbox.icon.focus.border", "CheckBox.icon.focusedBorderColor",values);
		defineCustomColorGroup("color.flat.menu.accelerator.fg", "Menu.acceleratorForeground",values);
		
		
		defineCustomColorGroup("color.flat.focus.border", "Button.focusedBorderColor", values);
		defineCustomColorGroup("color.flat.focus", "Component.focusColor", values);
		defineCustomColorGroup("color.flat.focus.bg", "Button.focusedBackground", values);
		defineCustomColorGroup("color.flat.checkmark", "CheckBox.icon.checkmarkColor", values);
		defineCustomColorGroup("color.flat.disabled", "Button.disabledBorderColor", values);
		defineCustomColorGroup("color.flat.disabled.selected", "Button.disabledSelectedBackground",values);
		defineCustomColorGroup("color.flat.arrow", "Spinner.buttonArrowColor",values);
		defineCustomColorGroup("color.flat.arrow.disabled", "Spinner.buttonDisabledArrowColor",values);
		defineCustomColorGroup("color.flat.arrow.hover", "Spinner.buttonHoverArrowColor",values);
		defineCustomColorGroup("color.flat.arrow.pressed", "Spinner.buttonPressedArrowColor",values);

		defineCustomColorGroup("color.flat.dropcell.bg", "List.dropCellBackground",values);
		defineCustomColorGroup("color.flat.dropline", "List.dropLineColor",values);
		defineCustomColorGroup("color.flat.underline", "MenuItem.underlineSelectionColor",values);
		defineCustomColorGroup("color.flat.docking.bg", "ToolBar.dockingBackground",values);
		defineCustomColorGroup("color.flat.progressbar.bg", "ProgressBar.background",values);
		defineCustomColorGroup("color.flat.progressbar.fg", "ProgressBar.foreground",values);
		defineCustomColorGroup("color.flat.icon.bg", "Tree.icon.openColor",values);
		defineCustomColorGroup("color.flat.selection.inactive", "Tree.selectionInactiveBackground",values);
		

		// @formatter:on
		super.group(values);
	}

}
