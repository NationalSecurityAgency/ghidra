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
		// we made up a source property for a common Flat color. Picked one of them as
		// an exemplar (menu.foreground)
		// @formatter:off
		defineCustomColorGroup(values, "color.flat.menu.hover.bg", "MenuBar.hoverBackground");
		defineCustomColorGroup(values, "color.flat.button.hover.bg", "Button.hoverBackground");
		defineCustomColorGroup(values, "color.flat.button.selected.bg","Button.selectedBackground");
		defineCustomColorGroup(values, "color.flat.button.toolbar.hover.bg","Button.toolbar.hoverBackground");
		defineCustomColorGroup(values, "color.flat.button.toolbar.pressed.bg","Button.toolbar.pressedBackground");
		defineCustomColorGroup(values, "color.flat.checkbox.icon.focus.border","CheckBox.icon.focusedBorderColor");
		defineCustomColorGroup(values, "color.flat.menu.accelerator.fg","Menu.acceleratorForeground");
		
		
		defineCustomColorGroup(values, "color.flat.focus.border", "Button.focusedBorderColor");
		defineCustomColorGroup(values, "color.flat.focus", "Component.focusColor");
		defineCustomColorGroup(values, "color.flat.focus.bg", "Button.focusedBackground");
		defineCustomColorGroup(values, "color.flat.checkmark", "CheckBox.icon.checkmarkColor");
		defineCustomColorGroup(values, "color.flat.disabled", "Button.disabledBorderColor");
		defineCustomColorGroup(values, "color.flat.disabled.selected","Button.disabledSelectedBackground");
		defineCustomColorGroup(values, "color.flat.arrow","Spinner.buttonArrowColor");
		defineCustomColorGroup(values, "color.flat.arrow.disabled","Spinner.buttonDisabledArrowColor");
		defineCustomColorGroup(values, "color.flat.arrow.hover","Spinner.buttonHoverArrowColor");
		defineCustomColorGroup(values, "color.flat.arrow.pressed","Spinner.buttonPressedArrowColor");

		defineCustomColorGroup(values, "color.flat.dropcell.bg","List.dropCellBackground");
		defineCustomColorGroup(values, "color.flat.dropline","List.dropLineColor");
		defineCustomColorGroup(values, "color.flat.underline","MenuItem.underlineSelectionColor");
		defineCustomColorGroup(values, "color.flat.docking.bg","ToolBar.dockingBackground");
		defineCustomColorGroup(values, "color.flat.progressbar.bg","ProgressBar.background");
		defineCustomColorGroup(values, "color.flat.progressbar.fg","ProgressBar.foreground");
		defineCustomColorGroup(values, "color.flat.icon.bg","Tree.icon.openColor");
		defineCustomColorGroup(values, "color.flat.selection.inactive","Tree.selectionInactiveBackground");
		

		// @formatter:on
		super.group(values);
	}

}
