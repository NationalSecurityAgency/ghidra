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
package generic.theme;

import generic.theme.laf.UiDefaultsMapper;

/**
 * This class provides a set of IDs that can be used in the application, regardless of which Look
 * and Feel (LaF) is being used.
 * <P>
 * Various LaFs have different names for common concepts and even define additional concepts not
 * listed here. The values in this class are those the application used use regardless of the LaF
 * being used. When we load a specific LaF, a {@link UiDefaultsMapper} specific to that LaF is used
 * to map its common LaF ids to these standard system ids. The {@link GThemeDefaults} uses these
 * system ids to define colors that can be used throughout the application without using these ids
 * directly.
 * <P>
 * The ids are assigned to categories as follows:
 * <UL>
 *      <LI>CONTROL- these ids are used for colors and fonts for general system components such as
 * 				Buttons, Checkboxes, or anything that doesn't fit into one of the other areas</LI>
 *  	<LI>VIEW - these ids are used for the colors and fonts used for widgets that display data
 *  			such as Trees, Tables, TextFieds, and Lists</LI>
 *  	<LI>MENU - these ids are used by menu components such as Menus and MenuItems.</LI>
 *  	<LI>TOOLTIP - these ids are used just by the tooltip component
 * </UL>
 * <P>
 * For each of those categories the ids specify a specific property for those components.
 * <UL>
 * 		<LI> BG - the background color
 * 		<LI> FG - the foreground color
 * 		<LI> BG_SELECTED - the background color when the component is selected
 * 		<LI> FG_SELECTED - the foreground color when the component is selected
 * 		<LI> FG_DISABLED - the foreground color when the component is disabled
 * 		<LI> BG_BORDER - the border color
 * 		<LI> FONT - the font
 * </UL>
 */
public class SystemThemeIds {
	public static final String FONT_CONTROL_ID = "system.font.control";
	public static final String FONT_VIEW_ID = "system.font.view";
	public static final String FONT_MENU_ID = "system.font.menu";

	public static final String BG_CONTROL_ID = "system.color.bg.control";
	public static final String BG_VIEW_ID = "system.color.bg.view";
	public static final String BG_TOOLTIP_ID = "system.color.bg.tooltip";
	public static final String BG_VIEW_SELECTED_ID = "system.color.bg.selected.view";
	public static final String BG_BORDER_ID = "system.color.bg.border";

	public static final String FG_CONTROL_ID = "system.color.fg.control";
	public static final String FG_VIEW_ID = "system.color.fg.view";
	public static final String FG_TOOLTIP_ID = "system.color.fg.tooltip";
	public static final String FG_VIEW_SELECTED_ID = "system.color.fg.selected.view";
	public static final String FG_DISABLED_ID = "system.color.fg.disabled";

}
