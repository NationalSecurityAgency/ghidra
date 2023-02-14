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

import java.awt.Color;
import java.awt.Font;

import ghidra.util.Msg;

/**
 * This is a strange implementation of {@link ThemeManager} that is meant to be used in a headless
 * environment, but also needs theme properties to have been loaded.  This is needed by any
 * application that needs to do theme property validation.
 */
public class HeadlessThemeManager extends ThemeManager {

	public static void initialize() {
		if (INSTANCE instanceof HeadlessThemeManager) {
			Msg.error(HeadlessThemeManager.class,
				"Attempted to initialize theming more than once!");
			return;
		}

		HeadlessThemeManager themeManager = new HeadlessThemeManager();
		themeManager.doInitialize();
	}

	public HeadlessThemeManager() {
		INSTANCE = this;
		installInGui();
	}

	private void doInitialize() {
		initializeSystemValues();
		buildCurrentValues();
		GColor.refreshAll(currentValues);
		GIcon.refreshAll(currentValues);
	}

	private void initializeSystemValues() {

		//
		// These values may be referenced by Java clients.   The headless env does not load the
		// Java LookAndFeel, which is from where the values are usually defined. So, add dummy 
		// definitions for these values here.
		//

		Font font = new Font("Arial", Font.PLAIN, 12);
		javaDefaults.addFont(new FontValue(SystemThemeIds.FONT_CONTROL_ID, font));
		javaDefaults.addFont(new FontValue(SystemThemeIds.FONT_VIEW_ID, font));
		javaDefaults.addFont(new FontValue(SystemThemeIds.FONT_MENU_ID, font));

		javaDefaults.addColor(new ColorValue(SystemThemeIds.BG_CONTROL_ID, Color.CYAN));
		javaDefaults.addColor(new ColorValue(SystemThemeIds.BG_VIEW_ID, Color.CYAN));
		javaDefaults.addColor(new ColorValue(SystemThemeIds.BG_TOOLTIP_ID, Color.CYAN));
		javaDefaults.addColor(new ColorValue(SystemThemeIds.BG_VIEW_SELECTED_ID, Color.CYAN));
		javaDefaults.addColor(new ColorValue(SystemThemeIds.BG_BORDER_ID, Color.CYAN));
		javaDefaults.addColor(new ColorValue(SystemThemeIds.FG_CONTROL_ID, Color.CYAN));
		javaDefaults.addColor(new ColorValue(SystemThemeIds.FG_VIEW_ID, Color.CYAN));
		javaDefaults.addColor(new ColorValue(SystemThemeIds.FG_TOOLTIP_ID, Color.CYAN));
		javaDefaults.addColor(new ColorValue(SystemThemeIds.FG_VIEW_SELECTED_ID, Color.CYAN));
		javaDefaults.addColor(new ColorValue(SystemThemeIds.FG_DISABLED_ID, Color.CYAN));

	}
}
