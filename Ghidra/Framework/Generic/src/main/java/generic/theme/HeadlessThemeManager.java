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
		buildCurrentValues();
		GColor.refreshAll(currentValues);
		GIcon.refreshAll(currentValues);
	}
}
