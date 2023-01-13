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

import generic.theme.GThemeValueMap;
import generic.theme.ThemeManager;

/**
 * Shares values for the three theme value tables so they all don't have their own copies
 */
public class GThemeValuesCache {

	private ThemeManager themeManager;
	private GThemeValueMap currentValues;
	private GThemeValueMap themeValues;
	private GThemeValueMap defaultValues;
	private GThemeValueMap lightValues;
	private GThemeValueMap darkValues;

	public GThemeValuesCache(ThemeManager themeManager) {
		this.themeManager = themeManager;
	}

	public void clear() {
		currentValues = null;
		themeValues = null;
		defaultValues = null;
		lightValues = null;
		darkValues = null;
	}

	public GThemeValueMap getCurrentValues() {
		if (currentValues == null) {
			currentValues = themeManager.getCurrentValues();
		}
		return currentValues;
	}

	public GThemeValueMap getThemeValues() {
		if (themeValues == null) {
			themeValues = themeManager.getThemeValues();
		}
		return themeValues;
	}

	public GThemeValueMap getDefaultValues() {
		if (defaultValues == null) {
			defaultValues = themeManager.getDefaults();
		}
		return defaultValues;
	}

	public GThemeValueMap getLightValues() {
		if (lightValues == null) {
			lightValues = themeManager.getApplicationLightDefaults();
		}
		return lightValues;
	}

	public GThemeValueMap getDarkValues() {
		if (darkValues == null) {
			darkValues = themeManager.getApplicationDarkDefaults();
		}
		return darkValues;
	}

}
