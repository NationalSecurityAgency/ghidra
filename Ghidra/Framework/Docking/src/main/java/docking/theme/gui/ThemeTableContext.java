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

import docking.DefaultActionContext;
import generic.theme.ThemeValue;

/**
 * ActionContext for ThemeDialog tables
 *
 * @param <T> the resource type (Color, Font, or Icon)
 */
public class ThemeTableContext<T> extends DefaultActionContext {

	private ThemeValue<T> currentValue;
	private ThemeValue<T> themeValue;
	private ThemeTable themeTable;

	public ThemeTableContext(ThemeValue<T> currentValue, ThemeValue<T> themeValue,
			ThemeTable themeTable) {
		this.currentValue = currentValue;
		this.themeValue = themeValue;
		this.themeTable = themeTable;
	}

	/**
	 * Returns the theme table for this context
	 * @return the table
	 */
	public ThemeTable getThemeTable() {
		return themeTable;
	}

	/**
	 * Returns the currentValue of the selected table row
	 * @return the currentValue of the selected table row
	 */
	public ThemeValue<T> getCurrentValue() {
		return currentValue;
	}

	/**
	 * Returns the original theme value of the selected table row
	 * @return the original theme value of the selected table row
	 */
	public ThemeValue<T> getThemeValue() {
		return themeValue;
	}

	/**
	 * Returns true if the current value is not the same as the original theme value for the
	 * selected table row
	 * @return true if the current value is not the same as the original theme value for the
	 * selected table row
	 */
	public boolean isChanged() {
		return !currentValue.equals(themeValue);
	}
}
