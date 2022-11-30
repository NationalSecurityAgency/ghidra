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

import javax.swing.LookAndFeel;

/**
 * Event for when a theme value changes;
 */
public class ThemeEvent {

	/**
	 * Returns true if the color associated with the given id has changed.
	 * @param id the color id to test if changed
	 * @return true if the color associated with the given id has changed
	 */
	public boolean isColorChanged(String id) {
		return false;
	}

	/**
	 * Returns true if the font associated with the given id has changed.
	 * @param id the font id to test if changed
	 * @return true if the font associated with the given id has changed
	 */
	public boolean isFontChanged(String id) {
		return false;
	}

	/**
	 * Returns true if the icon associated with the given id has changed.
	 * @param id the icon id to test if changed
	 * @return true if the icon associated with the given id has changed
	 */
	public boolean isIconChanged(String id) {
		return false;
	}

	/**
	 * Returns true if the {@link LookAndFeel} has changed (theme changed).
	 * @return true if the {@link LookAndFeel} has changed (theme changed).
	 */
	public boolean isLookAndFeelChanged() {
		return false;
	}

	/**
	 * Returns true if any color value changed.
	 * @return true if any color value changed.
	 */
	public boolean hasAnyColorChanged() {
		return false;
	}

	/**
	 * Returns true if any font value changed.
	 * @return true if any font value changed.
	 */
	public boolean hasAnyFontChanged() {
		return false;
	}

	/**
	 * Returns true if any icon value changed.
	 * @return true if any icon value changed.
	 */
	public boolean hasAnyIconChanged() {
		return false;
	}

	/**
	 * Returns true if all colors, fonts, and icons may have changed. This doesn't guarantee that 
	 * all the values have actually changed, just that they might have. In other words, a mass
	 * change occurred (theme change, theme reset, etc.) and any or all values may have changed.
	 * @return true if all colors, fonts, and icons may have changed.
	 */
	public boolean haveAllValuesChanged() {
		return false;
	}
}
