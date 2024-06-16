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
 * {@link ThemeEvent} for when a new theme is set or the current theme is reset to its original 
 * values.
 */
public class AllValuesChangedThemeEvent extends ThemeEvent {

	private boolean lookAndFeelChanged;

	/**
	 * Constructor
	 * @param lookAndFeelChanged true if the overall theme was changed which may have caused the
	 * {@link LookAndFeel} to change
	 */
	public AllValuesChangedThemeEvent(boolean lookAndFeelChanged) {
		this.lookAndFeelChanged = lookAndFeelChanged;
	}

	@Override
	public boolean isColorChanged(String id) {
		return true;
	}

	@Override
	public boolean isFontChanged(String id) {
		return true;
	}

	@Override
	public boolean isIconChanged(String id) {
		return true;
	}

	@Override
	public boolean isLookAndFeelChanged() {
		return lookAndFeelChanged;
	}

	@Override
	public boolean haveAllValuesChanged() {
		return true;
	}

	@Override
	public boolean hasAnyColorChanged() {
		return true;
	}

	@Override
	public boolean hasAnyFontChanged() {
		return true;
	}

	@Override
	public boolean hasAnyIconChanged() {
		return true;
	}
}
