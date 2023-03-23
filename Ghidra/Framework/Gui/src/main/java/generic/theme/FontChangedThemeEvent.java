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

/**
 * {@link ThemeEvent} for when a font changes for exactly one font id.
 */
public class FontChangedThemeEvent extends ThemeEvent {
	private final FontValue font;
	private final GThemeValueMap values;

	/**
	 * Constructor
	 * @param values the set of theme values used to resolve indirect references
	 * @param font the new {@link FontValue} for the font id that changed
	 */
	public FontChangedThemeEvent(GThemeValueMap values, FontValue font) {
		this.values = values;
		this.font = font;
	}

	@Override
	public boolean isFontChanged(String id) {
		if (id.equals(font.getId())) {
			return true;
		}
		FontValue testValue = values.getFont(id);
		if (testValue == null) {
			return false;
		}
		return testValue.inheritsFrom(font.getId(), values);
	}

	@Override
	public boolean hasAnyFontChanged() {
		return true;
	}
}
