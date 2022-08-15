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
 * {@link ThemeEvent} for when a color changes for exactly one color id.
 */
public class ColorChangedThemeEvent extends ThemeEvent {
	private final ColorValue color;

	/**
	 * Constructor
	 * @param color the new {@link ColorValue} for the color id that changed
	 */
	public ColorChangedThemeEvent(ColorValue color) {
		this.color = color;
	}

	@Override
	public boolean isColorChanged(String id) {
		return id.equals(color.getId());
	}

	@Override
	public boolean hasAnyColorChanged() {
		return true;
	}
}
