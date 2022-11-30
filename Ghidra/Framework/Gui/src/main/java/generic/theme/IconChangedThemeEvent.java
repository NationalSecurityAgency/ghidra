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
 * {@link ThemeEvent} for when an icon changes for exactly one icon id.
 */
public class IconChangedThemeEvent extends ThemeEvent {
	private final GThemeValueMap values;
	private final IconValue icon;

	/**
	 * Constructor
	 * @param icon the new {@link IconValue} for the icon id that changed
	 */
	public IconChangedThemeEvent(GThemeValueMap values, IconValue icon) {
		this.values = values;
		this.icon = icon;
	}

	@Override
	public boolean isIconChanged(String id) {
		if (id.equals(icon.getId())) {
			return true;
		}
		IconValue testValue = values.getIcon(id);
		if (testValue == null) {
			return false;
		}
		return testValue.inheritsFrom(icon.getId(), values);
	}

	@Override
	public boolean hasAnyIconChanged() {
		return true;
	}
}
