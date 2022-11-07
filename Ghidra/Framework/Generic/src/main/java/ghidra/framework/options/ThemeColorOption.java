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
package ghidra.framework.options;

import java.awt.Color;

import generic.theme.*;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;

/**
 * Options implementation for theme color options. A ThemeColorOption is an option that, when
 * changed, affects the current theme and is saved in the theme, instead of being saved with
 * normal non-theme related options.
 */
public class ThemeColorOption extends Option {

	private String colorId;

	public ThemeColorOption(String optionName, String colorId, String description,
			HelpLocation help) {
		super(optionName, OptionType.COLOR_TYPE, description, help, null, true, null);
		this.colorId = colorId;
		if (!Gui.hasColor(colorId)) {
			Msg.warn(this,
				"Registered a theme color option with a non-defined theme color id of \"" +
					colorId + "\"");
		}

	}

	@Override
	public Color getCurrentValue() {
		return new GColor(colorId);
	}

	@Override
	public Object getDefaultValue() {
		return getCurrentValue();
	}

	@Override
	public void doSetCurrentValue(Object value) {
		ThemeManager.getInstance().setColor(colorId, (Color) value);
	}

	@Override
	public boolean isDefault() {
		return !ThemeManager.getInstance().isChangedColor(colorId);
	}

	@Override
	public void restoreDefault() {
		ThemeManager.getInstance().restoreColor(colorId);
	}

}
