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

import java.awt.Font;

import generic.theme.Gui;
import generic.theme.ThemeManager;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;

/**
 * Options implementation for theme font options. A ThemeFontOption is an option that, when
 * changed, affects the current theme and is saved in the theme, instead of being saved with
 * normal non-theme related options.
 */
public class ThemeFontOption extends Option {

	private String fontId;

	public ThemeFontOption(String optionName, String fontId, String description,
			HelpLocation help) {
		super(optionName, OptionType.FONT_TYPE, description, help, null, true, null);
		this.fontId = fontId;
		if (!Gui.hasFont(fontId)) {
			Msg.warn(this,
				"Registered a theme font option with a non-defined theme font id of \"" +
					fontId + "\"");
		}

	}

	@Override
	public Font getCurrentValue() {
		return Gui.getFont(fontId);
	}

	@Override
	public Object getDefaultValue() {
		return getCurrentValue();
	}

	@Override
	public void doSetCurrentValue(Object value) {
		ThemeManager.getInstance().setFont(fontId, (Font) value);
	}

	@Override
	public boolean isDefault() {
		return !ThemeManager.getInstance().isChangedFont(fontId);
	}

	@Override
	public void restoreDefault() {
		ThemeManager.getInstance().restoreFont(fontId);
	}

}
