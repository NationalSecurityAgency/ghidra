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
package ghidra.program.model.data;

import ghidra.docking.settings.JavaEnumSettingsDefinition;
import ghidra.docking.settings.Settings;
import ghidra.program.model.data.RenderUnicodeSettingsDefinition.RENDER_ENUM;

/**
 * Settings definition for controlling the display of UNICODE characters.
 */
public class RenderUnicodeSettingsDefinition extends JavaEnumSettingsDefinition<RENDER_ENUM> {

	public enum RENDER_ENUM {
		ALL("all"), BYTE_SEQ("byte sequence"), ESC_SEQ("escape sequence");

		private final String s;

		private RENDER_ENUM(String s) {
			this.s = s;
		}

		@Override
		public String toString() {
			return s;
		}
	}

	public static final RenderUnicodeSettingsDefinition RENDER =
		new RenderUnicodeSettingsDefinition();

	private RenderUnicodeSettingsDefinition() {
		super("renderUnicode", "Render non-ASCII Unicode",
			"Selects if the unicode string should render all characters or only alphanumeric characters",
			RENDER_ENUM.ALL);
	}

	/**
	 * Gets the current rendering setting from the given settings objects or returns
	 * the default if not in either settings object
	 * @param settings the instance settings
	 * @return the current value for this settings definition
	 */
	public boolean isRenderAlphanumericOnly(Settings settings) {
		return getEnumValue(settings) == RENDER_ENUM.BYTE_SEQ;
	}

}
