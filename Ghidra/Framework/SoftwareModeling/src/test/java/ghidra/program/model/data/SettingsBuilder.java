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

import java.nio.charset.Charset;

import ghidra.docking.settings.Settings;
import ghidra.docking.settings.SettingsImpl;
import ghidra.program.model.data.RenderUnicodeSettingsDefinition.RENDER_ENUM;
import ghidra.program.model.data.TranslationSettingsDefinition.TRANSLATION_ENUM;

/**
 * Creates a {@link Settings} instance using some setter methods that are handy for unit testing.
 */
public class SettingsBuilder implements Settings {

	private Settings settings = new SettingsImpl();

	/**
	 * Creates an empty settings.
	 */
	public SettingsBuilder() {
		// nada
	}

	/**
	 * Sets the {@link CharsetSettingsDefinition}.
	 * 
	 * @param cs Charset to set
	 * @return chainable SettingsBuilder 
	 */
	public SettingsBuilder set(Charset cs) {
		CharsetSettingsDefinition.CHARSET.setCharset(settings, cs.name());
		return this;
	}

	/**
	 * Sets the {@link RenderUnicodeSettingsDefinition} setting.
	 * 
	 * @param ruenum {@link RENDER_ENUM} value to set.
	 * @return chainable SettingsBuilder
	 */
	public SettingsBuilder set(RENDER_ENUM ruenum) {
		RenderUnicodeSettingsDefinition.RENDER.setEnumValue(settings, ruenum);
		return this;
	}

	/**
	 * Sets the {@link TranslationSettingsDefinition} setting.
	 * 
	 * @param tenum {@link TRANSLATION_ENUM} value to set.
	 * @return chainable SettingsBuilder
	 */
	public SettingsBuilder set(TRANSLATION_ENUM tenum) {
		TranslationSettingsDefinition.TRANSLATION.setEnumValue(settings, tenum);
		return this;
	}

	@Override
	public Long getLong(String name) {
		return settings.getLong(name);
	}

	@Override
	public String getString(String name) {
		return settings.getString(name);
	}

	@Override
	public byte[] getByteArray(String name) {
		return settings.getByteArray(name);
	}

	@Override
	public Object getValue(String name) {
		return settings.getValue(name);
	}

	@Override
	public void setLong(String name, long value) {
		settings.setLong(name, value);
	}

	@Override
	public void setString(String name, String value) {
		settings.setString(name, value);
	}

	@Override
	public void setByteArray(String name, byte[] value) {
		settings.setByteArray(name, value);
	}

	@Override
	public void setValue(String name, Object value) {
		settings.setValue(name, value);
	}

	@Override
	public void clearSetting(String name) {
		settings.clearSetting(name);
	}

	@Override
	public void clearAllSettings() {
		settings.clearAllSettings();
	}

	@Override
	public String[] getNames() {
		return settings.getNames();
	}

	@Override
	public boolean isEmpty() {
		return settings.isEmpty();
	}

	@Override
	public Settings getDefaultSettings() {
		return settings.getDefaultSettings();
	}

}
