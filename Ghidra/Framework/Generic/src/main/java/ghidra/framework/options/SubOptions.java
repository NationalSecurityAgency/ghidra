/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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

import ghidra.util.HelpLocation;

import java.awt.Color;
import java.awt.Font;
import java.beans.PropertyEditor;
import java.io.File;
import java.util.*;

import javax.swing.KeyStroke;

public class SubOptions implements Options {

	private AbstractOptions options;
	private String prefix;
	private String name;

	public SubOptions(AbstractOptions options, String name, String prefix) {
		this.options = options;
		this.name = name;
		this.prefix = prefix;
	}

	@Override
	public String getName() {
		return name;
	}

	@Override
	public String toString() {
		return name;
	}

	@Override
	public PropertyEditor getPropertyEditor(String optionName) {
		return options.getPropertyEditor(prefix + optionName);
	}

	@Override
	public PropertyEditor getRegisteredPropertyEditor(String optionName) {
		return options.getRegisteredPropertyEditor(prefix + optionName);
	}

	@Override
	public List<Options> getChildOptions() {
		List<String> optionPaths = getOptionNames();
		Set<String> childCategories = AbstractOptions.getChildCategories(optionPaths);
		List<Options> childOptions = new ArrayList<Options>(childCategories.size());
		for (String categoryName : childCategories) {
			childOptions.add(new SubOptions(options, categoryName, prefix + categoryName +
				DELIMITER));
		}
		return childOptions;
	}

	@Override
	public HelpLocation getHelpLocation(String optionName) {
		return options.getHelpLocation(prefix + optionName);
	}

	@Override
	public void registerOption(String optionName, Object defaultValue, HelpLocation help,
			String description) {
		options.registerOption(prefix + optionName, defaultValue, help, description);
	}

	@Override
	public void registerOption(String optionName, OptionType type, Object defaultValue,
			HelpLocation help, String description) {
		options.registerOption(prefix + optionName, type, defaultValue, help, description);
	}

	@Override
	public void registerOption(String optionName, OptionType type, Object defaultValue,
			HelpLocation help, String description, PropertyEditor editor) {
		options.registerOption(prefix + optionName, type, defaultValue, help, description, editor);
	}

	@Override
	public void putObject(String optionName, Object obj) {
		options.putObject(prefix + optionName, obj);
	}

	@Override
	public Object getObject(String optionName, Object defaultValue) {
		return options.getObject(prefix + optionName, defaultValue);
	}

	@Override
	public boolean getBoolean(String optionName, boolean defaultValue) {
		return options.getBoolean(prefix + optionName, defaultValue);
	}

	@Override
	public byte[] getByteArray(String optionName, byte[] defaultValue) {
		return options.getByteArray(prefix + optionName, defaultValue);
	}

	@Override
	public int getInt(String optionName, int defaultValue) {
		return options.getInt(prefix + optionName, defaultValue);
	}

	@Override
	public double getDouble(String optionName, double defaultValue) {
		return options.getDouble(prefix + optionName, defaultValue);
	}

	@Override
	public float getFloat(String optionName, float defaultValue) {
		return options.getFloat(prefix + optionName, defaultValue);
	}

	@Override
	public long getLong(String optionName, long defaultValue) {
		return options.getLong(prefix + optionName, defaultValue);
	}

	@Override
	public CustomOption getCustomOption(String optionName, CustomOption defaultValue) {
		return options.getCustomOption(prefix + optionName, defaultValue);
	}

	@Override
	public Color getColor(String optionName, Color defaultValue) {
		return options.getColor(prefix + optionName, defaultValue);
	}

	@Override
	public File getFile(String optionName, File defaultValue) {
		return options.getFile(prefix + optionName, defaultValue);
	}

	@Override
	public Font getFont(String optionName, Font defaultValue) {
		return options.getFont(prefix + optionName, defaultValue);
	}

	@Override
	public KeyStroke getKeyStroke(String optionName, KeyStroke defaultValue) {
		return options.getKeyStroke(prefix + optionName, defaultValue);
	}

	@Override
	public String getString(String optionName, String defaultValue) {
		return options.getString(prefix + optionName, defaultValue);
	}

	@Override
	public <T extends Enum<T>> T getEnum(String optionName, T defaultValue) {
		return options.getEnum(prefix + optionName, defaultValue);
	}

	@Override
	public void setLong(String optionName, long value) {
		options.setLong(prefix + optionName, value);
	}

	@Override
	public void setBoolean(String optionName, boolean value) {
		options.setBoolean(prefix + optionName, value);
	}

	@Override
	public void setInt(String optionName, int value) {
		options.setInt(prefix + optionName, value);
	}

	@Override
	public void setDouble(String optionName, double value) {
		options.setDouble(prefix + optionName, value);
	}

	@Override
	public void setFloat(String optionName, float value) {
		options.setFloat(prefix + optionName, value);
	}

	@Override
	public void setCustomOption(String optionName, CustomOption value) {
		options.setCustomOption(prefix + optionName, value);
	}

	@Override
	public void setByteArray(String optionName, byte[] value) {
		options.setByteArray(prefix + optionName, value);
	}

	@Override
	public void setFile(String optionName, File value) {
		options.setFile(prefix + optionName, value);
	}

	@Override
	public void setColor(String optionName, Color value) {
		options.setColor(prefix + optionName, value);
	}

	@Override
	public void setFont(String optionName, Font value) {
		options.setFont(prefix + optionName, value);
	}

	@Override
	public void setKeyStroke(String optionName, KeyStroke value) {
		options.setKeyStroke(prefix + optionName, value);
	}

	@Override
	public void setString(String optionName, String value) {
		options.setString(prefix + optionName, value);
	}

	@Override
	public <T extends Enum<T>> void setEnum(String optionName, T value) {
		options.setEnum(prefix + optionName, value);
	}

	@Override
	public void removeOption(String optionName) {
		options.removeOption(prefix + optionName);
	}

	@Override
	public List<String> getOptionNames() {
		List<String> allOptionPaths = options.getOptionNames();
		List<String> names = new ArrayList<String>();
		for (String path : allOptionPaths) {
			if (path.startsWith(prefix)) {
				names.add(path.substring(prefix.length()));
			}
		}
		return names;
	}

	@Override
	public boolean contains(String optionName) {
		return options.contains(prefix + optionName);
	}

	@Override
	public String getDescription(String optionName) {
		return options.getDescription(prefix + optionName);
	}

	@Override
	public boolean isRegistered(String optionName) {
		return options.isRegistered(prefix + optionName);
	}

	@Override
	public boolean isDefaultValue(String optionName) {
		return options.isDefaultValue(prefix + optionName);
	}

	@Override
	public void restoreDefaultValues() {
		List<String> optionNames = getOptionNames();
		for (String optionName : optionNames) {
			restoreDefaultValue(optionName);
		}
	}

	@Override
	public void restoreDefaultValue(String optionName) {
		options.restoreDefaultValue(prefix + optionName);
	}

	@Override
	public OptionType getType(String optionName) {
		return options.getType(prefix + optionName);
	}

	@Override
	public Options getOptions(String path) {
		int lastIndexOf = path.lastIndexOf(DELIMITER);
		String subOptionName = lastIndexOf > 0 ? path.substring(lastIndexOf + 1) : path;
		return new SubOptions(options, subOptionName, prefix + path + DELIMITER);
	}

	@Override
	public void setOptionsHelpLocation(HelpLocation helpLocation) {
		options.setCategoryHelpLocation(prefix, helpLocation);
	}

	@Override
	public HelpLocation getOptionsHelpLocation() {
		return options.getCategoryHelpLocation(prefix);
	}

	@Override
	public void registerOptionsEditor(OptionsEditor editor) {
		options.registerOptionsEditor(prefix, editor);
	}

	@Override
	public OptionsEditor getOptionsEditor() {
		return options.getOptionsEditor(prefix);
	}

	@Override
	public void createAlias(String aliasName, Options otherOptions, String optionsName) {
		options.createAlias(prefix + aliasName, otherOptions, optionsName);
	}

	@Override
	public boolean isAlias(String aliasName) {
		return options.isAlias(prefix + aliasName);
	}

	@Override
	public Date getDate(String optionName, Date defaultValue) {
		return options.getDate(prefix + optionName, defaultValue);
	}

	@Override
	public void setDate(String propertyName, Date value) {
		options.setDate(prefix + propertyName, value);
	}

	@Override
	public Object getDefaultValue(String optionName) {
		return options.getDefaultValue(prefix + optionName);
	}

	@Override
	public String getValueAsString(String optionName) {
		return options.getValueAsString(prefix + optionName);
	}

	@Override
	public String getDefaultValueAsString(String optionName) {
		return options.getDefaultValueAsString(prefix + optionName);
	}

	AbstractOptions getOptions() {
		return options;
	}

	String getPrefix() {
		return prefix;
	}

	@Override
	public String getID(String optionName) {
		return options.getID(prefix + optionName);
	}

	@Override
	public List<String> getLeafOptionNames() {
		List<String> optionPaths = getOptionNames();
		Set<String> leaves = AbstractOptions.getLeaves(optionPaths);
		return new ArrayList<String>(leaves);
	}

}
