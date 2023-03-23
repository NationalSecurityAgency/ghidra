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

import java.beans.PropertyEditor;
import java.io.File;
import java.io.IOException;

import org.apache.commons.io.FilenameUtils;

import ghidra.util.HelpLocation;
import ghidra.util.Msg;

public class FileOptions extends AbstractOptions {

	private File file;

	public FileOptions(String name) {
		super(name);
	}

	public FileOptions(File file) throws IOException {
		this(FilenameUtils.getBaseName(file.getName()));
		this.file = file;
		loadFromFile();
	}

	public void save(File saveFile) throws IOException {
		this.name = FilenameUtils.getBaseName(saveFile.getName());
		this.file = saveFile;
		saveToFile();
	}

	public File getFile() {
		return file;
	}

	public CustomOption readCustomOption(SaveState saveState) {
		String customOptionClassName = saveState.getString("CUSTOM_OPTION_CLASS", null);
		try {
			Class<?> c = Class.forName(customOptionClassName);
			CustomOption customOption = (CustomOption) c.getDeclaredConstructor().newInstance();
			customOption.readState(saveState);
			return customOption;
		}
		catch (Exception e) {
			Msg.error(this, "Can't create customOption instance for: " + customOptionClassName, e);
		}
		return null;
	}

	private void loadFromFile() throws IOException {
		SaveState saveState = SaveState.readJsonFile(file);
		for (String optionName : saveState.getNames()) {
			Object object = saveState.getObject(optionName);
			if (object instanceof SaveState) {
				SaveState customState = (SaveState) object;
				object = readCustomOption(customState);
			}
			Option option =
				createUnregisteredOption(optionName, OptionType.getOptionType(object), null);
			option.doSetCurrentValue(object);  // use doSet versus set so that it is not registered
			valueMap.put(optionName, option);
		}
	}

	private void saveToFile() throws IOException {
		SaveState saveState = new SaveState("File_Options");

		for (String optionName : valueMap.keySet()) {
			Option optionValue = valueMap.get(optionName);
			if (!optionValue.isDefault()) {
				Object value = optionValue.getValue(null);
				if (value instanceof CustomOption) {
					SaveState customState = new SaveState();
					customState.putString("CUSTOM_OPTION_CLASS", value.getClass().getName());
					((CustomOption) value).writeState(customState);
					value = customState;
				}
				saveState.putObject(optionName, value);
			}
		}
		saveState.saveToJsonFile(file);
	}

	@Override
	protected Option createRegisteredOption(String optionName, OptionType type, String description,
			HelpLocation help, Object defaultValue, PropertyEditor editor) {
		return new FileOption(optionName, type, description, help, defaultValue, true, editor);
	}

	@Override
	protected Option createUnregisteredOption(String optionName, OptionType type,
			Object defaultValue) {
		return new FileOption(optionName, type, null, null, defaultValue, false, null);
	}

	@Override
	protected boolean notifyOptionChanged(String optionName, Object oldValue, Object newValue) {
		// do nothing for now
		return true;
	}

	private static class FileOption extends Option {
		private Object currentValue;

		FileOption(String name, OptionType type, String description, HelpLocation helpLocation,
				Object defaultValue, boolean isRegistered, PropertyEditor editor) {
			super(name, type, description, helpLocation, defaultValue, isRegistered, editor);

			this.currentValue = defaultValue;
		}

		@Override
		public Object getCurrentValue() {
			return currentValue;
		}

		@Override
		public void doSetCurrentValue(Object value) {
			currentValue = value;
		}
	}

	@Override
	public String toString() {
		return name;
	}

	public FileOptions copy() {
		FileOptions copy = new FileOptions("new");

		for (String optionName : valueMap.keySet()) {
			Option optionValue = valueMap.get(optionName);
			if (!optionValue.isDefault()) {
				Object value = optionValue.getValue(null);
				copy.putObject(optionName, value);
			}
		}

		return copy;
	}
}
