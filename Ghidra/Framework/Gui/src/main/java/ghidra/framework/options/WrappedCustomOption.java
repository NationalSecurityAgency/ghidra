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

import ghidra.util.Msg;

public class WrappedCustomOption implements WrappedOption {

	private CustomOption value;
	private boolean valid;

	public WrappedCustomOption(CustomOption value) {
		this();
		this.value = value;
	}

	public WrappedCustomOption() {
		this.valid = true;
	}

	@Override
	public void readState(SaveState saveState) {
		String customOptionClassName = saveState.getString("CUSTOM OPTION CLASS", null);
		valid = false;
		try {
			Class<?> c = Class.forName(customOptionClassName);
			value = (CustomOption) c.getConstructor().newInstance();
			value.readState(saveState);
			valid = true;
		}
		catch (ClassNotFoundException e) {
			Msg.info(this,
				"Custom option class '%s' does not exist".formatted(customOptionClassName));
		}
		catch (Exception e) {
			Msg.error(this, "Can't create customOption instance for: " + customOptionClassName, e);
		}
	}

	public boolean isValid() {
		return valid;
	}

	@Override
	public void writeState(SaveState saveState) {
		saveState.putString("CUSTOM OPTION CLASS", value.getClass().getName());
		value.writeState(saveState);
	}

	@Override
	public Object getObject() {
		return value;
	}

	@Override
	public OptionType getOptionType() {
		return OptionType.CUSTOM_TYPE;
	}

}
