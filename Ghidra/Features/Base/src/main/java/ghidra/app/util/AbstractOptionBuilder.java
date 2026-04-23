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
package ghidra.app.util;

import ghidra.app.util.importer.options.AbstractOption;

/**
 * A class to build {@link AbstractOption}s
 * 
 * @param <ValueType> The option value type
 * @param <OptionType> The build option type
 */
public abstract class AbstractOptionBuilder<ValueType, OptionType extends AbstractOption<ValueType>> {

	protected String name;
	protected String group;
	protected ValueType value;
	protected String commandLineArgument;
	protected String description;
	protected String stateKey;
	protected boolean hidden;

	/**
	 * Creates a new {@link AbstractOptionBuilder}
	 * 
	 * @param name The name of the {@link Option} to be built
	 */
	public AbstractOptionBuilder(String name) {
		this.name = name;
	}

	/**
	 * Sets the {@link Option}'s group
	 * 
	 * @param g The {@link Option}'s group
	 * @return This {@link AbstractOptionBuilder}
	 */
	public AbstractOptionBuilder<ValueType, OptionType> group(String g) {
		this.group = g;
		return this;
	}

	/**
	 * Sets the {@link Option}'s value
	 * 
	 * @param v The {@link Option}'s value
	 * @return This {@link AbstractOptionBuilder}
	 */
	public AbstractOptionBuilder<ValueType, OptionType> value(ValueType v) {
		this.value = v;
		return this;
	}

	/**
	 * Sets the {@link Option}'s command line argument
	 * 
	 * @param arg The {@link Option}'s command line argument
	 * @return This {@link AbstractOptionBuilder}
	 */
	public AbstractOptionBuilder<ValueType, OptionType> commandLineArgument(String arg) {
		this.commandLineArgument = arg;
		return this;
	}

	/**
	 * Sets the {@link Option}'s description
	 * 
	 * @param desc The {@link Option}'s description
	 * @return This {@link AbstractOptionBuilder}
	 */
	public AbstractOptionBuilder<ValueType, OptionType> description(String desc) {
		this.description = desc;
		return this;
	}

	/**
	 * Sets the {@link Option}'s state key
	 * 
	 * @param key The {@link Option}'s state key
	 * @return This {@link AbstractOptionBuilder}
	 */
	public AbstractOptionBuilder<ValueType, OptionType> stateKey(String key) {
		this.stateKey = key;
		return this;
	}

	/**
	 * Sets whether or not the {@link Option} is hidden
	 * 
	 * @param hide True if the {@link Option} should be hidden; otherwise, false
	 * @return This {@link AbstractOptionBuilder}
	 */
	public AbstractOptionBuilder<ValueType, OptionType> hidden(boolean hide) {
		this.hidden = hide;
		return this;
	}

	/**
	 * {@return a new {@link AbstractOption} based on the current state of this 
	 * {@link AbstractOptionBuilder}}
	 */
	public abstract OptionType build();
}
