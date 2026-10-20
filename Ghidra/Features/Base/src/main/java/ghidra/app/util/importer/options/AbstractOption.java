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
package ghidra.app.util.importer.options;

import ghidra.app.util.Option;

/**
 * An {@link Option} that is specific to a value type
 *
 * @param <T> The {@link Option} value type
 */
public abstract class AbstractOption<T> extends Option {

	/**
	 * A typed value that must stay synchronized with the parent {@link Option}'s {@code value}. 
	 * This allows clients to work with the proper value type instead of a generic {@link Object}.
	 */
	private T value;

	/**
	 * Construct a new {@link AbstractOption}
	 *
	 * @param name the name of the option
	 * @param valueClass valueClass the type of the option value, which should match {@code <T>}
	 * @param value the value of the option (could be {@code null})
	 * @param arg the option's command line argument (could be {@code null})
	 * @param group the name for group of options (could be {@code null})
	 * @param stateKey the state key name (could be {@code null})
	 * @param hidden true if this option should be hidden from the user; otherwise, false
	 * @param description a description of the option (could be {@code null})
	 */
	AbstractOption(String name, Class<T> valueClass, T value, String arg, String group,
			String stateKey, boolean hidden, String description) {
		super(name, valueClass, value, arg, group, stateKey, hidden, description);
		this.value = value;
	}

	@Override
	public T getValue() {
		return value;
	}

	@Override
	@SuppressWarnings("unchecked")
	public void setValue(Object v) throws IllegalArgumentException {
		this.value = (T) v; // must do this first, since super.setValue() calls the change listener
		super.setValue(v);
	}

	@Override
	public abstract AbstractOption<T> copy();
}
