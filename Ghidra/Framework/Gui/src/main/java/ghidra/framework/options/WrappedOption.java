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

/**
 * Wrapper class for an object that represents a property value and is saved as a set of primitives.
 */
public interface WrappedOption {

	/**
	 * {@return Get the object that is the property value}
	 */
	public abstract Object getObject();

	/**
	 * Subclasses of WrappedOption should read all state from the given save state object.
	 * @param saveState container of state information
	 */
	public abstract void readState(SaveState saveState);

	/**
	 * Subclasses of WrappedOption should write all state to the given save state object.
	 * @param saveState container of state information
	 */
	public abstract void writeState(SaveState saveState);

	/**
	 * {@return the option type}
	 */
	public abstract OptionType getOptionType();
}
