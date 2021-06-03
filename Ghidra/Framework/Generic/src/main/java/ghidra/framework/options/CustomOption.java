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

public interface CustomOption {

	/**
	 * <code>SaveState</code> key which corresponds to custom option
	 * implementation class.  The use of this key/value within the stored
	 * state information is reserved for use by the option storage 
	 * implementation and should be ignored by {@link #readState(SaveState)}
	 * implementation
	 */
	public final String CUSTOM_OPTION_CLASS_NAME_KEY = "CUSTOM_OPTION_CLASS";

	/**
	 * Concrete subclass of WrappedOption should read all of its
	 * state from the given saveState object.
	 * @param saveState container of state information
	 */
	public void readState(SaveState saveState);

	/**
	 * Concrete subclass of WrappedOption should write all of its
	 * state to the given saveState object.
	 * @param saveState container of state information
	 */
	public void writeState(SaveState saveState);

	/**
	 * CustomOption should implement this method to provide a formatted 
	 * string value of this option value.  The returned value will 
	 * be used in support of the {@link Options#getValueAsString(String)}
	 * and {@link Options#getDefaultValueAsString(String)}.
	 * @return option value as string
	 */
	@Override
	public String toString();

}
