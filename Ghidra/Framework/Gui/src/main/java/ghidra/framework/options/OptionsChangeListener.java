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

import ghidra.util.bean.opteditor.OptionsVetoException;

/**
 * Interface for notifying listeners when options change.
 * <p>
 * Register with {@link ToolOptions#addOptionsChangeListener(OptionsChangeListener)}.
 */
public interface OptionsChangeListener {

	/**
	 * Notification that an option changed.
	 * <p>
	 * Note: to reject an options change, you can throw a 
	 * {@link OptionsVetoException}.
	 * 
	 * @param options options object containing the property that changed
	 * @param optionName name of option that changed
	 * @param oldValue old value of the option
	 * @param newValue new value of the option
	 * @throws OptionsVetoException if a change is rejected
	 */
	public void optionsChanged(ToolOptions options, String optionName, Object oldValue,
			Object newValue) throws OptionsVetoException;
}
