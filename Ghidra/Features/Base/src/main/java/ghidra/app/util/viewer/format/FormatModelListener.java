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
package ghidra.app.util.viewer.format;

/**
 * Interface for listeners to format model changes.
 */
public interface FormatModelListener {

	/**
	 * Format model added. Not used.
	 * @param model the model that was added
	 * @deprecated not used
	 */
	@Deprecated(since = "11.2", forRemoval = true)
	default void formatModelAdded(FieldFormatModel model) {
		// not used
	}

	/**
	 * Format model removed. Not used.
	 * @param model the model that was added
	 * @deprecated not used
	 */
	@Deprecated(since = "11.2", forRemoval = true)
	default void formatModelRemoved(FieldFormatModel model) {
		// not used
	}

	/**
	 * Notifies that the given format model was changed.
	 * @param model the model that was changed.
	 */
	void formatModelChanged(FieldFormatModel model);
}
