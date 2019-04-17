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
package docking.widgets.autocomplete;

/**
 * A listener for autocompletion events.
 * 
 * @param <T> the type of suggestions presented by the autocompleter.
 * @see TextFieldAutocompleter
 */
public interface AutocompletionListener<T> {
	/**
	 * The user has activated a suggested item.
	 * 
	 * This means the user has explicitly activate the item, i.e., pressed enter on or clicked the
	 * item.
	 * @param e the event describing the activation
	 */
	public void completionActivated(AutocompletionEvent<T> e);
}
