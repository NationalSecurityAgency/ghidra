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

import javax.swing.JTextField;

/**
 * An event related to autocompletion, usually a completion being activated by the user.
 *
 * @param <T> the type of suggestions given by the autocompleter.
 * @see TextFieldAutocompleter
 */
public class AutocompletionEvent<T> {
	private T sel;
	private JTextField field;
	private boolean consumed;
	private boolean cancelled;

	/**
	 * Create a new event on the given selection and text field.
	 * @param sel the currently-selected (or activated) item.
	 * @param field the field having focus at the time of the event.
	 */
	public AutocompletionEvent(T sel, JTextField field) {
		this.sel = sel;
		this.field = field;
	}

	/**
	 * Get the item that was selected at the time of the event.
	 * 
	 * For activation, this is the activated suggestion.
	 * @return the selected suggestion.
	 */
	public T getSelection() {
		return sel;
	}

	/**
	 * Get the field having focus at the time of the event.
	 * 
	 * If the autocompleter is attached to multiple fields, this can be used to identify which
	 * field produced the event.
	 * @return the focused field
	 */
	public JTextField getField() {
		return field;
	}

	/**
	 * Prevent this event from being further processed.
	 * 
	 * The actual completion action will still be completed, though.
	 */
	public void consume() {
		this.consumed = true;
	}

	/**
	 * Check if this event has been consumed by an earlier listener.
	 * @return true if the event has been consumed, i.e., should not be further processed.
	 */
	public boolean isConsumed() {
		return consumed;
	}

	/**
	 * Prevent the actual completion action from taking place.
	 * 
	 * Further listeners may still process this event, though.
	 */
	public void cancel() {
		this.cancelled = true;
	}

	/**
	 * Check if the actual completion action will be performed.
	 * @return true if the completion action has been cancelled.
	 */
	public boolean isCancelled() {
		return cancelled;
	}
}
