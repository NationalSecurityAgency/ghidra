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
package docking.menu;

/**
 * Defines one "state" for a {@link MultiStateButton}. Each button state represents one choice from
 * a drop-down list of choices on the button. Each state provides information on what the button
 * text should be when it is the active state, the text in the drop-down for picking the state, text
 * for a tooltip description, and finally client data that the client can use to store info for
 * processing the action when that state is active.
 *
 * @param <T> the type of the client data object.
 */
public class ButtonState<T> {
	private String buttonText;
	private String menuText;
	private String description;
	private T clientData;

	/**
	 * Constructor
	 * @param buttonText the text to display as both the drop-down choice and the active button text
	 * @param description the tooltip for this state
	 * @param clientData the client data for this state
	 */
	public ButtonState(String buttonText, String description, T clientData) {
		this(buttonText, buttonText, description, clientData);
	}

	/**
	 * Constructor
	 * @param buttonText the text to display in the button when this state is active
	 * @param menuText the text to display in the drop-down list
	 * @param description the tooltip for this state
	 * @param clientData the client data for this state
	 */
	public ButtonState(String buttonText, String menuText, String description, T clientData) {
		this.buttonText = buttonText;
		this.menuText = menuText;
		this.description = description;
		this.clientData = clientData;
	}

	public String getButtonText() {
		return buttonText;
	}

	public String getMenuText() {
		return menuText;
	}

	public String getDescription() {
		return description;
	}

	public T getClientData() {
		return clientData;
	}

}
