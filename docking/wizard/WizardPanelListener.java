/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package docking.wizard;

/**
 * Listener that is called when something on the WizardPanel has
 * changed.
 */
public interface WizardPanelListener {
	/**
	 * Notification that something on the panel changed.
	 */
	public void validityChanged();

	/**
	 * Notification to set a status message.
	 * @param msg message
	 */
	public void setStatusMessage(String msg);
}
