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
package docking.widgets.fieldpanel.listener;
import javax.swing.JComponent;

/**
 * Interface implemented by objects that want to be notified when an overlay
 * is removed from the FieldPanel.
 */
public interface FieldOverlayListener {

	/**
	 * Called when the an existing component is removed from the FieldPanel.
	 * @param comp the overlay component that was removed.
	 */
	void fieldOverlayRemoved(JComponent comp);
}
