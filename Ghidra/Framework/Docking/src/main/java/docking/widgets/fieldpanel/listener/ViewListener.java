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
package docking.widgets.fieldpanel.listener;

import java.math.BigInteger;

import docking.widgets.fieldpanel.FieldPanel;

/**
 * Listener interface for notification when the top of screen position changes.
 */
public interface ViewListener {
	/**
	 * Notifies the listener that the top of the screen has changed position.
	 * @param fp the field panel whose view changed.
	 * @param index the index of the layout at the top of the screen.
	 * @param xOffset the x coordinate of the layout displayed at the left of the
	 * screen.
	 * @param yOffset the y coordinate of the layout displayed at the top of the
	 * screen.
	 */
	public void viewChanged(FieldPanel fp, BigInteger index, int xOffset, int yOffset);

}
