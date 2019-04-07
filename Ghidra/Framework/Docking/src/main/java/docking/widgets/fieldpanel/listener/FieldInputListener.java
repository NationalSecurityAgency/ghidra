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
import java.awt.event.KeyEvent;
import java.math.BigInteger;

import docking.widgets.fieldpanel.field.Field;

/**
 * Interface implemented by objects that want to be notified when key events occur
 * in the FieldPanel.
 */
public interface FieldInputListener {

	/**
	 * Called the the FieldPanel receives a KeyEvent that it doesn't handle.
	 * @param ev The KeyEvent generated when the user presses a key.
	 * @param index the index of the layout the cursor was on when the key was pressed.
	 * @param fieldNum the field index of the field the cursor was on when the key was
	 * pressed.
	 * @param row the row in the field the cursor was on when the key was pressed.
	 * @param col the col in the field the cursor was on when the key was pressed.
     * @param field current field the cursor was on when the
     * key was pressed.
	 */
	void keyPressed(KeyEvent ev, BigInteger index, int fieldNum, int row, int col,
                        Field field);
}
