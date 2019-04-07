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
package docking;

import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;

import javax.swing.KeyStroke;

/**
 * An implementation of {@link KeyStrokeConsumer} that checks to see if a given {@link KeyStroke}
 * is valid for performing lookup on trees and tables.
 */
public class AutoLookupKeyStrokeConsumer implements KeyStrokeConsumer {

	@Override
	public boolean isKeyConsumed(KeyStroke keyStroke) {
		int modifier = keyStroke.getModifiers();
		if ((modifier & InputEvent.CTRL_DOWN_MASK) == InputEvent.CTRL_DOWN_MASK) {
			return false;
		}

		if ((modifier & InputEvent.META_DOWN_MASK) == InputEvent.META_DOWN_MASK) {
			return false;
		}

		int code = keyStroke.getKeyCode();
		if (code >= KeyEvent.VK_COMMA && code < KeyEvent.VK_DELETE) {
			if (modifier == 0 ||
				(modifier & InputEvent.SHIFT_DOWN_MASK) == InputEvent.SHIFT_DOWN_MASK) {
				return true;
			}
		}
		return false;
	}

}
