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
package ghidra.util;

import java.awt.Component;
import java.awt.event.*;

import javax.swing.KeyStroke;
import javax.swing.UIManager;
import javax.swing.text.*;

public class SelectEndOfLineAction extends TextAction {

	public static final KeyStroke KEY_STROKE = KeyStroke.getKeyStroke(KeyEvent.VK_END,
		InputEvent.SHIFT_DOWN_MASK);
	private static final String ACTION_NAME = "selection-end-line";

	public SelectEndOfLineAction() {
		super(ACTION_NAME);
	}

	private void error(Component component) {
		UIManager.getLookAndFeel().provideErrorFeedback(component);
	}

	@Override
	public void actionPerformed(ActionEvent e) {
		JTextComponent component = getTextComponent(e);
		if (component == null) {
			return;
		}

		try {
			int dot = component.getCaretPosition();
			int endPosition = Utilities.getRowEnd(component, dot);
			component.moveCaretPosition(endPosition);
		}
		catch (BadLocationException bl) {
			error(component);
		}

	}
}
