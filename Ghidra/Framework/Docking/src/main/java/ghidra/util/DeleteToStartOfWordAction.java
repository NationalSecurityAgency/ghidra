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
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;

import javax.swing.*;
import javax.swing.text.*;

import docking.DockingUtils;

/**
 * An action to delete from the cursor position to the beginning of the current word, backwards.
 */
public class DeleteToStartOfWordAction extends TextAction {

	public static final KeyStroke KEY_STROKE = KeyStroke.getKeyStroke(KeyEvent.VK_BACK_SPACE,
		DockingUtils.CONTROL_KEY_MODIFIER_MASK);
	private static final String ACTION_NAME = "delete-to-start-of-word";

	public DeleteToStartOfWordAction() {
		super(ACTION_NAME);
	}

	private void error(Component component) {
		UIManager.getLookAndFeel().provideErrorFeedback(component);
	}

	@Override
	public void actionPerformed(ActionEvent e) {
		JTextComponent textComponent = getTextComponent(e);
		if (textComponent == null || !textComponent.isEditable()) {
			error(textComponent);
			return;
		}

		try {
			Document document = textComponent.getDocument();
			Caret caret = textComponent.getCaret();
			int caretIndex = caret.getDot();
			int markIndex = caret.getMark();

			int selectionStartIndex = Math.min(caretIndex, markIndex);
			int selectionEndIndex = Math.max(caretIndex, markIndex);
			int wordStartIndex = getStartOfWordIndex(textComponent, selectionStartIndex);

			if (wordStartIndex != selectionEndIndex) {
				document.remove(wordStartIndex, selectionEndIndex - wordStartIndex);
			}
			else if (caretIndex > 0) {
				error(textComponent);
			}
		}
		catch (BadLocationException ble) {
			error(textComponent);
		}
	}

	private int getStartOfWordIndex(JTextComponent textComponent, int offset)
			throws BadLocationException {

		if (textComponent instanceof JPasswordField) {
			return 0;
		}

		Element currentParagraph = Utilities.getParagraphElement(textComponent, offset);
		int previousWordOffset = Utilities.getPreviousWord(textComponent, offset);
		boolean isInPreviousParagraph = previousWordOffset < currentParagraph.getStartOffset();
		if (isInPreviousParagraph) {
			Element previousParagraphElement =
				Utilities.getParagraphElement(textComponent, previousWordOffset);
			return previousParagraphElement.getEndOffset() - 1;
		}
		return previousWordOffset;
	}

}
