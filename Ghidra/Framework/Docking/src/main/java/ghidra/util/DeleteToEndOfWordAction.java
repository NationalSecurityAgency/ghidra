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
 * An action to delete from the cursor position to the end of the current word.
 */
public class DeleteToEndOfWordAction extends TextAction {

	public static final KeyStroke KEY_STROKE = KeyStroke.getKeyStroke(KeyEvent.VK_DELETE,
		DockingUtils.CONTROL_KEY_MODIFIER_MASK);
	private static final String ACTION_NAME = "delete-to-end-of-word-word";

	public DeleteToEndOfWordAction() {
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
			int wordEndIndex = getEndOfWordIndex(textComponent, selectionStartIndex);

			if (wordEndIndex != selectionEndIndex) {
				document.remove(selectionStartIndex, wordEndIndex - selectionStartIndex);
			}
			else if (caretIndex > 0) {
				error(textComponent);
			}
		}
		catch (BadLocationException ble) {
			error(textComponent);
		}
	}

	private int getEndOfWordIndex(JTextComponent textComponent, int offset)
			throws BadLocationException {

		Element currentParagraph = Utilities.getParagraphElement(textComponent, offset);
		int currentParagraphEndOffset = currentParagraph.getEndOffset();
		int currentParagraphEnd = currentParagraphEndOffset - 1;
		if (textComponent instanceof JPasswordField) {
			return currentParagraphEnd;
		}

		int wordOffset = offset;
		try {
			int startOfNextWord = Utilities.getNextWord(textComponent, offset);
			int endOfCurrentWord = Utilities.getWordEnd(textComponent, offset);
			boolean isWhiteSpace = startOfNextWord == endOfCurrentWord;
			if (isWhiteSpace) {
				wordOffset = Utilities.getWordEnd(textComponent, startOfNextWord);
			}
			else {
				wordOffset = endOfCurrentWord;
			}

			if (wordOffset >= currentParagraphEndOffset && offset != currentParagraphEnd) {
				wordOffset = currentParagraphEnd;
			}
		}
		catch (BadLocationException ble) {
			Document document = textComponent.getDocument();
			int documentEnd = document.getLength();
			if (wordOffset != documentEnd) {
				if (offset != currentParagraphEnd) {
					wordOffset = currentParagraphEnd;
				}
				else {
					wordOffset = documentEnd;
				}
			}
			else {
				throw ble;
			}
		}
		return wordOffset;
	}

}
