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
package ghidra.framework.main;

import java.awt.Color;
import java.awt.Font;
import java.util.LinkedList;

import javax.swing.JTextPane;
import javax.swing.text.*;

import ghidra.framework.options.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.Msg;
import ghidra.util.SystemUtilities;
import ghidra.util.exception.AssertException;
import ghidra.util.task.SwingUpdateManager;

/** 
 * A generic text pane that is used as a console to which text can be written.
 * 
 * There is not test for this class, but it is indirectly tested by FrontEndGuiTest.
 */
public class ConsoleTextPane extends JTextPane implements OptionsChangeListener {

	private static final String CUSTOM_ATTRIBUTE_KEY = ConsoleTextPane.class.getName();
	private static final String OUTPUT_ATTRIBUTE_VALUE = "OUTPUT";
	private static final String ERROR_ATTRIBUTE_VALUE = "ERROR";

	private static final String OPTIONS_NAME = "Console";
	private static final String MAXIMUM_CHARACTERS_OPTION_NAME = "Character Limit";
	private static final String TRUNCATION_FACTOR_OPTION_NAME = "Truncation Factor";
	private static final int DEFAULT_MAXIMUM_CHARS = 50000;
	private static final int MINIMUM_MAXIMUM_CHARS = 1000;
	private static final int MAX_UPDATE_INTERVAL_MS = 100;

	/** % of characters to delete when truncation is necessary */
	private static double DEFAULT_TRUNCATION_FACTOR = .10;

	private static SimpleAttributeSet outputAttributeSet;
	private static SimpleAttributeSet errorAttributeSet;

	// don't update more than once per second if lots of messages are being written
	private SwingUpdateManager updateManager = new SwingUpdateManager(100, 1000, () -> doUpdate());

	private LinkedList<MessageWrapper> messageList = new LinkedList<>();

	private boolean scrollLock;
	private int maximumCharacterLimit = DEFAULT_MAXIMUM_CHARS;
	private double truncationFactor = DEFAULT_TRUNCATION_FACTOR;

	public ConsoleTextPane(PluginTool tool) {
		createAttribtues();
		setEditable(true);

		ToolOptions options = tool.getOptions(OPTIONS_NAME);
		options.addOptionsChangeListener(this);
		initOptions(options);
	}

	public void setScrollLock(boolean lock) {
		this.scrollLock = lock;
		updateCaretSelectionPolicy(lock);
	}

	public void addMessage(String message) {
		doAddMessage(new MessageWrapper(message));
	}

	public void addPartialMessage(String message) {
		doAddMessage(new MessageWrapper(message));
	}

	public void addErrorMessage(String message) {
		doAddMessage(new ErrorMessage(message));
	}

	@Override
	public void optionsChanged(ToolOptions options, String name, Object oldValue, Object newValue) {
		if (MAXIMUM_CHARACTERS_OPTION_NAME.equals(name) ||
			TRUNCATION_FACTOR_OPTION_NAME.equals(name)) {
			updateFromOptions(options);
		}
	}
//==================================================================================================
// Non-interface Methods
//==================================================================================================    

	private void initOptions(Options options) {
		options.registerOption(MAXIMUM_CHARACTERS_OPTION_NAME, DEFAULT_MAXIMUM_CHARS, null,
			"The maximum number of " +
				"characters to display before truncating characters from the top of the console.");

		options.registerOption(TRUNCATION_FACTOR_OPTION_NAME, DEFAULT_TRUNCATION_FACTOR, null,
			"The factor (when multiplied by the " + MAXIMUM_CHARACTERS_OPTION_NAME +
				") by which to remove characters when truncating is necessary.");

		updateFromOptions(options);
	}

	private void updateFromOptions(Options options) {
		int newLimit = options.getInt(MAXIMUM_CHARACTERS_OPTION_NAME, DEFAULT_MAXIMUM_CHARS);
		truncationFactor = options.getDouble(TRUNCATION_FACTOR_OPTION_NAME, DEFAULT_TRUNCATION_FACTOR);
		setMaximumCharacterLimit(newLimit);
	}

	void setMaximumCharacterLimit(int limit) {
		maximumCharacterLimit = Math.max(limit, MINIMUM_MAXIMUM_CHARS);
	}

	int getMaximumCharacterLimit() {
		return maximumCharacterLimit;
	}

	// keeps the caret from automatically scrolling to the bottom
	private void updateCaretSelectionPolicy(boolean lockSelection) {
		Caret caret = getCaret();
		if (caret instanceof DefaultCaret) {
			DefaultCaret defaultCaret = (DefaultCaret) caret;
			if (lockSelection) {
				defaultCaret.setUpdatePolicy(DefaultCaret.NEVER_UPDATE);
			}
			else {
				defaultCaret.setUpdatePolicy(DefaultCaret.ALWAYS_UPDATE);
			}
		}
	}

	private void doAddMessage(MessageWrapper newMessage) {
		synchronized (messageList) {
			if ( !messageList.isEmpty() ) {
				MessageWrapper lastMessage = messageList.getLast();
				if (lastMessage.merge(newMessage)) {
					return;
				}
			}
			messageList.add(newMessage);
		}
		updateManager.update();
	}

	@Override
	public void setFont(Font font) {
		createAttributes(font);
		updateCurrentTextWithNewFont();

		super.setFont(font);
	}

	private void updateCurrentTextWithNewFont() {
		Document document = getDocument();

		if (document == null) {
			return;
		}

		SystemUtilities.assertTrue(document instanceof StyledDocument,
			getClass().getName() + " is designed to work with StyledDocuments");

		StyledDocument styledDocument = (StyledDocument) document;
		int length = document.getLength();
		for (int i = 0; i < length;) {
			Element element = styledDocument.getCharacterElement(i);
			int elementStart = i;
			int elementLen = element.getEndOffset() - elementStart;
			i = element.getEndOffset();

			// get the name of the old AttributeSet and use that to pick the new live
			// AttributeSet that was updated.
			AttributeSet replacementAttributeSet = getAttributeSetByName(
				(String) element.getAttributes().getAttribute(CUSTOM_ATTRIBUTE_KEY));
			styledDocument.setCharacterAttributes(elementStart, elementLen, replacementAttributeSet,
				true);
		}
	}

	private AttributeSet getAttributeSetByName(String attributeSetName) {
		if (OUTPUT_ATTRIBUTE_VALUE.equals(attributeSetName)) {
			return outputAttributeSet;
		}
		else if (ERROR_ATTRIBUTE_VALUE.equals(attributeSetName)) {
			return errorAttributeSet;
		}
		else {
			// we found an attribute type that we do not know about
			throw new AssertException("Unexpected attribute type for text");
		}
	}

	private void createAttribtues() {
		createAttributes(new Font("monospaced", Font.PLAIN, 12));
	}

	private void createAttributes(Font font) {
		outputAttributeSet = new SimpleAttributeSet();
		outputAttributeSet.addAttribute(CUSTOM_ATTRIBUTE_KEY, OUTPUT_ATTRIBUTE_VALUE);
		outputAttributeSet.addAttribute(StyleConstants.FontFamily, font.getFamily());
		outputAttributeSet.addAttribute(StyleConstants.FontSize, font.getSize());
		outputAttributeSet.addAttribute(StyleConstants.Italic, font.isItalic());
		outputAttributeSet.addAttribute(StyleConstants.Bold, font.isBold());
		outputAttributeSet.addAttribute(StyleConstants.Foreground, Color.BLACK);

		errorAttributeSet = new SimpleAttributeSet();
		errorAttributeSet.addAttribute(CUSTOM_ATTRIBUTE_KEY, ERROR_ATTRIBUTE_VALUE);
		errorAttributeSet.addAttribute(StyleConstants.FontFamily, font.getFamily());
		errorAttributeSet.addAttribute(StyleConstants.FontSize, font.getSize());
		errorAttributeSet.addAttribute(StyleConstants.Italic, font.isItalic());
		errorAttributeSet.addAttribute(StyleConstants.Bold, font.isBold());
		errorAttributeSet.addAttribute(StyleConstants.Foreground, Color.RED);
	}

	private void doUpdate() {
		long stopMS = System.currentTimeMillis() + MAX_UPDATE_INTERVAL_MS;

		// track the caret manually because removing the text where the caret is located
		// will reset the caret position to 0, even with the update police NEVER_UPDATE.
		int caretPos = getCaretPosition();
		boolean caretInvalidated = false;
		synchronized (messageList) {
			// Holding the sync lock on the messageList will block the thread producing
			// messages while we clear the queue.  This is desirable to throttle a run-away
			// GhidraScript.
			while (!messageList.isEmpty() && (System.currentTimeMillis() < stopMS)) {
				MessageWrapper msg = messageList.removeFirst();
				caretInvalidated |= appendString(msg.getMessage(), msg.getAttributes());
			}
			if (!messageList.isEmpty()) {
				updateManager.updateLater();
			}
		}
		if (!scrollLock || caretInvalidated) {
			// manually set the caret position because it was
			// 1) invalidated (even though scroll lock was true), or
			// 2) is tracking the bottom of the console (normal mode)
			int newDocLen = getDocument().getLength();
			setCaretPosition(scrollLock ? Math.min(caretPos, newDocLen) : newDocLen);
		}
	}

	private boolean appendString(CharSequence message, AttributeSet attributeSet) {

		// cap message size before update
		if (message.length() > maximumCharacterLimit) {
			int delta = message.length() - maximumCharacterLimit;
			message = message.subSequence(delta, message.length());
		}

		try {
			Document document = getDocument();
			int overage = document.getLength() + message.length() - maximumCharacterLimit;
			if (overage <= 0) {
				document.insertString(document.getLength(), message.toString(), attributeSet);
				return false;
			}

			// trim the excess text that will result when inserting the new message
			int truncationAmount = (int) (maximumCharacterLimit * truncationFactor);
			int docToTrim = Math.min(overage + truncationAmount, document.getLength());
			int caretPos = getCaretPosition();
			document.remove(0, docToTrim);
			document.insertString(document.getLength(), message.toString(), attributeSet);
			return caretPos < docToTrim;
		}
		catch (BadLocationException e) {
			Msg.debug(this, "Unexpected exception updating text", e);
			return false;
		}
	}

	public void dispose() {
		updateManager.dispose();
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private static class MessageWrapper {
		private final StringBuilder message;

		private MessageWrapper(String message) {
			if (message == null) {
				throw new AssertException("Attempted to log a null message.");
			}
			this.message = new StringBuilder(message);
		}

		CharSequence getMessage() {
			return message;
		}

		boolean merge(MessageWrapper other) {
			if (getClass() != other.getClass()) {
				return false;
			}
			message.append(other.message);
			return true;
		}

		AttributeSet getAttributes() {
			return outputAttributeSet;
		}
	}

	private static class ErrorMessage extends MessageWrapper {
		private ErrorMessage(String message) {
			super(message);
		}

		@Override
		AttributeSet getAttributes() {
			return errorAttributeSet;
		}
	}

}
