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
import java.util.*;

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
	private static final String TRUNCTION_FACTOR_OPTION_NAME = "Truncation Factor";
	private static final int QUEUED_MESSAGE_LIMIT = 20;
	private static int MAXIMUM_CHARS = 50000;

	/** % of characters to delete when truncation is necessary */
	private static double TRUNCTION_FACTOR = .10;

	private static SimpleAttributeSet outputAttributeSet;
	private static SimpleAttributeSet errorAttributeSet;

	private SwingUpdateManager updateManager = new SwingUpdateManager(1, 500, () -> doUpdate());

	private List<MessageWrapper> messageList =
		Collections.synchronizedList(new LinkedList<MessageWrapper>());
	private ConsoleListener listener;

	private boolean scrollLock;
	private int maximumCharacterLimit = MAXIMUM_CHARS;
	private double truncationFactor = TRUNCTION_FACTOR;
	private int truncationAmount = (int) (MAXIMUM_CHARS * TRUNCTION_FACTOR);
	private int queuedMessageCount;

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

	public void setConsoleListener(ConsoleListener listener) {
		this.listener = listener;
	}

	public void addMessage(String message) {
		doAddMessage(new MessageWrapper(message, true));
	}

	public void addPartialMessage(String message) {
		doAddMessage(new MessageWrapper(message, false));
	}

	public void addErrorMessage(String message) {
		doAddMessage(new ErrorMessage(message, true));
	}

	@Override
	public void optionsChanged(ToolOptions options, String name, Object oldValue, Object newValue) {
		if (MAXIMUM_CHARACTERS_OPTION_NAME.equals(name) ||
			TRUNCTION_FACTOR_OPTION_NAME.equals(name)) {
			updateFromOptions(options);
		}
	}
//==================================================================================================
// Non-interface Methods
//==================================================================================================    

	private void initOptions(Options options) {
		options.registerOption(MAXIMUM_CHARACTERS_OPTION_NAME, MAXIMUM_CHARS, null,
			"The maximum number of " +
				"characters to display before truncating characters from the top of the console.");

		options.registerOption(TRUNCTION_FACTOR_OPTION_NAME, TRUNCTION_FACTOR, null,
			"The factor (when multiplied by the " + MAXIMUM_CHARACTERS_OPTION_NAME +
				") by which to remove characters when truncating is necessary.");

		updateFromOptions(options);
	}

	private void updateFromOptions(Options options) {
		int newLimit = options.getInt(MAXIMUM_CHARACTERS_OPTION_NAME, MAXIMUM_CHARS);
		truncationFactor = options.getDouble(TRUNCTION_FACTOR_OPTION_NAME, TRUNCTION_FACTOR);
		setMaximumCharacterLimit(newLimit);
	}

	void setMaximumCharacterLimit(int limit) {
		maximumCharacterLimit = limit;
		truncationAmount = (int) (maximumCharacterLimit * truncationFactor);
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

	private void doAddMessage(MessageWrapper messageWrapper) {
		messageList.add(messageWrapper);
		updateManager.update();
		if (queuedMessageCount++ > QUEUED_MESSAGE_LIMIT) {
			queuedMessageCount = 0;
			Thread.yield();
		}
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
		for (int i = 0; i < length; i++) {
			Element element = styledDocument.getCharacterElement(i);
			AttributeSet attributes = element.getAttributes();

			Object attribute = attributes.getAttribute(CUSTOM_ATTRIBUTE_KEY);
			if (OUTPUT_ATTRIBUTE_VALUE.equals(attribute)) {
				styledDocument.setCharacterAttributes(i, 1, outputAttributeSet, true);
			}
			else if (ERROR_ATTRIBUTE_VALUE.equals(attribute)) {
				styledDocument.setCharacterAttributes(i, 1, errorAttributeSet, true);
			}
			else {
				// we found an attribute type that we do not know about
				throw new AssertException("Unexpected attribute type for text");
			}
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

	private void insertString(String message, AttributeSet attributeSet) {
		Document document = getDocument();
		int offset = document.getLength();

		try {
			document.insertString(offset, message, attributeSet);
		}
		catch (BadLocationException e) {
			Msg.debug(this, "Unexpected exception updating text", e);
		}
	}

	private void doUpdate() {
		for (int i = 0; !messageList.isEmpty(); i++) {
			MessageWrapper messageWrapper = messageList.remove(0);
			String message = messageWrapper.getMessage();
			insertString(message, messageWrapper.getAttributes());

			validateCapacity();

			notifyListener(messageWrapper);

			if (i % 1000 == 0) { // force a repaint if we do a large volume of work
				paintImmediately(getBounds());
			}
		}

		updateView();
	}

	private void notifyListener(MessageWrapper messageWrapper) {
		if (listener != null) {
			if (messageWrapper.isDoNewline()) {
				listener.putln(messageWrapper.getMessage(),
					(messageWrapper instanceof ErrorMessage));
			}
			else {
				listener.put(messageWrapper.getMessage(), (messageWrapper instanceof ErrorMessage));
			}
		}
	}

	private void updateView() {
		if (scrollLock) {
			return;
		}

		Document doc = getDocument();
		int length = doc.getLength();
		setCaretPosition(length);
	}

	private void validateCapacity() {
		Document doc = getDocument();
		int length = doc.getLength();
		if (length > maximumCharacterLimit) {
			// we need to account for any accumulation over our limit when deciding how much
			// text to remove
			int overage = length - maximumCharacterLimit;
			int totalToTrim = overage + truncationAmount;
			try {
				doc.remove(0, totalToTrim);
			}
			catch (BadLocationException e) {
				Msg.debug(this, "Unexpected exception updating text", e);
			}
		}
	}

	public void dispose() {
		updateManager.dispose();
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private static class MessageWrapper {
		private final String message;
		private final boolean doNewline;

		private MessageWrapper(String message, boolean doNewline) {
			if (message == null) {
				throw new AssertException("Attempted to log a null message.");
			}
			this.message = message;
			this.doNewline = doNewline;
		}

		public boolean isDoNewline() {
			return doNewline;
		}

		String getMessage() {
			return message;
		}

		AttributeSet getAttributes() {
			return outputAttributeSet;
		}
	}

	private static class ErrorMessage extends MessageWrapper {
		private ErrorMessage(String message, boolean doNewline) {
			super(message, doNewline);
		}

		@Override
		AttributeSet getAttributes() {
			return errorAttributeSet;
		}
	}

}
