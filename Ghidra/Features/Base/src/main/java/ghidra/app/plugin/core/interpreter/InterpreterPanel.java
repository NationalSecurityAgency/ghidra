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
package ghidra.app.plugin.core.interpreter;

import java.awt.*;
import java.awt.event.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.swing.*;
import javax.swing.text.*;

import docking.DockingUtils;
import docking.actions.KeyBindingUtils;
import generic.util.WindowUtilities;
import ghidra.app.plugin.core.console.CodeCompletion;
import ghidra.framework.options.OptionsChangeListener;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.*;

public class InterpreterPanel extends JPanel implements OptionsChangeListener {

	private static final String COMPLETION_WINDOW_TRIGGER_LABEL = "Completion Window Trigger";
	private static final String COMPLETION_WINDOW_TRIGGER_DESCRIPTION =
		"The key binding used to show the auto-complete window " +
			"(for those consoles that have auto-complete).";
	private static final String FONT_OPTION_LABEL = "Font";
	private static final String FONT_DESCRIPTION =
		"This is the font that will be used in the Console.  " +
			"Double-click the font example to change it.";

	private static final Color NORMAL_COLOR = Color.black;
	private static final Color ERROR_COLOR = Color.red;

	public enum TextType {
		STDOUT, STDERR, STDIN;
	}

	private InterpreterConnection interpreter;
	private JScrollPane outputScrollPane;
	private JTextPane outputTextPane;
	private JTextPane promptTextPane;
	/* junit */ JTextPane inputTextPane;

	private CodeCompletionWindow codeCompletionWindow;
	private HistoryManager history;

	/* junit */ IPStdin stdin;
	private OutputStream stdout;
	private OutputStream stderr;
	private PrintWriter outWriter;
	private PrintWriter errWriter;

	private Font basicFont = getBasicFont();
	private Font basicBoldFont = getBoldFont(basicFont);
	private SimpleAttributeSet STDOUT_SET;
	private SimpleAttributeSet STDERR_SET;
	private SimpleAttributeSet STDIN_SET;

	private CompletionWindowTrigger completionWindowTrigger = CompletionWindowTrigger.TAB;
	private boolean highlightCompletion = false;

	private boolean caretGuard = true;
	private PluginTool tool;

	private static Font getBasicFont() {
		return new Font(Font.MONOSPACED, Font.PLAIN, 20);
	}

	private static Font getBoldFont(Font font) {
		return font.deriveFont(Font.BOLD);
	}

	private static SimpleAttributeSet createAttributes(Font font, Color color) {
		SimpleAttributeSet attributeSet = new SimpleAttributeSet();
		attributeSet.addAttribute(StyleConstants.FontFamily, font.getFamily());
		attributeSet.addAttribute(StyleConstants.FontSize, font.getSize());
		attributeSet.addAttribute(StyleConstants.Italic, font.isItalic());
		attributeSet.addAttribute(StyleConstants.Bold, font.isBold());
		attributeSet.addAttribute(StyleConstants.Foreground, color);
		return attributeSet;
	}

	public InterpreterPanel(PluginTool tool, InterpreterConnection interpreter) {
		this.tool = tool;
		this.interpreter = interpreter;

		addHierarchyListener(e -> {
			if (codeCompletionWindow != null) {
				// docked/undocked
				codeCompletionWindow.dispose();
				codeCompletionWindow = null;
			}
		});

		addHierarchyBoundsListener(new HierarchyBoundsAdapter() {
			@Override
			public void ancestorMoved(HierarchyEvent e) {
				// move the completion window with the parent window
				updateCompletionWindowLocation();
			}
		});

		build();

		createOptions();
	}

	private void build() {
		outputTextPane = new JTextPane();
		outputTextPane.setName("Interpreter Output Display");
		outputScrollPane = new JScrollPane(outputTextPane);
		outputScrollPane.setBorder(BorderFactory.createEmptyBorder());
		promptTextPane = new JTextPane();
		inputTextPane = new JTextPane();
		inputTextPane.setName("Interpreter Input Field");

		history = new HistoryManagerImpl();

		outputScrollPane.setFocusable(false);
		promptTextPane.setFocusable(false);

		stdin = new IPStdin();
		stdout = new IPOut(TextType.STDOUT);
		stderr = new IPOut(TextType.STDERR);
		outWriter = new PrintWriter(stdout, true);
		errWriter = new PrintWriter(stderr, true);

		outputTextPane.setEditable(false);
		promptTextPane.setEditable(false);

		JPanel interior = new JPanel();
		interior.setLayout(new BorderLayout());
		interior.add(promptTextPane, BorderLayout.WEST);
		interior.add(inputTextPane, BorderLayout.CENTER);

		setLayout(new BorderLayout());
		add(outputScrollPane, BorderLayout.CENTER);
		add(interior, BorderLayout.SOUTH);

		AbstractDocument document = (AbstractDocument) inputTextPane.getDocument();
		document.setDocumentFilter(new DocumentFilter() {
			private String extractAndExecuteCommands(FilterBypass fb, int offset, int length,
					String newText) {
				Document doc = fb.getDocument();
				try {
					String docText = doc.getText(0, offset);
					String text = docText + newText;
					int indexOf = text.indexOf('\n');
					while (indexOf != -1) {
						String command = text.substring(0, indexOf + 1);
						executeCommand(command);
						text = text.substring(indexOf + 1);
						indexOf = text.indexOf('\n');
					}
					return text;
				}
				catch (BadLocationException e) {
					Msg.error(this, "Interpreter document positioning error", e);
				}
				return "";
			}

			@Override
			public void insertString(FilterBypass fb, int offset, String string, AttributeSet attr)
					throws BadLocationException {
				String text = extractAndExecuteCommands(fb, offset, 0, string);
				super.replace(fb, 0, offset, text, attr);
				updateCompletionList();
			}

			@Override
			public void replace(FilterBypass fb, int offset, int length, String text,
					AttributeSet attrs) throws BadLocationException {
				String txt = extractAndExecuteCommands(fb, offset, length, text);
				super.replace(fb, 0, offset + length, txt, attrs);
				updateCompletionList();
			}

			@Override
			public void remove(FilterBypass fb, int offset, int length)
					throws BadLocationException {
				super.remove(fb, offset, length);
				updateCompletionList();
			}
		});

		outputTextPane.addKeyListener(new KeyListener() {
			private void handleEvent(KeyEvent e) {

				// Ignore the copy event, as the output text pane knows how to copy its text
				KeyStroke copyKeyStroke =
					KeyStroke.getKeyStroke(KeyEvent.VK_C, DockingUtils.CONTROL_KEY_MODIFIER_MASK);
				if (copyKeyStroke.equals(KeyStroke.getKeyStrokeForEvent(e))) {
					return;
				}

				// Send everything else down to the inputTextPane.
				KeyBindingUtils.retargetEvent(inputTextPane, e);
			}

			@Override
			public void keyTyped(KeyEvent e) {
				handleEvent(e);
			}

			@Override
			public void keyReleased(KeyEvent e) {
				handleEvent(e);
			}

			@Override
			public void keyPressed(KeyEvent e) {
				handleEvent(e);
			}
		});

		inputTextPane.addKeyListener(new KeyAdapter() {
			@Override
			public void keyPressed(KeyEvent e) {
				CodeCompletionWindow completionWindow = getCodeCompletionWindow();

				switch (e.getKeyCode()) {
					case KeyEvent.VK_ENTER:
						if (completionWindow.isVisible()) {
							/* As opposed to TAB, ENTER inserts the selected
							 * completion (if there is one selected) then
							 * *closes* the completionWindow
							 */
							insertCompletion(completionWindow.getCompletion());
							completionWindow.setVisible(false);
							e.consume();
						}
						else {
							inputTextPane.setCaretPosition(inputTextPane.getDocument().getLength());
						}
						break;
					case KeyEvent.VK_UP:
						if (completionWindow.isVisible()) {
							/* scroll up in the completion window */
							completionWindow.selectPrevious();
						}
						else {
							String historyUp = history.getHistoryUp();
							if (historyUp != null) {
								setInputTextPaneText(historyUp);
							}
						}
						e.consume();
						break;
					case KeyEvent.VK_DOWN:
						if (completionWindow.isVisible()) {
							/* scroll down in the completion window */
							completionWindow.selectNext();
						}
						else {
							String historyDown = history.getHistoryDown();
							if (historyDown != null) {
								setInputTextPaneText(historyDown);
							}
						}
						e.consume();
						break;
					case KeyEvent.VK_ESCAPE:
						completionWindow.setVisible(false);
						e.consume();
						break;
					default:

						// Check for the completion window trigger on input that contains text
						if (completionWindowTrigger.isTrigger(e) &&
							!inputTextPane.getText().trim().isEmpty()) {
							completionWindowTriggered(completionWindow);
							e.consume();
							break;
						}

						updateCompletionList();
						// and let the key go through to the text input field
				}
			}
		});

		outputTextPane.addCaretListener(e -> {
			Caret caret = inputTextPane.getCaret();
			if (caretGuard) {
				caretGuard = false;
				caret.setDot(caret.getDot());
				caretGuard = true;
			}
			caret.setVisible(true);
		});

		inputTextPane.addCaretListener(e -> {
			Caret caret = outputTextPane.getCaret();
			if (caretGuard) {
				caretGuard = false;
				caret.setDot(caret.getDot());
				caretGuard = true;
			}
		});

		FocusTraversalPolicy policy = new FocusTraversalPolicy() {
			@Override
			public Component getLastComponent(Container aContainer) {
				return inputTextPane;
			}

			@Override
			public Component getFirstComponent(Container aContainer) {
				return inputTextPane;
			}

			@Override
			public Component getDefaultComponent(Container aContainer) {
				return inputTextPane;
			}

			@Override
			public Component getComponentBefore(Container aContainer, Component aComponent) {
				return inputTextPane;
			}

			@Override
			public Component getComponentAfter(Container aContainer, Component aComponent) {
				return inputTextPane;
			}
		};
		setFocusCycleRoot(true);
		setFocusTraversalPolicy(policy);
		setFocusTraversalPolicyProvider(true);
	}

	private void completionWindowTriggered(CodeCompletionWindow completionWindow) {
		if (completionWindow.isVisible()) {
			CodeCompletion completion = completionWindow.getCompletion();
			if (null == completion) {
				/* scroll down in the completion window
				 * (i.e. select first available completion, if
				 * possible) */
				completionWindow.selectNext();
			}
			else {
				insertCompletion(completionWindow.getCompletion());
			}
		}
		else {
			completionWindow.setVisible(true);
			updateCompletionList();
		}
	}

	private void updateFontAttributes(Font newFont) {
		basicFont = newFont;
		basicBoldFont = getBoldFont(newFont);
		STDOUT_SET = createAttributes(basicFont, NORMAL_COLOR);
		STDERR_SET = createAttributes(basicFont, ERROR_COLOR);
		STDIN_SET = createAttributes(basicBoldFont, NORMAL_COLOR);

		setTextPaneFont(inputTextPane, basicBoldFont);
		setTextPaneFont(promptTextPane, basicFont);
		setPrompt(promptTextPane.getText());
	}

	private void createOptions() {
		ToolOptions options = tool.getOptions("Console");

// TODO: change help anchor name		
		HelpLocation help = new HelpLocation(getName(), "ConsolePlugin");
		options.setOptionsHelpLocation(help);

		options.registerOption(FONT_OPTION_LABEL, basicFont, help, FONT_DESCRIPTION);
		options.registerOption(COMPLETION_WINDOW_TRIGGER_LABEL, CompletionWindowTrigger.TAB, help,
			COMPLETION_WINDOW_TRIGGER_DESCRIPTION);

		basicFont = options.getFont(FONT_OPTION_LABEL, basicFont);
		basicFont = SystemUtilities.adjustForFontSizeOverride(basicFont);
		updateFontAttributes(basicFont);

		completionWindowTrigger =
			options.getEnum(COMPLETION_WINDOW_TRIGGER_LABEL, CompletionWindowTrigger.TAB);

// TODO		
//		highlightCompletion =
//			options.getBoolean(HIGHLIGHT_COMPLETION_OPTION_LABEL, DEFAULT_HIGHLIGHT_COMPLETION);
//		options.setDescription(HIGHLIGHT_COMPLETION_OPTION_LABEL, HIGHLIGHT_COMPLETION_DESCRIPTION);
//		options.addOptionsChangeListener(this);

		options.addOptionsChangeListener(this);
	}

	@Override
	public void optionsChanged(ToolOptions options, String optionName, Object oldValue,
			Object newValue) {
		if (optionName.equals(FONT_OPTION_LABEL)) {
			basicFont = SystemUtilities.adjustForFontSizeOverride((Font) newValue);
			updateFontAttributes(basicFont);
		}
		else if (optionName.equals(COMPLETION_WINDOW_TRIGGER_LABEL)) {
			completionWindowTrigger = (CompletionWindowTrigger) newValue;
		}
// TODO		
//		else if (optionName.equals(HIGHLIGHT_COMPLETION_OPTION_LABEL)) {
//			highlightCompletion = ((Boolean) newValue).booleanValue();
//		}
	}

	@Override
	public Dimension getPreferredSize() {
		// give a reasonable amount of vertical space initially
		Dimension preferredSize = super.getPreferredSize();
		preferredSize.height = Math.max(preferredSize.height, 400);
		return preferredSize;
	}

	private void executeCommand(String command) {
		try {
			StyledDocument document = promptTextPane.getStyledDocument();
			String prompt = document.getText(0, document.getLength());
			addText(prompt, TextType.STDOUT);
			addText(command, TextType.STDIN);
			repositionScrollpane();
			stdin.addText(command);
			history.addHistory(command);
		}
		catch (BadLocationException e1) {
			Msg.error(this, "internal buffer error", e1);
		}
	}

	private CodeCompletionWindow getCodeCompletionWindow() {
		if (codeCompletionWindow == null) {
			Window parent = WindowUtilities.windowForComponent(inputTextPane);
			codeCompletionWindow = new CodeCompletionWindow(parent, this, inputTextPane);

			// let's give a good default location
			updateCompletionWindowLocation();
		}

		return codeCompletionWindow;
	}

	private void updateCompletionWindowLocation() {
		if (codeCompletionWindow == null) {
			return;
		}

		Point currentLocation = new Point(0, 0);
		Point caretPosition = inputTextPane.getCaret().getMagicCaretPosition();
		if (caretPosition != null) {
			currentLocation = caretPosition;
		}

		codeCompletionWindow.updateLocation(currentLocation);
	}

	private void updateCompletionList() {
		SwingUtilities.invokeLater(() -> {
			/* the second check here is necessary because we don't know
			 * exactly when we are running, so the command line might yet be
			 * in an inconsistent state
			 */
			CodeCompletionWindow completionWindow = getCodeCompletionWindow();
			if (!completionWindow.isVisible()) {
				return;
			}

			String text = getInputTextPaneText();
			List<CodeCompletion> completions =
				InterpreterPanel.this.interpreter.getCompletions(text);
			completionWindow.updateCompletionList(completions);
		});
	}

	private String getInputTextPaneText() {
		String text = null;
		try {
			Document doc = inputTextPane.getDocument();
			text = doc.getText(0, doc.getLength());
		}
		catch (BadLocationException e) {
			Msg.error(this, "internal buffer error", e);
		}
		return text;
	}

	private void setInputTextPaneText(String text) {
		try {
			final Document document = inputTextPane.getDocument();
			document.remove(0, document.getLength());
			document.insertString(0, text, STDIN_SET);
		}
		catch (BadLocationException e) {
			Msg.error(this, "internal document positioning error", e);
		}
	}

	private void repositionScrollpane() {
		// NOTE:  CRAZY CODE!  subtract one to position short of final newline
		outputTextPane.setCaretPosition(Math.max(0, outputTextPane.getDocument().getLength() - 1));
	}

	void addText(String text, TextType type) {
		SimpleAttributeSet attributes;
		switch (type) {
			case STDERR:
				attributes = STDERR_SET;
				break;
			case STDIN:
				attributes = STDIN_SET;
				break;
			case STDOUT:
			default:
				attributes = STDOUT_SET;
				break;
		}
		try {
			StyledDocument document = outputTextPane.getStyledDocument();
			document.insertString(document.getLength(), text, attributes);
			repositionScrollpane();
		}
		catch (BadLocationException e) {
			Msg.error(this, "internal document positioning error", e);
		}
	}

	private class IPOut extends OutputStream {
		TextType type;
		byte[] buffer = new byte[1];

		IPOut(TextType type) {
			this.type = type;
		}

		@Override
		public void write(int b) throws IOException {
			buffer[0] = (byte) b;
			String text = new String(buffer);
			addText(text, type);
		}

		@Override
		public void write(byte[] b, int off, int len) throws IOException {
			String text = new String(b, off, len);
			addText(text, type);
		}
	}

	public void clear() {
		outputTextPane.setText("");
		stdin.resetStream();
	}

	public String getOutputText() {
		return outputTextPane.getText();
	}

	public InputStream getStdin() {
		return stdin;
	}

	public OutputStream getStdOut() {
		return stdout;
	}

	public OutputStream getStdErr() {
		return stderr;
	}

	public PrintWriter getOutWriter() {
		return outWriter;
	}

	public PrintWriter getErrWriter() {
		return errWriter;
	}

	public String getPrompt() {
		return promptTextPane.getText();
	}

	public void setPrompt(String prompt) {
		try {
			final Document document = promptTextPane.getDocument();
			document.remove(0, document.getLength());
			document.insertString(0, prompt, STDOUT_SET);
		}
		catch (BadLocationException e) {
			Msg.error(this, "internal document positioning error", e);
		}
	}

	public void insertCompletion(CodeCompletion completion) {
		if (!CodeCompletion.isValid(completion)) {
			return;
		}

		String text = getInputTextPaneText();
		int position = inputTextPane.getCaretPosition();
		String insertion = completion.getInsertion();

		/* insert completion string */
		setInputTextPaneText(text.substring(0, position) + insertion + text.substring(position));

		/* Select what we inserted so that the user can easily
		 * get rid of what they did (in case of a mistake). */
		if (highlightCompletion) {
			inputTextPane.setSelectionStart(position);
		}

		/* Then put the caret right after what we inserted. */
		inputTextPane.moveCaretPosition(position + insertion.length());
		updateCompletionList();
	}

	public void dispose() {

		stdin.close();
		setVisible(false);
	}

	public void setTextPaneFont(JTextPane textPane, Font font) {
		MutableAttributeSet attributes = new SimpleAttributeSet();
		StyleConstants.setFontFamily(attributes, font.getFamily());
		StyleConstants.setFontSize(attributes, font.getSize());
		StyleConstants.setItalic(attributes, font.isItalic());
		StyleConstants.setBold(attributes, font.isBold());
		StyleConstants.setForeground(attributes, NORMAL_COLOR);

		MutableAttributeSet inputAttributes = textPane.getInputAttributes();
		inputAttributes.removeAttribute(attributes);
		inputAttributes.addAttributes(attributes);
	}

	public boolean isInputPermitted() {
		return inputTextPane.isEditable();
	}

	public void setInputPermitted(boolean permitted) {
		inputTextPane.setEditable(permitted);
	}

//==================================================================================================
// Inner Classes
//==================================================================================================


	/**
	 * An {@link InputStream} that has as its source text strings being pushed into
	 * it by a thread, and being read by another thread.
	 * <p>
	 * Not thread-safe for multiple readers, but is thread-safe for writers.
	 * <p>
	 * {@link #close() Closing} this stream (from any thread) will awaken the
	 * blocked reader thread and give an EOF result to the read operation it was blocking on.
	 */
	/* junit vis */ static class IPStdin extends InputStream {
		private static final byte[] EMPTY_BYTES = new byte[0];

		// reader-thread only fields.  write operations may not access/modify these
		// fields.
		private byte[] bytes = EMPTY_BYTES;
		private int position = 0;
		// end reader-thread only fields

		// shared reader / writer fields.  Any thread may access these as they
		// are threadsafe on their own
		private LinkedBlockingQueue<byte[]> queuedBytes = new LinkedBlockingQueue<>();
		private AtomicBoolean isClosed = new AtomicBoolean(false);
		// end shared fields

		private boolean fetchBytesFromQueue(boolean blocking) {

			try {
				// if the current byte buffer is exhausted, loop until we get
				// a new non-empty byte buffer.
				while (!isClosed.get() && position >= bytes.length) {
					byte[] newBytes = blocking ? queuedBytes.take() : queuedBytes.poll();
					if (newBytes == null) {
						// this only happens when blocking == false, ie. a poll() operation
						break;
					}
					bytes = newBytes;
					position = 0;
				}
			}
			catch (InterruptedException e) {
				// fall thru to return which will return false
			}

			return position < bytes.length;
		}

		@Override
		public int read(byte[] b, int off, int len) throws IOException {
			if (!fetchBytesFromQueue(true)) {
				return -1;
			}

			int length = Math.min(bytes.length - position, len);
			System.arraycopy(bytes, position, b, off, length);
			position += length;
			return length;
		}

		@Override
		public int read() throws IOException {
			byte[] buffer = new byte[1];
			if (read(buffer, 0, 1) != 1) {
				return -1;
			}
			return buffer[0] & 0xff;
		}

		@Override
		public int available() {
			fetchBytesFromQueue(false);
			return bytes.length - position;
		}

		@Override
		public void close() {
			// this will wake up a blocked read-thread waiting on a read() operation
			// and cause it to return a EOF result.
			// All reads() after this close will return EOF value
			isClosed.set(true);
			queuedBytes.clear();
			queuedBytes.offer(EMPTY_BYTES);
		}

		void addText(String text) {
			if (!isClosed.get()) {
				queuedBytes.offer(text.getBytes(StandardCharsets.UTF_8));
			}
		}

		/**
		 * Resets this stream from a closed/always-eof state to an open state.
		 * <p>
		 * Also clears any queued bytes.  Safe to call even when open.
		 */
		void resetStream() {
			isClosed.set(false);
			queuedBytes.clear();
			queuedBytes.offer(EMPTY_BYTES);
		}
	}
}
