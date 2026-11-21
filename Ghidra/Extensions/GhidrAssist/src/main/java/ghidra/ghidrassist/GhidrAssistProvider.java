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
package ghidra.ghidrassist;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;
import java.util.ArrayList;
import java.util.List;

import javax.swing.AbstractAction;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTextArea;
import javax.swing.JTextPane;
import javax.swing.KeyStroke;
import javax.swing.SwingUtilities;
import javax.swing.text.AttributeSet;
import javax.swing.text.BadLocationException;
import javax.swing.text.SimpleAttributeSet;
import javax.swing.text.StyleConstants;
import javax.swing.text.StyledDocument;

import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.util.Msg;

/**
 * Docked chat panel for GhidrAssist. Keeps the current conversation in memory
 * for the session; "Clear" resets it. Streaming responses are rendered as the
 * tokens arrive.
 */
public class GhidrAssistProvider extends ComponentProviderAdapter {

	private final GhidrAssistPlugin plugin;
	private final List<ClaudeMessage> history = new ArrayList<>();

	private JPanel component;
	private JTextPane transcript;
	private StyledDocument doc;
	private JTextArea input;
	private JButton sendButton;
	private JButton clearButton;

	private volatile boolean inflight;
	private int streamingAnchor = -1;

	private final SimpleAttributeSet userStyle = new SimpleAttributeSet();
	private final SimpleAttributeSet assistantStyle = new SimpleAttributeSet();
	private final SimpleAttributeSet systemStyle = new SimpleAttributeSet();
	private final SimpleAttributeSet labelStyle = new SimpleAttributeSet();

	public GhidrAssistProvider(GhidrAssistPlugin plugin) {
		super(plugin.getTool(), "GhidrAssist", plugin.getName());
		this.plugin = plugin;
		setTitle("GhidrAssist");
		setWindowMenuGroup("GhidrAssist");
		setDefaultWindowPosition(docking.WindowPosition.RIGHT);
		buildStyles();
		component = buildComponent();
	}

	private void buildStyles() {
		StyleConstants.setForeground(userStyle, new Color(0x1E88E5));
		StyleConstants.setBold(userStyle, false);
		StyleConstants.setForeground(assistantStyle, new Color(0x2E7D32));
		StyleConstants.setForeground(systemStyle, new Color(0x9E9E9E));
		StyleConstants.setItalic(systemStyle, true);
		StyleConstants.setBold(labelStyle, true);
	}

	private JPanel buildComponent() {
		JPanel panel = new JPanel(new BorderLayout());

		transcript = new JTextPane();
		transcript.setEditable(false);
		transcript.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
		doc = transcript.getStyledDocument();
		JScrollPane transcriptScroll = new JScrollPane(transcript);
		transcriptScroll.setPreferredSize(new Dimension(560, 360));

		input = new JTextArea(5, 40);
		input.setLineWrap(true);
		input.setWrapStyleWord(true);
		input.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
		JScrollPane inputScroll = new JScrollPane(input);
		inputScroll.setBorder(BorderFactory.createTitledBorder("You"));

		input.getInputMap().put(KeyStroke.getKeyStroke(KeyEvent.VK_ENTER,
			java.awt.Toolkit.getDefaultToolkit().getMenuShortcutKeyMaskEx()), "send");
		input.getActionMap().put("send", new AbstractAction() {
			@Override
			public void actionPerformed(ActionEvent e) {
				sendCurrent();
			}
		});

		sendButton = new JButton("Send");
		sendButton.addActionListener(e -> sendCurrent());
		clearButton = new JButton("Clear");
		clearButton.addActionListener(e -> clearHistory());

		JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT));
		buttons.add(clearButton);
		buttons.add(sendButton);

		JPanel bottom = new JPanel(new BorderLayout());
		bottom.add(inputScroll, BorderLayout.CENTER);
		bottom.add(buttons, BorderLayout.SOUTH);

		JSplitPane split =
			new JSplitPane(JSplitPane.VERTICAL_SPLIT, transcriptScroll, bottom);
		split.setResizeWeight(0.8);
		split.setBorder(null);
		panel.add(split, BorderLayout.CENTER);
		return panel;
	}

	void dispose() {
		removeFromTool();
	}

	@Override
	public JComponent getComponent() {
		return component;
	}

	private void sendCurrent() {
		if (inflight) {
			return;
		}
		String text = input.getText().trim();
		if (text.isEmpty()) {
			return;
		}
		input.setText("");
		postUser(text);
		runStreaming(text);
	}

	private void clearHistory() {
		history.clear();
		try {
			doc.remove(0, doc.getLength());
		}
		catch (BadLocationException ignored) {
		}
		appendStyled("Conversation cleared.\n", systemStyle);
	}

	private void runStreaming(String userText) {
		history.add(ClaudeMessage.user(userText));
		inflight = true;
		setSendEnabled(false);

		appendLabel("Claude");
		streamingAnchor = doc.getLength();

		ClaudeOptions opts = plugin.options();
		StringBuilder complete = new StringBuilder();

		Thread t = new Thread(() -> {
			plugin.claude().stream(opts, new ArrayList<>(history),
				delta -> SwingUtilities.invokeLater(() -> {
					complete.append(delta);
					appendStyled(delta, assistantStyle);
				}),
				done -> SwingUtilities.invokeLater(() -> {
					appendStyled("\n\n", assistantStyle);
					history.add(ClaudeMessage.assistant(complete.toString()));
					inflight = false;
					setSendEnabled(true);
				}),
				err -> SwingUtilities.invokeLater(() -> {
					appendStyled("\n[error: " + err.getMessage() + "]\n\n", systemStyle);
					history.remove(history.size() - 1); // roll back the user turn
					inflight = false;
					setSendEnabled(true);
					Msg.error(this, "Claude request failed", err);
				}));
		}, "GhidrAssist-chat");
		t.setDaemon(true);
		t.start();
	}

	private void setSendEnabled(boolean enabled) {
		sendButton.setEnabled(enabled);
		input.setEnabled(enabled);
	}

	private void postUser(String text) {
		appendLabel("You");
		appendStyled(text + "\n\n", userStyle);
	}

	private void appendLabel(String who) {
		appendStyled(who + ": ", labelStyle);
	}

	private void appendStyled(String text, AttributeSet style) {
		try {
			doc.insertString(doc.getLength(), text, style);
			transcript.setCaretPosition(doc.getLength());
		}
		catch (BadLocationException ignored) {
		}
	}

	/** Public hook used by context actions to post results into the chat. */
	public void postAssistantMessage(String label, String content) {
		SwingUtilities.invokeLater(() -> {
			if (!isVisible()) {
				setVisible(true);
			}
			appendLabel("GhidrAssist — " + label);
			appendStyled("\n" + content + "\n\n", assistantStyle);
			history.add(ClaudeMessage.assistant("[" + label + "]\n" + content));
		});
	}

	/** Also used by actions to inform the user something happened. */
	public void postSystemMessage(String text) {
		SwingUtilities.invokeLater(() -> appendStyled(text + "\n", systemStyle));
	}

	/**
	 * Open a labeled streaming region in the transcript. Call
	 * {@link StreamHandle#append(String)} for each delta and
	 * {@link StreamHandle#close(String)} with the final text when done.
	 */
	public StreamHandle beginStream(String label) {
		SwingUtilities.invokeLater(() -> {
			if (!isVisible()) {
				setVisible(true);
			}
			appendLabel("GhidrAssist — " + label);
			appendStyled("\n", assistantStyle);
		});
		return new StreamHandle(label);
	}

	public final class StreamHandle {
		private final String label;

		private StreamHandle(String label) {
			this.label = label;
		}

		public void append(String delta) {
			SwingUtilities.invokeLater(() -> appendStyled(delta, assistantStyle));
		}

		public void close(String full) {
			SwingUtilities.invokeLater(() -> {
				appendStyled("\n\n", assistantStyle);
				history.add(ClaudeMessage.assistant("[" + label + "]\n" + full));
			});
		}

		public void error(Throwable err) {
			SwingUtilities.invokeLater(() -> appendStyled(
				"\n[error: " + err.getMessage() + "]\n\n", systemStyle));
		}
	}
}
