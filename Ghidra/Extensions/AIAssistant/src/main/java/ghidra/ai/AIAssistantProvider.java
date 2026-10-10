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
package ghidra.ai;

import java.awt.*;

import javax.swing.*;

import com.anthropic.errors.RateLimitException;
import com.anthropic.errors.UnauthorizedException;

import docking.WindowPosition;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.program.model.listing.Function;
import ghidra.util.Msg;
import ghidra.util.Swing;
import ghidra.util.task.*;

/**
 * The docked chat window of the AI assistant. All labels are in Hebrew and text is laid out
 * right-to-left.
 */
class AIAssistantProvider extends ComponentProviderAdapter {

	private static final ComponentOrientation RTL = ComponentOrientation.RIGHT_TO_LEFT;

	private final AIAssistantPlugin plugin;
	private JPanel mainPanel;
	private JTextArea chatArea;
	private JTextField inputField;
	private JButton sendButton;
	private JButton explainButton;
	private JButton renameButton;
	private JButton resetButton;

	AIAssistantProvider(AIAssistantPlugin plugin) {
		super(plugin.getTool(), "AI Assistant", plugin.getName());
		this.plugin = plugin;
		setTitle("עוזר AI");
		setDefaultWindowPosition(WindowPosition.RIGHT);
		buildPanel();
		appendLine("עוזר AI מוכן. בחר פונקציה ולחץ \"הסבר פונקציה\", או כתוב שאלה ולחץ \"שלח\".");
	}

	private void buildPanel() {
		mainPanel = new JPanel(new BorderLayout(4, 4));

		chatArea = new JTextArea();
		chatArea.setEditable(false);
		chatArea.setLineWrap(true);
		chatArea.setWrapStyleWord(true);
		chatArea.setComponentOrientation(RTL);
		mainPanel.add(new JScrollPane(chatArea), BorderLayout.CENTER);

		explainButton = new JButton("הסבר פונקציה");
		explainButton.addActionListener(e -> askAboutCurrentFunction(
			"הסבר מה הפונקציה הבאה עושה, שלב אחר שלב, וציין דברים חשודים או מעניינים:"));
		renameButton = new JButton("הצע שמות");
		renameButton.addActionListener(e -> askAboutCurrentFunction(
			"הצע שם טוב לפונקציה הבאה ושמות למשתנים ולפרמטרים שלה, עם הסבר קצר לכל שם:"));
		resetButton = new JButton("שיחה חדשה");
		resetButton.addActionListener(e -> {
			plugin.getClaude().reset();
			chatArea.setText("");
			appendLine("התחלנו שיחה חדשה.");
		});

		JPanel topPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
		topPanel.setComponentOrientation(RTL);
		topPanel.add(explainButton);
		topPanel.add(renameButton);
		topPanel.add(resetButton);
		mainPanel.add(topPanel, BorderLayout.NORTH);

		inputField = new JTextField();
		inputField.setComponentOrientation(RTL);
		inputField.addActionListener(e -> sendFreeText());
		sendButton = new JButton("שלח");
		sendButton.addActionListener(e -> sendFreeText());

		JPanel bottomPanel = new JPanel(new BorderLayout(4, 4));
		bottomPanel.setComponentOrientation(RTL);
		bottomPanel.add(inputField, BorderLayout.CENTER);
		bottomPanel.add(sendButton, BorderLayout.LINE_END);
		mainPanel.add(bottomPanel, BorderLayout.SOUTH);

		mainPanel.setComponentOrientation(RTL);
		mainPanel.setPreferredSize(new Dimension(450, 500));
	}

	private void sendFreeText() {
		String text = inputField.getText().strip();
		if (text.isEmpty()) {
			return;
		}
		inputField.setText("");
		appendLine("\nאתה: " + text);
		runRequest("שולח שאלה ל-AI", monitor -> text);
	}

	private void askAboutCurrentFunction(String instruction) {
		Function function = plugin.getCurrentFunction();
		if (function == null) {
			appendLine("\nלא נבחרה פונקציה. מקם את הסמן בתוך פונקציה ונסה שוב.");
			return;
		}
		appendLine("\nאתה: " + instruction + " " + function.getName());
		runRequest("מנתח את " + function.getName(), monitor -> {
			monitor.setMessage("מבצע דה-קומפילציה...");
			String code = plugin.decompile(function, monitor);
			if (code == null) {
				throw new IllegalStateException("הדה-קומפילציה של " + function.getName() + " נכשלה");
			}
			return instruction + "\n\nFunction: " + function.getName() + " @ " +
				function.getEntryPoint() + "\n\n```c\n" + code + "\n```";
		});
	}

	@FunctionalInterface
	private interface PromptBuilder {
		String build(TaskMonitor monitor) throws Exception;
	}

	private void runRequest(String title, PromptBuilder promptBuilder) {
		String apiKey = plugin.getApiKey();
		if (apiKey.isEmpty()) {
			appendLine("\nחסר מפתח API. הגדר אותו ב-Edit > Tool Options > " +
				AIAssistantPlugin.OPTIONS_CATEGORY + ", או במשתנה הסביבה ANTHROPIC_API_KEY.");
			return;
		}
		String model = plugin.getModel();
		setBusy(true);
		Task task = new Task(title, true, false, false) {
			@Override
			public void run(TaskMonitor monitor) {
				try {
					String prompt = promptBuilder.build(monitor);
					monitor.setMessage("ממתין לתשובה מ-Claude...");
					String reply = plugin.getClaude().send(apiKey, model, prompt);
					appendLine("\nClaude: " + reply);
				}
				catch (UnauthorizedException e) {
					appendLine("\nשגיאה: מפתח ה-API אינו תקין. בדוק אותו באפשרויות של עוזר AI.");
				}
				catch (RateLimitException e) {
					appendLine("\nשגיאה: חרגת ממגבלת הבקשות. נסה שוב בעוד מספר שניות.");
				}
				catch (Exception e) {
					Msg.error(AIAssistantProvider.this, "AI request failed", e);
					appendLine("\nשגיאה: " + e.getMessage());
				}
				finally {
					Swing.runLater(() -> setBusy(false));
				}
			}
		};
		new TaskLauncher(task, mainPanel);
	}

	private void setBusy(boolean busy) {
		sendButton.setEnabled(!busy);
		explainButton.setEnabled(!busy);
		renameButton.setEnabled(!busy);
		resetButton.setEnabled(!busy);
	}

	private void appendLine(String text) {
		Swing.runLater(() -> {
			chatArea.append(text + "\n");
			chatArea.setCaretPosition(chatArea.getDocument().getLength());
		});
	}

	@Override
	public JComponent getComponent() {
		return mainPanel;
	}

	void dispose() {
		removeFromTool();
	}
}
