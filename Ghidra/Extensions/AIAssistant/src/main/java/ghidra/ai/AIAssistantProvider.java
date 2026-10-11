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
import java.io.File;
import java.util.Map;

import javax.swing.*;

import com.google.gson.JsonObject;

import docking.WindowPosition;
import docking.widgets.OptionDialog;
import docking.widgets.filechooser.GhidraFileChooser;
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

	/** Hebrew descriptions of the tools, shown while the AI works. */
	private static final Map<String, String> TOOL_LABELS = Map.ofEntries(
		Map.entry("get_program_info", "קורא מידע כללי על התוכנית"),
		Map.entry("get_current_location", "בודק איפה הסמן נמצא"),
		Map.entry("search_functions", "מחפש פונקציות"),
		Map.entry("search_strings", "מחפש מחרוזות"),
		Map.entry("search_symbols", "מחפש סמלים"),
		Map.entry("list_imports", "בודק ייבואים"),
		Map.entry("list_entry_points", "בודק נקודות כניסה"),
		Map.entry("get_references_to", "מחפש הפניות אל"),
		Map.entry("get_callers", "בודק מי קורא ל"),
		Map.entry("get_callees", "בודק למי קוראת"),
		Map.entry("decompile_function", "מפענח את"),
		Map.entry("disassemble", "קורא אסמבלי ב"),
		Map.entry("go_to", "מנווט אל"),
		Map.entry("find_unreferenced_functions", "מחפש פונקציות שאף אחד לא קורא להן"),
		Map.entry("rename_function", "מבקש לשנות שם פונקציה"),
		Map.entry("rename_variable", "מבקש לשנות שם משתנה"),
		Map.entry("set_function_signature", "מבקש לשנות חתימה של"),
		Map.entry("set_comment", "מבקש להוסיף הערה ב"),
		Map.entry("create_label", "מבקש ליצור תווית"),
		Map.entry("patch_instruction", "מבקש לתקן פקודה ב"),
		Map.entry("patch_bytes", "מבקש לכתוב בתים ב"),
		Map.entry("delete_function", "מבקש למחוק את הפונקציה"));

	private final AIAssistantPlugin plugin;
	private JPanel mainPanel;
	private JTextArea chatArea;
	private JTextField inputField;
	private JLabel backendLabel;
	private JButton sendButton;
	private JButton explainButton;
	private JButton renameButton;
	private JButton resetButton;
	private JButton documentButton;
	private JButton exportBinaryButton;
	private JButton exportCButton;

	AIAssistantProvider(AIAssistantPlugin plugin) {
		super(plugin.getTool(), "AI Assistant", plugin.getName());
		this.plugin = plugin;
		setTitle("עוזר AI");
		setDefaultWindowPosition(WindowPosition.RIGHT);
		buildPanel();
		appendLine("שלום! שאל אותי כל שאלה על התוכנית הפתוחה, למשל:\n" +
			"  • איפה נמצא הקוד שבודק את הסיסמה?\n" +
			"  • מה גורם להודעת השגיאה \"Access denied\"?\n" +
			"  • מי קורא לפונקציה הזו ומה היא עושה?\n" +
			"  • מה אפשר למחוק או לנטרל בתוכנית הזו?\n" +
			"  • תשנה את השם של הפונקציה הזו ותוסיף לה הערה בעברית.\n" +
			"אני מחפש בתוכנית בעצמי, מסביר, ומעביר אותך למקום הנכון. כל שינוי שאציע " +
			"יבוצע רק באישורך, ואפשר לבטל אותו עם Ctrl+Z.");
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
			"הסבר מה הפונקציה הבאה עושה, שלב אחר שלב, וציין דברים חשודים או מעניינים. " +
				"אם צריך, בדוק גם את הפונקציות שהיא קוראת להן ומי קורא לה."));
		renameButton = new JButton("הצע שמות");
		renameButton.addActionListener(e -> askAboutCurrentFunction(
			"הצע שם טוב לפונקציה הבאה ושמות למשתנים ולפרמטרים שלה, עם הסבר קצר לכל שם."));
		resetButton = new JButton("שיחה חדשה");
		resetButton.addActionListener(e -> {
			plugin.resetConversation();
			chatArea.setText("");
			appendLine("התחלנו שיחה חדשה.");
		});

		documentButton = new JButton("תעד הכל בעברית");
		documentButton.setToolTipText("כותב הערה בעברית מעל כל פונקציה שאין לה הערה");
		documentButton.addActionListener(e -> documentAll());
		exportBinaryButton = new JButton("ייצא קובץ מתוקן");
		exportBinaryButton.setToolTipText(
			"שומר את הקובץ הבינארי עם כל התיקונים (Patch) שבוצעו, כך שאפשר להריץ אותו");
		exportBinaryButton.addActionListener(e -> export(true));
		exportCButton = new JButton("ייצא את כל הקוד ל-C");
		exportCButton.setToolTipText("שומר את כל התוכנית כקוד C מפוענח, כולל ההערות בעברית");
		exportCButton.addActionListener(e -> export(false));

		JPanel buttons = new JPanel(new GridLayout(2, 3, 4, 4));
		buttons.setComponentOrientation(RTL);
		buttons.add(explainButton);
		buttons.add(renameButton);
		buttons.add(resetButton);
		buttons.add(documentButton);
		buttons.add(exportBinaryButton);
		buttons.add(exportCButton);

		backendLabel = new JLabel();
		backendLabel.setComponentOrientation(RTL);
		backendLabel.setBorder(BorderFactory.createEmptyBorder(0, 6, 0, 6));
		updateBackendLabel();

		JPanel topPanel = new JPanel(new BorderLayout());
		topPanel.setComponentOrientation(RTL);
		topPanel.add(buttons, BorderLayout.CENTER);
		topPanel.add(backendLabel, BorderLayout.SOUTH);
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
		mainPanel.setPreferredSize(new Dimension(480, 560));
	}

	private void updateBackendLabel() {
		// the trailing LRM keeps the closing parenthesis of "(model)" on the correct side
		backendLabel.setText("ספק: " + plugin.describeBackend() + "\u200E");
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
		appendLine("\nאתה: " + instruction + " (" + function.getName() + ")");
		runRequest("מנתח את " + function.getName(), monitor -> {
			monitor.setMessage("מבצע דה-קומפילציה...");
			String code = plugin.decompile(function, monitor);
			if (code == null) {
				throw new IllegalStateException("הדה-קומפילציה של " + function.getName() + " נכשלה");
			}
			return instruction + "\n\nFunction: " + function.getName(true) + " @ " +
				function.getEntryPoint() + "\n\n```c\n" + code + "\n```";
		});
	}

	@FunctionalInterface
	private interface PromptBuilder {
		String build(TaskMonitor monitor) throws Exception;
	}

	private void runRequest(String title, PromptBuilder promptBuilder) {
		updateBackendLabel();
		String problem = plugin.getConfigurationProblem();
		if (problem != null) {
			appendLine("\n" + problem);
			return;
		}
		if (plugin.getProgram() == null) {
			appendLine("\nאין תוכנית פתוחה. פתח תוכנית ונסה שוב.");
			return;
		}
		setBusy(true);
		Task task = new Task(title, true, false, false) {
			@Override
			public void run(TaskMonitor monitor) {
				try {
					String prompt = promptBuilder.build(monitor);
					monitor.setMessage("ממתין לתשובה מ-AI...");
					String reply = plugin.ask(prompt, (name, args) -> {
						String line = "  🔎 " + TOOL_LABELS.getOrDefault(name, name) + " " +
							describeArgs(args);
						appendLine(line);
						monitor.setMessage(line.strip());
					}, monitor);
					appendLine("\nעוזר AI: " + reply);
				}
				catch (AIProvider.AIException e) {
					appendLine("\n" + friendlyError(e));
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

	private void documentAll() {
		String problem = plugin.getConfigurationProblem();
		if (problem != null || plugin.getProgram() == null) {
			appendLine("\n" + (problem != null ? problem : "אין תוכנית פתוחה."));
			return;
		}
		int limit = plugin.getDocumentLimit();
		int answer = OptionDialog.showYesNoDialog(mainPanel, "תיעוד כל הפונקציות",
			"ה-AI יכתוב הערה בעברית מעל כל פונקציה שאין לה הערה (עד " + limit +
				" פונקציות).\nכל פונקציה היא בקשה נפרדת לשירות ה-AI ועולה כסף.\n" +
				"אפשר לעצור באמצע, ולבטל עם Ctrl+Z.\n\nלהמשיך?");
		if (answer != OptionDialog.YES_OPTION) {
			return;
		}
		appendLine("\nמתעד את הפונקציות בעברית...");
		setBusy(true);
		Task task = new Task("תיעוד כל הפונקציות", true, true, false) {
			@Override
			public void run(TaskMonitor monitor) {
				try {
					appendLine("\n" + plugin.documentAllFunctions(line -> appendLine(line),
						monitor));
				}
				catch (AIProvider.AIException e) {
					appendLine("\n" + friendlyError(e));
				}
				catch (Exception e) {
					Msg.error(AIAssistantProvider.this, "Documenting functions failed", e);
					appendLine("\nשגיאה: " + e.getMessage());
				}
				finally {
					Swing.runLater(() -> setBusy(false));
				}
			}
		};
		new TaskLauncher(task, mainPanel);
	}

	private void export(boolean binary) {
		if (plugin.getProgram() == null) {
			appendLine("\nאין תוכנית פתוחה.");
			return;
		}
		GhidraFileChooser chooser = new GhidraFileChooser(mainPanel);
		chooser.setTitle(binary ? "שמירת הקובץ המתוקן" : "שמירת הקוד כ-C");
		chooser.setApproveButtonText("שמור");
		String name = plugin.getProgram().getName();
		chooser.setSelectedFile(new File(binary ? patchedName(name) : name + ".c"));
		File file = chooser.getSelectedFile();
		chooser.dispose();
		if (file == null) {
			return;
		}
		Task task = new Task(binary ? "מייצא קובץ מתוקן" : "מייצא קוד C", true, false, false) {
			@Override
			public void run(TaskMonitor monitor) {
				try {
					boolean ok = binary ? plugin.exportPatchedBinary(file, monitor)
							: plugin.exportAllC(file, monitor);
					appendLine(ok ? "\nנשמר: " + file.getAbsolutePath() +
						(binary ? "" : "\nשים לב: קוד מפוענח בדרך כלל דורש תיקונים ידניים " +
							"לפני שאפשר לקמפל אותו מחדש.")
							: "\nהייצוא נכשל.");
				}
				catch (Exception e) {
					Msg.error(AIAssistantProvider.this, "Export failed", e);
					appendLine("\nהייצוא נכשל: " + e.getMessage());
				}
			}
		};
		new TaskLauncher(task, mainPanel);
	}

	private static String patchedName(String name) {
		int dot = name.lastIndexOf('.');
		return dot > 0 ? name.substring(0, dot) + "_patched" + name.substring(dot)
				: name + "_patched";
	}

	private static String friendlyError(AIProvider.AIException e) {
		return switch (e.getStatus()) {
			case 401, 403 -> "שגיאה: מפתח ה-API אינו תקין או שאין לו הרשאה. בדוק אותו " +
				"ב-Edit > Tool Options > " + AIAssistantPlugin.OPTIONS_CATEGORY + ".\n(" +
				e.getMessage() + ")";
			case 404 -> "שגיאה: המודל או הכתובת לא נמצאו. בדוק את שם המודל וכתובת השרת " +
				"באפשרויות.\n(" + e.getMessage() + ")";
			case 429 -> "שגיאה: חרגת ממגבלת הבקשות או מהמכסה. נסה שוב בעוד כמה שניות.\n(" +
				e.getMessage() + ")";
			default -> "שגיאה מהשרת: " + e.getMessage();
		};
	}

	/** Shows the most informative argument (query/target) of a tool call. */
	private static String describeArgs(String json) {
		JsonObject args = HttpJson.parseArgs(json);
		for (String key : new String[] { "query", "target" }) {
			if (args.has(key) && !args.get(key).isJsonNull()) {
				return "'" + args.get(key).getAsString() + "'";
			}
		}
		return "";
	}

	private void setBusy(boolean busy) {
		sendButton.setEnabled(!busy);
		explainButton.setEnabled(!busy);
		renameButton.setEnabled(!busy);
		resetButton.setEnabled(!busy);
		documentButton.setEnabled(!busy);
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
