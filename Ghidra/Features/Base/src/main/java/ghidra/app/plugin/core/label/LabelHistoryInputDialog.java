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
package ghidra.app.plugin.core.label;

import java.awt.BorderLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

import docking.DialogComponentProvider;
import ghidra.app.util.HelpTopics;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;
import ghidra.util.task.Task;

public class LabelHistoryInputDialog extends DialogComponentProvider {

	private JTextField inputField;
	private LabelHistoryTask task;
	private final Program program;
	private PluginTool tool;

	public LabelHistoryInputDialog(PluginTool tool, Program program) {
		super("Label History Search", true);
		this.program = program;
		this.tool = tool;

		addWorkPanel(buildMainPanel());
		addOKButton();
		addCancelButton();
		setHelpLocation(new HelpLocation(HelpTopics.LABEL, "Show_All_History"));
	}

	@Override
	protected void cancelCallback() {
		close();
	}

	@Override
	protected void okCallback() {
		String text = inputField.getText();
		if (text.length() == 0) {
			text = null;
		}
		task = new LabelHistoryTask(tool, program, text);
		task.addTaskListener(this);

		tool.execute(task, 250);
	}

	void showDialog() {
		clearStatusText();
		inputField.selectAll();
		tool.showDialog(this);
	}

	private JPanel buildMainPanel() {
		JPanel panel = new JPanel(new BorderLayout());
		panel.setBorder(BorderFactory.createTitledBorder("Enter Symbol Name"));

		inputField = new JTextField(25);
		setFocusComponent(inputField);
		inputField.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				okCallback();
			}
		});
		inputField.getDocument().addDocumentListener(new DocumentListener() {
			@Override
			public void changedUpdate(DocumentEvent e) {
				clearStatusText();
			}

			@Override
			public void insertUpdate(DocumentEvent e) {
				clearStatusText();
			}

			@Override
			public void removeUpdate(DocumentEvent e) {
				clearStatusText();
			}
		});

		panel.add(inputField, BorderLayout.CENTER);
		JPanel outerPanel = new JPanel(new BorderLayout());
		outerPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 0, 5));
		outerPanel.add(panel, BorderLayout.CENTER);
		return outerPanel;
	}

	@Override
	public void taskCancelled(Task cancelTask) {
		taskCompleted(cancelTask);
	}

	@Override
	public void taskCompleted(Task t) {
		if (!task.labelsFound()) {
			String matchStr = inputField.getText();
			if (matchStr.length() == 0) {
				setStatusText("No label history was found");
			}
			else {
				setStatusText("No matches were found for " + matchStr);
			}
		}
		else {
			close();
		}
	}

}
