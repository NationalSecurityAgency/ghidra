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
package ghidra.app.plugin.core.validator;

import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.util.List;

import javax.swing.*;

import docking.DialogComponentProvider;
import docking.widgets.conditiontestpanel.ConditionTestPanel;
import docking.widgets.conditiontestpanel.ConditionTester;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;

public class ValidateProgramDialog extends DialogComponentProvider {
	private ConditionTestPanel conditionTestPanel;

	public ValidateProgramDialog(Program program, List<ConditionTester> list) {
		super(getTitle(program), true, true, true, false);

		JPanel mainPanel = new JPanel();

		conditionTestPanel = new ConditionTestPanel(list);
		conditionTestPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

		mainPanel.setBorder(BorderFactory.createEmptyBorder(5, 10, 5, 10));
		mainPanel.setLayout(new BorderLayout());

		JPanel runButtonPanel = new JPanel();
		runButtonPanel.setBorder(BorderFactory.createEmptyBorder(20, 0, 0, 0));
		runButtonPanel.setLayout(new FlowLayout());
		JButton runTestsButton = new JButton("Run Validators");
		runTestsButton.addActionListener(e -> conditionTestPanel.runTests());
		runButtonPanel.add(runTestsButton);
		mainPanel.add(conditionTestPanel, BorderLayout.CENTER);
		mainPanel.add(runButtonPanel, BorderLayout.SOUTH);

		addWorkPanel(mainPanel);
		addOKButton();
		setOkEnabled(true);
		setHelpLocation(new HelpLocation("ValidateProgram", "top_of_page"));
	}

	private static String getTitle(Program program) {
		return "Validate: " + program.getDomainFile().getName();
	}

	@Override
	protected void okCallback() {
		close();
	}
}
