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
package ghidra.feature.vt.gui.wizard.session;

import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.lang.reflect.Constructor;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.swing.*;

import docking.widgets.conditiontestpanel.*;
import docking.wizard.WizardModel;
import ghidra.feature.vt.api.main.VTSession;
import ghidra.feature.vt.gui.validator.VTPreconditionValidator;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.classfinder.ClassSearcher;
import utility.function.Callback;

public class PreconditionsPanel extends JPanel {
	private static final Dimension DEFAULT_SIZE = new Dimension(650, 480);
	private ConditionTestPanel conditionsTestPanel;
	private boolean testsDone = false;
	private Callback statusChangedCallback;

	public PreconditionsPanel(WizardModel<NewSessionData> model,
			Callback statusChangedCallback) {
		this.statusChangedCallback = statusChangedCallback;
		setBorder(BorderFactory.createEmptyBorder(5, 10, 5, 10));
		setLayout(new BorderLayout());

		JPanel runButtonPanel = new JPanel();
		runButtonPanel.setBorder(BorderFactory.createEmptyBorder(20, 0, 0, 0));
		runButtonPanel.setLayout(new FlowLayout());
		JButton runTestsButton = new JButton("Run Precondition Checks");
		runTestsButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				conditionsTestPanel.runTests();
			}
		});
		runButtonPanel.add(runTestsButton);

		JButton skipTestsButton = new JButton("Skip");
		skipTestsButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				conditionsTestPanel.skipTests();
				model.goNext();
			}
		});
		runButtonPanel.add(skipTestsButton);

		add(runButtonPanel, BorderLayout.SOUTH);
	}

	void dispose() {
		if (conditionsTestPanel != null) {
			conditionsTestPanel.cancel();
		}
	}

	private ConditionTestPanel buildConditionPanel(Program source, Program destination) {
		List<ConditionTester> list = getConditionTests(source, destination);
		Collections.sort(list, (t1, t2) -> t1.getName().compareTo(t2.getName()));
		ConditionTestPanel panel = new ConditionTestPanel(list);
		panel.addListener(new ConditionTestListener() {
			@Override
			public void testsCompleted() {
				testsDone();
			}
		});
		return panel;
	}

	private void testsDone() {
		testsDone = true;
		statusChangedCallback.call();
		if (hasAnyErrorStatus()) {
			Msg.showError(getClass(), this, "Warning - Serious Precondition failures",
				"The precondition checks discovered one or more serious problems. \n\n" +
					"If you continue, your version tracking results may be invalid.\n" +
					"You should review the errors, cancel this wizard, and correct the problems.");
		}
	}

	private List<ConditionTester> getConditionTests(Program sourceProgram,
			Program destinationProgram) throws SecurityException {
		List<ConditionTester> list = new ArrayList<ConditionTester>();

		List<Class<? extends VTPreconditionValidator>> vtValidatorClasses =
			ClassSearcher.getClasses(VTPreconditionValidator.class);
		for (Class<? extends VTPreconditionValidator> validatorClass : vtValidatorClasses) {
			try {
				Constructor<? extends VTPreconditionValidator> ctor =
					validatorClass.getConstructor(Program.class, Program.class, VTSession.class);
				VTPreconditionValidator validator =
					ctor.newInstance(sourceProgram, destinationProgram, null);
				list.add(validator);
			}
			catch (Exception e) {
				Msg.error(this, "error including VTPreconditionValidator " + validatorClass, e);
			}
		}
		return list;
	}

	private Boolean hasAnyErrorStatus() {
		return conditionsTestPanel.getErrorCount() > 0;
	}

	@Override
	// Overridden to account for the fact that we don't know our preferred size until later in 
	// the wizard flow.  At that point, the initial size of the wizard is already too small.
	public Dimension getPreferredSize() {
		Dimension superSize = super.getPreferredSize();
		if (superSize.width > DEFAULT_SIZE.width && superSize.height > DEFAULT_SIZE.height) {
			return superSize;
		}
		return DEFAULT_SIZE;
	}

	public void initializeTests(Program sourceProgram, Program destinationProgram) {
		testsDone = false;
		if (conditionsTestPanel != null) {
			remove(conditionsTestPanel);
		}
		conditionsTestPanel = buildConditionPanel(sourceProgram, destinationProgram);
		add(conditionsTestPanel, BorderLayout.CENTER);
	}

	public boolean hasRunTests() {
		return testsDone;
	}
}
