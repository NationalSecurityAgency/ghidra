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
package ghidra.feature.vt.gui.wizard;

import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.lang.reflect.Constructor;
import java.util.*;
import java.util.List;

import javax.swing.*;

import docking.widgets.conditiontestpanel.*;
import docking.wizard.*;
import ghidra.feature.vt.api.main.VTSession;
import ghidra.feature.vt.gui.validator.VTPreconditionValidator;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.classfinder.ClassSearcher;

public class PreconditionsPanel extends AbstractMageJPanel<VTWizardStateKey> implements Scrollable {
	private static final Dimension DEFAULT_SIZE = new Dimension(650, 480);
	private ConditionTestPanel conditionsTestPanel;
	private boolean testsDone = false;
	private VTNewSessionWizardManager wizardManager;

	public PreconditionsPanel(VTNewSessionWizardManager panelManager) {

		this.wizardManager = panelManager;
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
				wizardManager.getWizardManager().next();
			}
		});
		runButtonPanel.add(skipTestsButton);

		add(runButtonPanel, BorderLayout.SOUTH);
	}

	@Override
	public HelpLocation getHelpLocation() {
		return new HelpLocation("VersionTrackingPlugin", "Preconditions_Panel");
	}

	@Override
	public void addDependencies(WizardState<VTWizardStateKey> state) {
		state.addDependency(VTWizardStateKey.PRECONDITION_CHECKS_RUN,
			VTWizardStateKey.SOURCE_PROGRAM_FILE);
		state.addDependency(VTWizardStateKey.PRECONDITION_CHECKS_RUN,
			VTWizardStateKey.DESTINATION_PROGRAM_FILE);

		state.addDependency(VTWizardStateKey.HIGHEST_PRECONDITION_STATUS,
			VTWizardStateKey.PRECONDITION_CHECKS_RUN);
	}

	@Override
	public void dispose() {
		if (conditionsTestPanel != null) {
			conditionsTestPanel.cancel();
		}
	}

	@Override
	public void enterPanel(WizardState<VTWizardStateKey> state) {
		initializeRunState(state);

		if (!testsDone) {
			if (conditionsTestPanel != null) {
				remove(conditionsTestPanel);
			}
			conditionsTestPanel = buildConditionPanel(state);
			add(conditionsTestPanel, BorderLayout.CENTER);
		}
	}

	private void initializeRunState(WizardState<VTWizardStateKey> state) {
		Boolean b = (Boolean) state.get(VTWizardStateKey.PRECONDITION_CHECKS_RUN);
		testsDone = b == null ? false : b.booleanValue();
	}

	private ConditionTestPanel buildConditionPanel(final WizardState<VTWizardStateKey> state) {

		Program sourceProgram = (Program) state.get(VTWizardStateKey.SOURCE_PROGRAM);
		Program destinationProgram = (Program) state.get(VTWizardStateKey.DESTINATION_PROGRAM);

		VTSession existingResults = (VTSession) state.get(VTWizardStateKey.EXISTING_SESSION);

		List<ConditionTester> list =
			getConditionTests(sourceProgram, destinationProgram, existingResults);
		Collections.sort(list, new ConditionsComparator());
		ConditionTestPanel panel = new ConditionTestPanel(list);
		panel.addListener(new ConditionTestListener() {
			@Override
			public void testsCompleted() {
				state.put(VTWizardStateKey.PRECONDITION_CHECKS_RUN, Boolean.valueOf(testsDone));
				testsDone();
			}
		});
		return panel;
	}

	private void testsDone() {
		testsDone = true;
		notifyListenersOfValidityChanged();
		if (hasAnyErrorStatus()) {
			Msg.showError(getClass(), this, "Warning - Serious Precondition failures",
				"The precondition checks discovered one or more serious problems. \n\n"
					+ "If you continue, your version tracking results may be invalid.\n"
					+ "You should review the errors, cancel this wizard, and correct the problems.");
		}
	}

	private List<ConditionTester> getConditionTests(Program sourceProgram,
			Program destinationProgram, VTSession existingResults) throws SecurityException {
		List<ConditionTester> list = new ArrayList<ConditionTester>();

		List<Class<? extends VTPreconditionValidator>> vtValidatorClasses =
			ClassSearcher.getClasses(VTPreconditionValidator.class);
		for (Class<? extends VTPreconditionValidator> validatorClass : vtValidatorClasses) {
			try {
				Constructor<? extends VTPreconditionValidator> ctor =
					validatorClass.getConstructor(Program.class, Program.class, VTSession.class);
				VTPreconditionValidator validator =
					ctor.newInstance(sourceProgram, destinationProgram, existingResults);
				list.add(validator);
			}
			catch (Exception e) {
				Msg.error(this, "error including VTPreconditionValidator " + validatorClass, e);
			}
		}
		return list;
	}

	@Override
	public WizardPanelDisplayability getPanelDisplayabilityAndUpdateState(
			WizardState<VTWizardStateKey> state) {

		initializeRunState(state);
		return testsDone ? WizardPanelDisplayability.CAN_BE_DISPLAYED
				: WizardPanelDisplayability.MUST_BE_DISPLAYED;
	}

	@Override
	public void leavePanel(WizardState<VTWizardStateKey> state) {
		updateStateObjectWithPanelInfo(state);
	}

	@Override
	public void updateStateObjectWithPanelInfo(WizardState<VTWizardStateKey> state) {
		state.put(VTWizardStateKey.PRECONDITION_CHECKS_RUN, Boolean.valueOf(testsDone));
		state.put(VTWizardStateKey.HIGHEST_PRECONDITION_STATUS, hasAnyErrorStatus());
	}

	private Boolean hasAnyErrorStatus() {
		return conditionsTestPanel.getErrorCount() > 0;
	}

	@Override
	public String getTitle() {
		return "Precondition Checklist";
	}

	@Override
	public void initialize() {
		// do nothing
	}

	@Override
	public boolean isValidInformation() {
		return testsDone;
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

	@Override
	public Dimension getPreferredScrollableViewportSize() {
		return getPreferredSize();
	}

	@Override
	public int getScrollableBlockIncrement(Rectangle visibleRect, int orientation, int direction) {
		return 25;
	}

	@Override
	public boolean getScrollableTracksViewportHeight() {
		return true;
	}

	@Override
	public boolean getScrollableTracksViewportWidth() {
		return true;
	}

	@Override
	public int getScrollableUnitIncrement(Rectangle visibleRect, int orientation, int direction) {
		return 10;
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private class ConditionsComparator implements Comparator<ConditionTester> {
		@Override
		public int compare(ConditionTester o1, ConditionTester o2) {
			return o1.getName().compareTo(o2.getName());
		}
	}
}
