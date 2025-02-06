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
package docking.wizard;

import java.awt.Dimension;
import java.util.ArrayList;
import java.util.List;

import javax.swing.Icon;
import javax.swing.JComponent;

/**
 * This is the main class for defining the steps and GUI for a {@link WizardDialog}.
 * <P>
 * A wizard dialog is a dialog that uses multiple input Gui panels to gather all the
 * information required before doing some complex action. Typically, a wizard dialog is used when 
 * the user input is best gathered in steps, so as to not overwhelm the user with an overly complex
 * screen. Additionally, the information from one step may determine which follow-on steps
 * are needed.
 * <P>
 * To create a wizard dialog, the developer needs to create the following:<br>
 * <OL>
 *    <LI> A class that extends this WizardModel. </LI>
 *    <LI> One or more classes that extend {@link WizardStep}<br>
 *    <LI> A data class that holds that data being collected by this wizard.<br> 
 * </OL>
 *
 * Subclasses must at a minimum implement two methods.
 * <OL>
 * 	   <LI> AddWizardSteps() - This is where the model defines the ordered list of
 * 			 {@link WizardStep} for this wizard.
 * 	   <LI> doFinish() - This is where the model should perform the main action of the wizard. This
 * 			will be called when the user presses the <B>Finish</B> button and all the panels have
 * 			had a chance to update the wizard data object.</LI>
 * </OL>
 *
 * Optionally, there are several additional methods clients may want to override.
 * <OL>
 * 		<LI>dispose() - This will be called when the wizard is completed or cancelled and this is
 * 			where any cleanup, if any, should be done, including cleaning up the data object if
 * 			necessary. The super of this method will call dispose on each wizard step, so that
 * 			 won't be necessary as long as this overridden dispose() calls super.dispose();</LI>
 * 	  	<LI>cancel() - This will only be called if the dialog is cancelled. This is a chance to  
 * 		    perform cleanup that should only be done when the operation is cancelled.
 * 			This is in addition to any cleanup in the dispose() call. This is not normally needed.
 * 			An example of where this might be useful is suppose the purpose of the wizard is to
 * 			pick and open two related files. If the wizard completes successfully, then the two
 * 			files are supposed to remain open after the wizard is closed. However, suppose after
 * 			one step that opened the first file, the user cancels the operation. Then you would 
 * 			want to close the first file that was opened in this cancelled cancel() call, because
 * 			you don't want to do it in the dispose() since that will be called even if the wizard
 * 			completed.</LI>
 * 		<LI>getPreferredSize() - By default, this will return a preferred size that is the biggest
 * 			width and height of all the preferred sizes of the step panels. Override this to 
 * 			simply specify the preferred size of the dialog.</LI>
 * </OL>
 * 
 * @param <T> the data object for this wizard
 */
public abstract class WizardModel<T> {
	private List<WizardStep<T>> wizardSteps = new ArrayList<>();
	private int currentStepIndex = 0;
	protected T data;
	protected WizardDialog wizardDialog;
	private WizardStep<T> currentStep;
	private String title;
	private Icon wizardIcon;
	private boolean completed = false;

	// The busy flag is not used for threading. Is is simply set while performing the apply()
	// calls which can be lengthy. Its only purpose is to for disabling the various dialog buttons
	// while the performing these potentially expensive calls. It will only ever be set or 
	// checked on the swing thread.
	private boolean busy;

	/**
	 * Constructor for a wizard model without an icon.
	 * @param title the title for the wizard dialog.
	 * @param data the data object that will be used to store wizard data. This will typically be
	 * a simple data container designed specifically for this wizard.
	 */
	protected WizardModel(String title, T data) {
		this(title, data, null);
	}

	/**
	 * Constructor for a wizard model with an icon
	 * @param title the title for the wizard dialog.
	 * @param data the data object that will be used to store wizard data. This will typically be
	 * a simple data container designed specifically for this wizard.
	 * @param wizardIcon the icon to display on the wizard
	 */
	protected WizardModel(String title, T data, Icon wizardIcon) {
		this.title = title;
		this.data = data;
		this.wizardIcon = wizardIcon;
	}

	/**
	 * This method defines the wizard step objects in the order that will be displayed.
	 * @param steps the wizard steps
	 */
	protected abstract void addWizardSteps(List<WizardStep<T>> steps);

	/**
	 * This method is called when the user presses the "Finish" button and all the steps have
	 * completed their apply() methods successfully.
	 * @return true if the model successfully completes the wizard. If false is returned, the wizard
	 * will not be closed.
	 */
	protected abstract boolean doFinish();

	/**
	 * Subclasses should override this method if they have special cleanup that only needs to
	 * be done if the wizard is cancelled. Otherwise, all cleanup should be done in the
	 * {@link #dispose()} method which is called whether or not the dialog is cancelled.
	 */
	protected void cancel() {
		// For subclasses to clean up specifically if cancelled. The dispose() will also be called
		// which, typically, is sufficient to clean up whether the wizard completed fully or was
		// cancelled.
	}

	/**
	 * Returns the title of this wizard.
	 * @return the title of this wizard
	 */
	public String getTitle() {
		return title;
	}

	/**
	 * Returns the icon for this wizard.
	 * @return the icon for this wizard
	 */
	public Icon getIcon() {
		return wizardIcon;
	}

	/**
	 * Returns the current status message for the wizard.
	 * @return the current status message for the wizard
	 */
	public String getStatusMessage() {
		return getCurrentStep().getStatusMessage();
	}

	/**
	 * Completes the wizard. Gives each remaining panel a chance to validate and populate the data
	 * object before calling the {@link #doFinish()} method where subclasses can do the final task.
	 */
	public final void finish() {
		if (!canFinish()) {
			return;
		}
		int failedStep = applyRemainingSteps();

		if (failedStep >= 0) {
			setWizardStep(failedStep);
			return;
		}
		boolean success = doFinish();
		if (success) {
			completed = true;
			wizardDialog.close();
		}
	}

	/**
	 * Calls dispose() on all the wizard steps. Subclasses can override this do do additional
	 * cleanup if needed.
	 */
	public void dispose() {
		for (WizardStep<T> step : wizardSteps) {
			step.dispose(data);
		}
	}

	/**
	 * Returns the data object which is populated by the various wizard steps as they completed.
	 * @return the data object
	 */
	public T getData() {
		return data;
	}

	/**
	 * Returns true if the wizard was cancelled.
	 * @return true if the wizard was cancelled
	 */
	public boolean wasCancelled() {
		return !completed;
	}

	/**
	 * Returns the current {@link WizardStep}.
	 * @return the current wizard step
	 */
	public WizardStep<T> getCurrentStep() {
		return currentStep;
	}

	/**
	 * Returns true if the "Back" button should be enabled.
	 * @return true if the "Back" button should be enabled
	 */
	public boolean canGoBack() {
		return !busy && currentStepIndex > 0;
	}

	/**
	 * Returns true if the "Next" button should be enabled.
	 * @return true if the "Next" button should be enabled
	 */
	public boolean canGoNext() {
		if (busy) {
			return false;
		}
		currentStep.clearStatus();
		if (!currentStep.isValid()) {
			return false;
		}
		currentStep.populateData(data);
		return findNextApplicableStep() >= 0;
	}

	/**
	 * Returns true if the "Finish" button should be enabled.
	 * @return true if the "Finish" button should be enabled
	 */
	public boolean canFinish() {
		if (busy) {
			return false;
		}
		if (!currentStep.isValid()) {
			return false;
		}

		// flush current step's gui info to data object so follow-on steps can see the current
		// changes when deciding if they can finish
		currentStep.populateData(data);

		// All follow-on steps should evaluate if the current data object has all the required
		// info to finish. The follow-on steps can change the data, but should only do so based
		// on the values in the data object. Anything in their gui data should be ignored in
		// their canFinish() methods as it could be stale after the user backed up and made changes.
		for (int i = currentStepIndex + 1; i < wizardSteps.size(); i++) {
			WizardStep<T> step = wizardSteps.get(i);
			if (step.isApplicable(data) && !step.canFinish(data)) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Returns true if the cancel button should be enabled. The only time this is disabled is
	 * when the wizard is performing some expensive operation between steps.
	 * @return true if the cancel button should be enabled
	 */
	public boolean canCancel() {
		return !busy;
	}

	/**
	 * Returns the wizard back to the previous step.
	 */
	public void goBack() {
		if (canGoBack()) {
			setWizardStep(findPreviousApplicableStep());
		}
	}

	/**
	 * Advances the wizard to the next step.
	 */
	public void goNext() {
		if (!canGoNext()) {
			return;
		}
		boolean success = apply();
		if (success) {
			setWizardStep(findNextApplicableStep());
		}
		else {
			wizardDialog.statusChanged();
		}
	}

	/**
	 * Returns the preferred size of the panels in the wizard dialog. By default the preferred
	 * size is the largest size of any panels that have been created at construction time
	 * (components are not required to be constructed until they are shown).
	 * Subclasses can override this method to just hard code a preferred size for the dialog.
	 * @return the preferred size of the panels in the wizard dialog
	 */
	protected Dimension getPreferredSize() {
		int width = 300;
		int height = 200;
		for (WizardStep<T> step : wizardSteps) {
			JComponent c = step.getComponent();
			if (c != null) {
				Dimension preferredSize = c.getPreferredSize();
				width = Math.max(width, preferredSize.width);
				height = Math.max(height, preferredSize.height);
			}
		}
		return new Dimension(width, height);
	}

	void initialize(WizardDialog dialog) {
		addWizardSteps(wizardSteps);
		setWizardStep(0);
		this.wizardDialog = dialog;
	}

	private boolean apply() {
		busy = true;
		try {
			return currentStep.apply(data);
		}
		finally {
			busy = false;
		}
	}

	private int applyRemainingSteps() {
		busy = true;
		try {
			for (int i = currentStepIndex; i < wizardSteps.size(); i++) {
				WizardStep<T> step = wizardSteps.get(i);
				if (step.isApplicable(data) && !step.apply(data)) {
					return i;		// applicable step failed to apply, return failed step index
				}
			}
		}
		finally {
			busy = false;
		}
		return -1;
	}

	private void setWizardStep(int stepIndex) {
		currentStepIndex = stepIndex;
		currentStep = wizardSteps.get(currentStepIndex);
		currentStep.initialize(data);
		notifyWizardStepChanged();
	}

	private void notifyWizardStepChanged() {
		if (wizardDialog != null) {
			wizardDialog.wizardStepChanged(currentStep);
		}
	}

	protected void statusChanged(WizardStep<T> step) {
		if (wizardDialog != null && step == currentStep) {
			wizardDialog.statusChanged();
		}
	}

	protected void setStatusMessage(String statusMessage) {
		currentStep.setStatusMessage(statusMessage);
	}

	private int findNextApplicableStep() {
		for (int i = currentStepIndex + 1; i < wizardSteps.size(); i++) {
			if (wizardSteps.get(i).isApplicable(data)) {
				return i;
			}
		}
		return -1;
	}

	private int findPreviousApplicableStep() {
		for (int i = currentStepIndex - 1; i >= 1; i--) {
			if (wizardSteps.get(i).isApplicable(data)) {
				return i;
			}
		}
		return 0;		// step 0 is always applicable
	}
}
