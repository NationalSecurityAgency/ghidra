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

import java.awt.Component;

import javax.swing.JComponent;

import ghidra.util.HelpLocation;

/**
 * This is the base class for defining a step in a {@link WizardModel} to be displayed using
 * a {@link WizardDialog}.
 * <P>
 * A wizard dialog collects information from a user in a step by step process. Each step presents
 * a Gui panel to the user that must be completed and validated before advancing to the next step.
 * <P>
 * Each step in the wizard must implement several methods to support the wizard step's life cycle.
 * The basic life cycle for a step that is shown is initialize(), getComponent(), then repeated
 * calls to isValid() and populateData() while it is showing and being modified, followed by
 * the apply() method when moving on to the next step.
 * <P>
 * In addition, there are several methods that step's must implement that are called when the step
 * is not showing and should not consider any Gui state that it may have (The Gui state may be stale
 * if the user back tracked or it may never have been created or initialized) such as the 
 * isApplicable() and canFinish().
 * <P>
 * Each step must implement the following methods:
 * 
 * <UL>
 * 		<LI> <B>initialize(T data)</B> - This method is called just before the step's Gui component
 * 			is shown. This is were the step should use the information in the passed in data object
 * 	 		to populate its Gui data fields. The component can be lazily created in this method
 * 			if not created in the constructor, as the {@link #getComponent()} will not be called
 * 			before the initialize method is called. Note that the initialize method can possibly
 *  		be called multiple times if the user goes back to a previous panel and then forward
 *  		again.</LI>
 *  
 *   	<LI> <B>isValid()</B> - This method is called repeatedly while the step is showing as the
 *   		step calls back to the model as any Gui component is modified. When the step reports
 *   		back that it is valid, then the next and finish buttons can be enabled. Also, if
 *   		valid, this step's {@link #populateData(Object)} will be called so its data can
 *   		be seen by follow-on steps in their {@link #canFinish(Object)} calls.</LI>
 *   
 *   	<LI> <B>canFinish(T data)</B> - This method is called on steps that follow the current step
 *   		if the current step is valid. When implementing this method, the data in the step's Gui
 *   		should be ignored (it may not have been initialized yet or it may be stale if the user
 *   		back tracked) and its determination if it can finish should be done
 *   		purely based on the information in the passed in data object. The idea is that if 
 *   		a step returns true for canFinish(), it does not need to be shown before the wizard
 *   		can complete.</LI>
 *   	<LI>
 *   		<B>populateData(T data)</B> - This method is called on the current step whenever the 
 *   		isValid() method of the current step returns true. The step should simply transfer data
 *   		from it's Gui component to the data component. It should not do any time consuming
 *   		operations in this method.</LI>
 *   	<LI>
 *   		<B>apply(T data)</B> - This method is called on each step when it is the current step 
 *   		and the next button is pressed. It is also called on each follow-on step when the finish
 *   		button is pressed. Expensive operations should be done here when a step is completed and 
 *   		moving to the next step. Typically, the implementer of the apply method should perform
 *   		the operation in a task. One example, might be the user is picking files to open, the
 *   		populateData() method might copy the file names to the data object, but the apply() 
 *   		method is used to actually open the files and put them into the data object. Most
 *   		wizard steps should just return true here.</LI>
 *   
 *   	<LI>
 *   		<B>isApplicable(T data)</B> - this method is called to see if a step is applicable based
 *   		on choices made in previous steps.</LI>
 *   </UL>
 * 
 * @param <T> the custom data object for wizard
 */
public abstract class WizardStep<T> {
	private String title;
	private HelpLocation helpLocation;
	private WizardModel<T> model;
	private String statusMessage;

	/**
	 * Constructor
	 * @param model the wizard model
	 * @param title the title for the wizard step (can be null and set later)
	 * @param help the help location for the wizard step (can be null and set later)
	 */
	protected WizardStep(WizardModel<T> model, String title, HelpLocation help) {
		this.model = model;
		this.title = title;
		this.helpLocation = help;
	}

	/**
	 * Sets the title for this step. Typically, this method is only used if the title is data
	 * dependent.
	 * @param title the new title for the step.
	 */
	protected void setTitle(String title) {
		this.title = title;
	}

	/**
	 * Sets the help location for this step. Typically, this method is only used if the help is data
	 * dependent.
	 * @param help the new help location for the step.
	 */
	protected void setHelpLocation(HelpLocation help) {
		this.helpLocation = help;
	}

	/**
	 * Initialize the panel as though this is the first time it is
	 * being displayed. This is where the step should initialize all Gui fields from the given
	 * data object.
	 * <P>
	 * Creating the Gui component can be done lazily in this method if not done in 
	 * the constructor, as the initialize() method will always be called before the getComponent()
	 * method is called. Just be careful as this method can be called multiple times if the user
	 * backtracks in the wizard dialog.
	 * @param data the custom wizard data containing the information from all previous steps.
	 */
	public abstract void initialize(T data);

	/**
	 * Checks if the Gui component has completed and has valid information. Typically, whenever the
	 * Gui state changes, it notifies the model using the statusChangedCallback, which in turn
	 * will call the isValid() method on the current step. If the current step is valid, it will
	 * in turn trigger additional calls to follow-on steps to see if the wizard can finish.
	 * @return true if the Gui component has completed and valid information and is eligible to
	 * continue to the next step.
	 */
	public abstract boolean isValid();

	/**
	 * Reports true if the information in the given data object is sufficient enough that this
	 * step does not need to be shown in order to complete the wizard. It is only called on steps
	 * subsequent to the current step. Wizard steps should only make their decisions based on the
	 * information in the data object and not their internal GUI, which might not have even been
	 * initialized at this point. This method is only called on steps whose
	 * {@link #isApplicable(Object)} method returns true.
	 * @param data the custom wizard data containing the information from all previous steps.
	 * @return true if this step does not need to be shown before completing the wizard
	 */
	public abstract boolean canFinish(T data);

	/**
	 * This method should populate the given data object with information from its Gui component.
	 * @param data the custom wizard data containing the information from all previous steps.
	 */
	public abstract void populateData(T data);

	/**
	 * This method is called on the current step when advancing to the next step. It is also called
	 * on all subsequent steps when finishing the wizard as those steps are skipped because the
	 * finish button was pressed. This method is for steps to perform more extensive operations 
	 * when moving on to subsequent steps. Most steps can just return true here as simple data
	 * will be added during the {@link #populateData(Object)} method.
	 * @param data the custom wizard data containing the information from all previous steps.
	 * @return true if the apply completes successfully.
	 */
	public abstract boolean apply(T data);

	/**
	 * Returns true if a step is applicable base on the information in the given data object. 
	 * Data from previous steps may make a subsequent step applicable or not.
	 * @param data the custom wizard data containing the information from all previous steps.
	 * @return
	 */
	public boolean isApplicable(T data) {
		return true;
	}

	/**
	 * Get the panel object
	 * @return JPanel panel
	 */
	public abstract JComponent getComponent();

	/**
	 * Get the title for this step.
	 * @return the title for this step
	 */
	public String getTitle() {
		return title;
	}

	/**
	 * Returns the help content location for this panel. 
	 * 
	 * @return String help location for this panel; return null if default help
	 * location should be used.
	 */
	public HelpLocation getHelpLocation() {
		return helpLocation;
	}

	/**
	 * Returns the component, if any, that should receive focus when this panel is shown.
	 * @return the component, if any, that should receive focus when this panel is shown; null
	 *         if no preferred focus component exists.
	 */
	public Component getDefaultFocusComponent() {
		return null;
	}

	/**
	 * Returns the current status message to be displayed in the wizard dialog for this step.
	 * @return the current status message to be displayed in the wizard dialog for this step.
	 */
	protected String getStatusMessage() {
		return statusMessage;
	}

	/**
	 * Sets the current status message to be displayed in the wizard dialog for this step.
	 * @param message the message to display in the wizard dialog
	 */
	protected void setStatusMessage(String message) {
		this.statusMessage = message;
	}

	/**
	 * Clears the current status message for this step.
	 */
	protected void clearStatus() {
		statusMessage = null;
	}

	/**
	 * Subclasses can call this method to notify the wizard dialog that the user made some
	 * change to the current step's Gui state. This will trigger calls to the {@link #isValid()}
	 * and possibly {@link #populateData(Object)}
	 */
	protected void notifyStatusChanged() {
		model.statusChanged(this);
	}

	/**
	 * Called for steps to possibly do any clean up.
	 * @param data the custom data object
	 */
	protected void dispose(T data) {
		// for sub-classes to override if needed
	}

}
