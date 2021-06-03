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
package ghidra.app.merge;

import ghidra.framework.main.ProgramaticUseOnly;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.*;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

import java.rmi.NoSuchObjectException;

import javax.swing.JComponent;

/**
 * Plugin that provides a merge component provider.
 */
public abstract class MergeManagerPlugin extends Plugin implements ProgramaticUseOnly,
		DomainObjectListener {

	protected MergeManager mergeManager;
	protected MergeManagerProvider provider;
	protected UndoableDomainObject currentDomainObject;

	/**
	 * Constructor for plugin that handles multi-user merge of programs.
	 * @param tool the tool with the active program to be merged
	 * @param mergeManager the merge manager that will control the merge process
	 * @param domainObject the current domain object
	 */
	public MergeManagerPlugin(PluginTool tool, MergeManager mergeManager,
			UndoableDomainObject domainObject) {
		super(tool);
		this.mergeManager = mergeManager;
		this.currentDomainObject = domainObject;
		provider = createProvider();
		addDomainChangeListeners();
	}

	private void addDomainChangeListeners() {
		for (DomainObject dobj : getAllOpenDomainObjects()) {
			dobj.addListener(this);
		}
	}

	private void removeDomainChangeListeners() {
		for (DomainObject dobj : getAllOpenDomainObjects()) {
			dobj.removeListener(this);
		}
	}

	/**
	 * Creates the provider that will be displayed in the merge tool. This shows the merge
	 * progress to the user and lets the user resolve conflicts.
	 * Any class that extends this plugin must provide its own MergeManagerProvider here that will 
	 * be shown to the user for the merge.
	 * @return the merge provider associated with this plugin.
	 */
	public abstract MergeManagerProvider createProvider();

	@Override
	public abstract void processEvent(PluginEvent event);

	/* (non-Javadoc)
	 * @see ghidra.framework.plugintool.Plugin#dispose()
	 */
	@Override
	protected void dispose() {
		provider.dispose();
		removeDomainChangeListeners();
	}

	public static String getDescription() {
		return "Manage merge of Domain Object";
	}

	public static String getDescriptiveName() {
		return "Domain Object Merge Manager";
	}

	public static String getCategory() {
		return "Unmanaged";
	}

	@Override
	protected boolean canClose() {
		provider.cancelCallback(false);
		return false;
	}

	/**
	 * Gets the merge manager associated with this plug-in.
	 * @return the merge manager
	 */
	MergeManager getMergeManager() {
		return mergeManager;
	}

	/**
	 * Defines and displays a component for resolving merge conflicts.
	 * @param component the component
	 * @param componentID the identifier for this component
	 */
	void setMergeComponent(JComponent component, String componentID) {
		provider.setMergeComponent(component, componentID);
	}

	/**
	 * Removes a component that is no longer needed for resolving merge conflicts.
	 * @param component the component
	 */
	void removeMergeComponent(JComponent component) {
		provider.removeMergeComponent(component);
	}

	/**
	 * Sets the merge description at the top of the merge tool.
	 * @param mergeDescription the new description
	 */
	void updateMergeDescription(String mergeDescription) {
		provider.updateMergeDescription(mergeDescription);
	}

	/**
	 * Sets the message below the progress meter in the current phase progress area.
	 * @param progressDescription the new text message to display. If null, then the default message is displayed.
	 */
	void updateProgressDetails(String progressDescription) {
		provider.updateProgressDetails(progressDescription);
	}

	/**
	 * Sets the percentage of the progress meter that is filled in for the current phase progress area.
	 * @param currentPercentProgress the percentage of the progress bar to fill in from 0 to 100.
	 */
	void setCurrentProgress(int currentPercentProgress) {
		provider.setCurrentProgress(currentPercentProgress);
	}

	/**
	 * Displays the default information in the merge tool.
	 */
	void showDefaultComponent() {
		provider.showDefaultComponent();
	}

	/**
	 * Enables/disables the Apply button at the bottom of the merge tool.
	 * The Apply button is for applying conflicts.
	 * @param state true means enable the button. false means disable it.
	 */
	void setApplyEnabled(boolean state) {
		provider.setApplyEnabled(state);
	}

	/**
	 * Gets the provider for the merge.
	 * @return the provider
	 */
	MergeManagerProvider getProvider() {
		return provider;
	}

	private boolean domainFileErrorOccurred;

	@Override
	public void domainObjectChanged(DomainObjectChangedEvent ev) {
		// Only concerned about error which will be the only change record
		DomainObjectChangeRecord docr = ev.getChangeRecord(0);
		if (!domainFileErrorOccurred && docr.getEventType() == DomainObject.DO_OBJECT_ERROR) {
			domainFileErrorOccurred = true;
			String msg;
			Throwable t = (Throwable) docr.getNewValue();
			if (t instanceof NoSuchObjectException) {
				msg =
					"Merge is closing due to an unrecoverable error!"
						+ "\nThis error can be caused when your system becomes"
						+ "\nsuspended or due to a server/network problem.";
			}
			else {
				msg =
					"Merge is closing due to an unrecoverable error!"
						+ "\n \nSuch failures are generally due to an IO Error caused"
						+ "\nby the local filesystem or server.";
			}

			//abort();
			Msg.showError(this, tool.getToolFrame(), "Severe Error Condition", msg);
			provider.cancelCallback(true);
			return;
		}
	}

	public boolean closeAllDomainObjects(boolean ignoreChanges) {
		return false;
	}

	public boolean closeDomainObject() {
		return false;
	}

	public boolean closeDomainObject(UndoableDomainObject domainObject, boolean ignoreChanges) {
		return false;
	}

	public UndoableDomainObject[] getAllOpenDomainObjects() {
		return new UndoableDomainObject[] { mergeManager.getDomainObject(MergeConstants.RESULT),
			mergeManager.getDomainObject(MergeConstants.LATEST),
			mergeManager.getDomainObject(MergeConstants.MY),
			mergeManager.getDomainObject(MergeConstants.ORIGINAL) };
	}

	public UndoableDomainObject getCurrentDomainObject() {
		return currentDomainObject;
	}

	public int getSearchPriority(UndoableDomainObject domainObject) {
		return 0;
	}

	public boolean isVisible(UndoableDomainObject domainObject) {
		return false;
	}

	public Program openDomainObject(DomainFile domainFile) {
		return null;
	}

	public Program openDomainObject(DomainFile df, int version) {
		return null;
	}

	public Program openDomainObject(DomainFile domainFile, int version, int state) {
		return null;
	}

	public void openDomainObject(UndoableDomainObject domainObject) {
	}

	public void openDomainObject(UndoableDomainObject domainObject, boolean current) {
	}

	public void openDomainObject(UndoableDomainObject domainObject, int state) {
	}

	public void releaseDomainObject(UndoableDomainObject domainObject, Object persistentOwner) {
	}

	public void setCurrentDomainObject(UndoableDomainObject domainObject) {
	}

	public boolean setPersistentOwner(UndoableDomainObject domainObject, Object owner) {
		return false;
	}

	public void setSearchPriority(UndoableDomainObject domainObject, int priority) {
	}

}
