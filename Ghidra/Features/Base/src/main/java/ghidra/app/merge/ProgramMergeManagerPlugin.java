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

import ghidra.app.CorePluginPackage;
import ghidra.app.events.ProgramActivatedPluginEvent;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.services.ProgramManager;
import ghidra.framework.model.DomainFile;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;

import java.awt.Component;
import java.net.URL;

import javax.swing.JComponent;

/**
 * Plugin that provides a merge component provider.
 * 
 * 
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.HIDDEN,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.UNMANAGED,
	shortDescription = "Program Merge Manager",
	description = "Manage merge of Programs",
	servicesProvided = { ProgramManager.class },
	eventsConsumed = { ProgramActivatedPluginEvent.class }
)
//@formatter:on
public class ProgramMergeManagerPlugin extends MergeManagerPlugin implements ProgramManager {

	/**
	 * Constructor for plugin that handles multi-user merge of programs.
	 * @param tool the tool with the active program to be merged
	 * @param mergeManager the merge manager that will control the merge process
	 * @param program the current program
	 */
	public ProgramMergeManagerPlugin(PluginTool tool, ProgramMultiUserMergeManager mergeManager,
			Program program) {
		super(tool, mergeManager, program);
	}

	@Override
	public MergeManagerProvider createProvider() {
		return new MergeManagerProvider(this, "Merge Programs for " + currentDomainObject.getName());
	}

	@Override
	public void processEvent(PluginEvent event) {
		if (event instanceof ProgramActivatedPluginEvent) {
			Program activeProgram = ((ProgramActivatedPluginEvent) event).getActiveProgram();
			currentDomainObject = activeProgram;
		}
	}

	/* (non-Javadoc)
	 * @see ghidra.framework.plugintool.Plugin#dispose()
	 */
	@Override
	protected void dispose() {
		provider.dispose();
	}

	/**
	 * Gets the merge manager associated with this plug-in.
	 * @return the merge manager
	 */
	@Override
	MergeManager getMergeManager() {
		return mergeManager;
	}

	/**
	 * Defines and displays a component for resolving merge conflicts.
	 * @param component the component
	 * @param componentID the identifier for this component
	 */
	@Override
	void setMergeComponent(JComponent component, String componentID) {
		provider.setMergeComponent(component, componentID);
	}

	/**
	 * Sets the merge description at the top of the merge tool.
	 * @param mergeDescription the new description
	 */
	@Override
	void updateMergeDescription(String mergeDescription) {
		provider.updateMergeDescription(mergeDescription);
	}

	/**
	 * Sets the message below the progress meter in the current phase progress area.
	 * @param progressDescription the new text message to display. If null, then the default message is displayed.
	 */
	@Override
	void updateProgressDetails(String progressDescription) {
		provider.updateProgressDetails(progressDescription);
	}

	/**
	 * Sets the percentage of the progress meter that is filled in for the current phase progress area.
	 * @param currentPercentProgress the percentage of the progress bar to fill in from 0 to 100.
	 */
	@Override
	void setCurrentProgress(int currentPercentProgress) {
		provider.setCurrentProgress(currentPercentProgress);
	}

	/**
	 * Displays the default information in the merge tool.
	 */
	@Override
	void showDefaultComponent() {
		provider.showDefaultComponent();
	}

	/**
	 * Enables/disables the Apply button at the bottom of the merge tool.
	 * The Apply button is for applying conflicts.
	 * @param state true means enable the button. false means disable it.
	 */
	@Override
	void setApplyEnabled(boolean state) {
		provider.setApplyEnabled(state);
	}

	/**
	 * Gets the provider for the merge.
	 * @return the provider
	 */
	@Override
	MergeManagerProvider getProvider() {
		return provider;
	}

	public boolean closeOtherPrograms(boolean ignoreChanges) {
		return false;
	}

	public boolean closeAllPrograms(boolean ignoreChanges) {
		return false;
	}

	public boolean closeProgram() {
		return false;
	}

	public boolean closeProgram(Program program, boolean ignoreChanges) {
		return false;
	}

	public Program[] getAllOpenPrograms() {
		ProgramMultiUserMergeManager programMergeManager =
			(ProgramMultiUserMergeManager) mergeManager;
		return new Program[] { programMergeManager.getProgram(MergeConstants.RESULT),
			programMergeManager.getProgram(MergeConstants.LATEST),
			programMergeManager.getProgram(MergeConstants.MY),
			programMergeManager.getProgram(MergeConstants.ORIGINAL) };
	}

	public Program getCurrentProgram() {
		return (Program) currentDomainObject;
	}

	public Program getProgram(Address addr) {
		return null;
	}

	public int getSearchPriority(Program p) {
		return 0;
	}

	public boolean isVisible(Program program) {
		return false;
	}

	@Override
	public Program openProgram(URL ghidraURL, int state) {
		return null;
	}

	public Program openProgram(DomainFile domainFile) {
		return null;
	}

	@Override
	public Program openProgram(DomainFile domainFile, Component dialogParent) {
		return null;
	}

	public Program openProgram(DomainFile df, int version) {
		return null;
	}

	public Program openProgram(DomainFile domainFile, int version, int state) {
		return null;
	}

	public void openProgram(Program program) {
	}

	public void openProgram(Program program, boolean current) {
	}

	public void openProgram(Program program, int state) {
	}

	public void releaseProgram(Program program, Object persistentOwner) {
	}

	public void setCurrentProgram(Program p) {
	}

	public boolean setPersistentOwner(Program program, Object owner) {
		return false;
	}

	public void setSearchPriority(Program p, int priority) {
	}

	public boolean isLocked() {
		return false;
	}

	public void lockDown(boolean state) {
	}
}
