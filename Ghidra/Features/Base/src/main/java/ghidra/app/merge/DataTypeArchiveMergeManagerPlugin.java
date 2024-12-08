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

import javax.swing.JComponent;

import ghidra.app.CorePluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.DataTypeArchive;

/**
 * Plugin that provides a merge component provider for data type archives.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.HIDDEN,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.COMMON,
	shortDescription = "DataType Archive Merge Manager",
	description = "Manage merge of DataType Archives"
)
//@formatter:on
public class DataTypeArchiveMergeManagerPlugin extends MergeManagerPlugin {

	/**
	 * Constructor for plugin that handles multi-user merge of data type archives.
	 * @param tool the tool
	 * @param mergeManager the merge manager that will control the merge process
	 * @param dataTypeArchive the data type archive
	 */
	public DataTypeArchiveMergeManagerPlugin(PluginTool tool,
			DataTypeArchiveMergeManager mergeManager,
			DataTypeArchive dataTypeArchive) {
		super(tool, mergeManager, dataTypeArchive);
	}

	@Override
	public MergeManagerProvider createProvider() {
		return new MergeManagerProvider(this,
			"Merge Data Type Archives for " + currentDomainObject.getName());
	}

	@Override
	public void processEvent(PluginEvent event) {
		// stub
	}

	@Override
	protected void dispose() {
		provider.dispose();
	}

	/**
	 * Gets the merge manager associated with this plug-in.
	 * @return the merge manager
	 */
	@Override
	DataTypeArchiveMergeManager getMergeManager() {
		return (DataTypeArchiveMergeManager) mergeManager;
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
}
