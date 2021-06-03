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
package ghidra.app.merge.tool;

import docking.ComponentProvider;
import ghidra.app.CorePluginPackage;
import ghidra.app.events.ProgramActivatedPluginEvent;
import ghidra.app.events.ProgramLocationPluginEvent;
import ghidra.app.merge.MergeConstants;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.framework.main.ProgramaticUseOnly;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.util.ProgramLocation;

//@formatter:off
@PluginInfo(
	status = PluginStatus.STABLE,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.TESTING,
	shortDescription = "Listing Merge",
	description = "Merge Panel for Listing",
	eventsConsumed = { ProgramLocationPluginEvent.class }
)
//@formatter:on
public class ListingMergePanelPlugin extends Plugin implements ProgramaticUseOnly {
	private ListingMergePanelProvider provider;

	/**
	 * Constructor
	 * @param tool merge tool
	 * @param mergePanel merge panel
	 */
	public ListingMergePanelPlugin(PluginTool tool, ListingMergePanel mergePanel) { 
		super(tool); 
		createProvider(mergePanel);
		firePluginEvent(new ProgramActivatedPluginEvent(this.getName(),
			mergePanel.getProgram(MergeConstants.RESULT)));
		createActions();
	}
	 
	private void createActions() {
		ViewInstructionDetailsAction viewDetailsAction = new ViewInstructionDetailsAction(this);
		tool.addAction(viewDetailsAction);
	}

	public ComponentProvider getProvider() {
		return provider;
	}
	
	/* (non-Javadoc)
	 * @see ghidra.framework.plugintool.Plugin#dispose()
	 */
	@Override
    public void dispose() { 
		if (provider != null) {
			provider.dispose();
			firePluginEvent(new ProgramActivatedPluginEvent(this.getName(), null));
		}
	}
	public static String getDescription() {
		return "Listing Merge";
	}

	public static String getDescriptiveName() {
		return "Merge Panel for Listing";
	}

	public static String getCategory() {
		return "Test Unmanaged";
	}

	private void createProvider(ListingMergePanel mergePanel) {
		provider = new ListingMergePanelProvider(tool,this, getName(), mergePanel); 
		tool.addComponentProvider(provider, false);
	}

	
	@Override
    public void processEvent(PluginEvent event) {

        if (event instanceof ProgramLocationPluginEvent) {
        	ProgramLocationPluginEvent evt = (ProgramLocationPluginEvent)event;
            ProgramLocation location = evt.getLocation();
            ListingMergePanel mergePanel = (ListingMergePanel)provider.getComponent();
            mergePanel.goTo(location, true);
        }
	}	
}
