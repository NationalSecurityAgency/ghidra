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
package ghidra.examples;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.app.ExamplesPluginPackage;
import ghidra.app.context.ListingActionContext;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.ProgramManager;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramChangeRecord;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;

/**
 * Sample plugin for dealing with Programs. The base class handles
 * the event processing and enabling/disabling of actions. This
 * allows the derived class to be very simple.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = ExamplesPluginPackage.NAME,
	category = PluginCategoryNames.EXAMPLES,
	shortDescription = "Plugin starter template",
	description = "Copy this plugin and use as a template for creating a new plugin.",
	servicesRequired = { ProgramManager.class /* list of service classes that this plugin requires */ },
	servicesProvided = { /* list of service classes that this plugin registers with Plugin.registerServiceProvided() */ }
)
//@formatter:on
public class TemplateProgramPlugin extends ProgramPlugin implements DomainObjectListener {

	private DockingAction action;

	/*******************************************************************
	*
	*                 Standard Plugin Constructor
	*
	*******************************************************************/
	public TemplateProgramPlugin(PluginTool tool) {

		super(tool, true, // true means this plugin consumes ProgramLocation events
			false); // false means this plugin does not consume
					// ProgramSelection events
					// the base class ProgramPlugin handles all the event registering

		// set up list of actions.
		setupActions();
	}

	/**
	 * This is the callback method for DomainObjectChangedEvents.
	 */
	@Override
	public void domainObjectChanged(DomainObjectChangedEvent ev) {
		for (int i = 0; i < ev.numRecords(); i++) {
			DomainObjectChangeRecord record = ev.getChangeRecord(i);
			if (record instanceof ProgramChangeRecord) {
				@SuppressWarnings("unused")
				ProgramChangeRecord r = (ProgramChangeRecord) record;
				// code for processing the record...
				// ...
			}
		}
	}

	/**
	 * Called when the program is opened.
	 */
	@Override
	protected void programActivated(Program program) {
		program.addListener(this);
	}

	/**
	 * Called when the program is closed.
	 */
	@Override
	protected void programDeactivated(Program program) {
		program.removeListener(this);
	}

	/*******************************************************************
	********************************************************************
	**
	**
	**      Function 1
	**
	**
	********************************************************************
	*******************************************************************/
	private void Function_1() {
		// do something with a program location
		Msg.info(this, getPluginDescription().getName() + ": Program Location==> " +
			currentLocation.getAddress());
	}

	/**
	* Set up Actions
	*/
	private void setupActions() {

		//
		// Function 1
		//
		action = new DockingAction("Function 1 Code", getName()) {
			@Override
			public void actionPerformed(ActionContext e) {
				Function_1();
			}

			@Override
			public boolean isValidContext(ActionContext context) {
				return context instanceof ListingActionContext;
			}
		};
		action.setEnabled(false);

		action.setMenuBarData(
			new MenuData(new String[] { "Misc", "Menu", "Menu item 1" }, null, null));

		action.setHelpLocation(
			new HelpLocation("SampleHelpTopic", "TemplateProgramPlugin_Anchor_Name"));
		tool.addAction(action);
	}

}
