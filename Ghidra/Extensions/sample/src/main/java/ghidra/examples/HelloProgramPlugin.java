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

import ghidra.app.ExamplesPluginPackage;
import ghidra.app.events.ProgramActivatedPluginEvent;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;

import javax.swing.JOptionPane;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;


/**
  * Plugin to demonstrate handling of Program within a plugin.  This introduces
  * Event handling, Services, and Dependencies on other plugins.
  */

//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = ExamplesPluginPackage.NAME,
	category = PluginCategoryNames.EXAMPLES,
	shortDescription = "Hello Program",
	description = "Sample plugin for accessing a Program object",
	servicesRequired = { ProgramManager.class },
	eventsConsumed = { ProgramActivatedPluginEvent.class }
)
//@formatter:on
public class HelloProgramPlugin extends Plugin {

    private DockingAction helloProgramAction;

    /** 
      * Constructor
      */
    public HelloProgramPlugin(PluginTool tool) {

        super(tool);

        // set up list of actions.
        setupActions();

    }

    private void setupActions() {
        DockingAction action;

        // add menu action for Hello->Program
        action = new DockingAction("Hello Program", getName() ) {
            @Override
            public void actionPerformed( ActionContext context ) {
                sayHelloProgram();
            }
        };
        action.setEnabled( getProgram() != null );        
        action.setMenuBarData( new MenuData( new String[]{"Misc","Hello Program"}, "Hello" ) );
        tool.addAction(action);

        // remember this action so I can enable/disable it later
        helloProgramAction = action;
    }

    /**
     * Put event processing code here.
     */
    @Override
    public void processEvent(PluginEvent event) {
        if (event instanceof ProgramActivatedPluginEvent) {
        	helloProgramAction.setEnabled(((ProgramActivatedPluginEvent)event).getActiveProgram() != null);
        }
    }


    /**
     * Callback for Hello->Program menu option
     */
    protected void sayHelloProgram() {
        Program p = getProgram();

        if (p == null) {
            return;
        }

        announce("Hello " + p.getName());
    }

    protected void announce(String message) {
        JOptionPane.showMessageDialog(null,message,"Hello World",
                                      JOptionPane.INFORMATION_MESSAGE);
    }


    /**
     * Get the currently open program using the ProgramManager service.
     */
    private Program getProgram() {

		ProgramManager pm = tool.getService(ProgramManager.class);
		if (pm != null) {
			return pm.getCurrentProgram();
		}
		return null;
    }

}
