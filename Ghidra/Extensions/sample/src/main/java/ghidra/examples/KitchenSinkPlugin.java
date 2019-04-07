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
import ghidra.app.events.ProgramLocationPluginEvent;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.ProgramManager;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;

import java.awt.Event;
import java.awt.event.KeyEvent;

import javax.swing.*;

import resources.ResourceManager;
import docking.ActionContext;
import docking.action.*;

/**
  * Class description goes here
  *
  */
//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = ExamplesPluginPackage.NAME,
	category = PluginCategoryNames.EXAMPLES,
	shortDescription = "Kitchen Sink hello",
	description = "Sample plugin to demonstrate services and action enablement, hello world.",
	servicesProvided = { HelloWorldService.class },
	servicesRequired = { ProgramManager.class },
	eventsProduced = { ProgramLocationPluginEvent.class }
)
//@formatter:on
public class KitchenSinkPlugin extends ProgramPlugin {
	private final static String NEXT_IMAGE = "images/right.png";
	private final static String PREV_IMAGE = "images/left.png";

    private DockingAction helloProgramAction;
    private Program program;

    /**
      * Constructor
      */ 
    public KitchenSinkPlugin(PluginTool tool) {

        super(tool, false, false);

        // set up list of services.
        setupServices();

        // set up list of actions.
        setupActions(); 
    }

    private void setupServices() {
    	registerServiceProvided(HelloWorldService.class,
        	new HelloWorldService() {
	            public void sayHello() {
    	            announce("Hello");
        	    }
        	});
    }

    private void setupActions() {
        DockingAction action = new DockingAction("Hello World", getName() ) {
            @Override
            public void actionPerformed( ActionContext context ) {
                Msg.info(this, "Hello World:: action");
                announce("Hello World");
            }
        };
        action.setEnabled( true );
        String helloGroup = "Hello";
        ImageIcon prevImage = ResourceManager.loadImage(PREV_IMAGE);
        action.setMenuBarData( new MenuData( new String[] {"Misc", "Hello World"}, prevImage, helloGroup ) );
        action.setPopupMenuData( new MenuData( new String[] {"Hello World"}, prevImage, helloGroup ) );
        action.setKeyBindingData( new KeyBindingData( KeyStroke.getKeyStroke('H', Event.CTRL_MASK ) ) );
        action.setToolBarData( new ToolBarData( prevImage, helloGroup ) );
        action.setDescription("Hello World");
        action.setHelpLocation(new HelpLocation("SampleHelpTopic", "KS_Hello_World"));

        tool.addAction(action);

        action = new DockingAction("Hello Program", getName() ) {
            @Override
            public void actionPerformed( ActionContext context ) {
                Msg.info(this, "Hello Program:: action");
                sayHelloProgram();        
            }
        };
        action.setEnabled(false);
        ImageIcon nextImage = ResourceManager.loadImage(NEXT_IMAGE);
        action.setMenuBarData( new MenuData( new String[]{"Misc", "Hello Program"}, nextImage, helloGroup ) );
        action.setKeyBindingData( new KeyBindingData( KeyStroke.getKeyStroke(KeyEvent.VK_P, Event.CTRL_MASK ) ) );
        action.setToolBarData( new ToolBarData( nextImage, helloGroup ) );
        action.setDescription("Hello Program");
        action.setHelpLocation(new HelpLocation("SampleHelpTopic", "KS_Hello_Program"));
        tool.addAction(action);

        // remember this action so I can enable/disable it later
        helloProgramAction = action;
    }

	@Override
    protected void programActivated(Program activatedProgram) {
		helloProgramAction.setEnabled(true);
        this.program = activatedProgram; 
	}
	@Override
    protected void programDeactivated(Program deactivatedProgram) {
		if (this.program == deactivatedProgram) {
			helloProgramAction.setEnabled(false);
			this.program = null;
		}
	}
    protected void sayHelloProgram() {

        if (program == null) {
            return;
        }

        announce("Hello " + program.getName());
    }

    protected void announce(String message) {
        JOptionPane.showMessageDialog(null,message,"Hello World",
                                      JOptionPane.INFORMATION_MESSAGE);
    }
    
  	/**
	 * If your plugin maintains configuration state, you must save that state information
     * to the SaveState object in this method.  For example, the Code Browser can be configured
     * to show fields in different colors.  This is the method where that type
     * information is saved.
	 */
    @Override
    public void writeConfigState(SaveState saveState) {
    }
	/**
	 * If your plugin maintains configuration state, this is where you read it
     * back in.
	 */
    @Override
    public void readConfigState(SaveState saveState) {
    }
}





