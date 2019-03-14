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

import ghidra.app.context.ListingActionContext;
import ghidra.app.events.ProgramActivatedPluginEvent;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.*;
import ghidra.program.model.listing.Program;
import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;

/*******************************************************************
*
*         Here's an example of a plugin for a GHIDRA tool.
*
*******************************************************************/
/**
 * NOTE: this example class is abstract so that it does not appear in the
 * list of valid plugins. Real plugins should not be abstract.
 */
public abstract class Template extends Plugin {
	private DockingAction function_1Action;
	private DockingAction function_2Action;
	private DockingAction function_3Action;

	/*******************************************************************
	*
	*                 Standard Plugin Constructor
	*
	*******************************************************************/
	public Template(PluginTool tool) {

		super(tool);

		// set up list of actions.
		setupActions();

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

	} // Function_1

	/*******************************************************************
	********************************************************************
	**
	**
	**    Function 2
	**
	**
	********************************************************************
	*******************************************************************/
	private void Function_2() {

	} // Function_2

	/*******************************************************************
	********************************************************************
	**
	**
	**		Function 3
	**
	**
	********************************************************************
	*******************************************************************/
	private void Function_3() {

	} // Function_3

	/*******************************************************************
	********************************************************************
	**
	**
	**                  User Plugin Utilities
	**
	**
	********************************************************************
	*******************************************************************/
	/**
	* Get the current program
	*/
	private Program getProgram() {

		ProgramManager pm = tool.getService(ProgramManager.class);
		if (pm != null) {
			return pm.getCurrentProgram();
		}
		return null;
	}

	/*******************************************************************
	********************************************************************
	**
	**
	**                  Required Plugin Routines
	**
	**
	********************************************************************
	*******************************************************************/

	/**
	* Set up Actions
	*/
	private void setupActions() {

		DockingAction action;

		//
		// Function 1
		//
		action = new DockingAction( "Function 1 Code", getName() ) {
			@Override
            public void actionPerformed(ActionContext e) {
				Function_1();
			}
			
			@Override
			public boolean isAddToPopup( ActionContext context ) {
			    if ( !(context.getContextObject() instanceof ListingActionContext) ) {
			        return false;
			    }
			    return super.isAddToPopup( context );
			}
		};

		action.setMenuBarData( new MenuData( 
		    new String[] { "Misc", "Menu", "menu item 1" }, null, null ) );
		
		if (getProgram() == null) {
			action.setEnabled(false);
		}
		tool.addAction(action);

		function_1Action = action;

		//
		// Function 2
		//
		action =new DockingAction("Function 2 Code", getName() ) {
            @Override
            public void actionPerformed(ActionContext e) {
                Function_2();
            }
            @Override
            public boolean isValidContext(ActionContext context) {
            	return context instanceof ListingActionContext;
            }
        };

		action.setMenuBarData( new MenuData( 
		    new String[] { "Misc", "Menu", "Menu item 2" }, null, null ) );
		if (getProgram() == null) {
			action.setEnabled(false);
		}
		tool.addAction(action);

		// remember this action so I can enable/disable it later
		function_2Action = action;

		//
		// Function 3
		//
		action =
			new DockingAction("Function 3 Code", getName() ) {
            
			@Override
            public void actionPerformed(ActionContext e) {
                Function_3();
            }
            
            @Override
            public boolean isValidContext( ActionContext context ) {
                return context instanceof ListingActionContext;
            }
        };

		action.setMenuBarData( new MenuData( 
		    new String[] { "Misc", "Menu", "Menu item 3" }, null, null ) );
		
		if (getProgram() == null) {
			action.setEnabled(false);
		}
		tool.addAction(action);

		// remember this action so I can enable/disable it later
		function_3Action = action;
	}

	/**
	* Put event processing code here.
	*/
	@Override
    public void processEvent(PluginEvent event) {
		if (event instanceof ProgramActivatedPluginEvent) {
			Program p = ((ProgramActivatedPluginEvent)event).getActiveProgram();
			function_1Action.setEnabled(p!=null);
			function_2Action.setEnabled(p!=null);
			function_3Action.setEnabled(p!=null);
		}
	}

} 
