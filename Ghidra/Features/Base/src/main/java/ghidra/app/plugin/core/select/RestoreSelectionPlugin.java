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
package ghidra.app.plugin.core.select;

import ghidra.app.CorePluginPackage;
import ghidra.app.events.ProgramSelectionPluginEvent;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.util.HelpTopics;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.*;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramSelection;
import ghidra.util.HelpLocation;
import ghidra.util.exception.AssertException;

import java.util.HashMap;
import java.util.Map;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.tool.ToolConstants;

//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.SELECTION,
	shortDescription = "Restore Selection",
	description = "This plugin provides the ability to restore the previous selection. " +
	        "This is useful if you accidently lose you selection; for example, by clicking in " +
	        " the CodeBrowser.  Clicking thusly will clear any selection, which can be restored by " +
	        "performing the " + RestoreSelectionPlugin.RESTORE_SELECTION_ACTION_NAME + " action."
)
//@formatter:on
public class RestoreSelectionPlugin extends ProgramPlugin {

    static final String RESTORE_SELECTION_ACTION_NAME = "Restore Selection";
    
    private DockingAction restoreSelectionAction;
    private Map<Program, SelectionState> programToSelectionMap = new HashMap<Program, SelectionState>();
    
    public RestoreSelectionPlugin( PluginTool tool ) {
        super( tool, false, true );
    }

    @Override
    protected void init() {
        super.init();
        createActions();
    }
    
    private void createActions() {        
        DockingAction action = new DockingAction( RESTORE_SELECTION_ACTION_NAME, getName() ) {
            @Override
            public void actionPerformed( ActionContext context ) {
                SelectionState programSelectionState = programToSelectionMap.get( currentProgram );
                firePluginEvent( new ProgramSelectionPluginEvent( 
                    RestoreSelectionPlugin.this.getName(), 
                    programSelectionState.getSelectionToRestore(), currentProgram ) );
            }
        };
// ACTIONS - auto generated
        action.setMenuBarData( new MenuData( 
        	new String[]{ToolConstants.MENU_SELECTION, 
RESTORE_SELECTION_ACTION_NAME}, 
        	null, 
        	"SelectUtils" ) );


        action.setHelpLocation(new HelpLocation(HelpTopics.SELECTION, RESTORE_SELECTION_ACTION_NAME));
        action.setEnabled( false );
        
        tool.addAction( action );
        
        restoreSelectionAction = action;
    }
    
    @Override
    protected void dispose() {
        programToSelectionMap.clear();        
        super.dispose();
    }
    
    @Override
    protected void programActivated( Program program ) {
        SelectionState programSelectionState = programToSelectionMap.get( program );
        if ( programSelectionState == null ) {
            programSelectionState = new SelectionState();
            programToSelectionMap.put( program, programSelectionState );
        }
        restoreSelectionAction.setEnabled( programSelectionState.canRestoreSelection() );
    }
    
    @Override
    protected void programClosed( Program program ) {
        programToSelectionMap.remove( program );
    }
    
    @Override
    protected void selectionChanged( ProgramSelection selection ) {
        SelectionState selectionState = programToSelectionMap.get( currentProgram );
        if ( selectionState == null ) {
            return; // can happen during cleanup
        }
        
        selectionState.pushSelection( selection );
        
        // make sure we eventually enable the action (once we've had a valid selection, then the
        // action will always be enabled for a given program, so no need to disable the action
        // here).
        if ( selectionState.canRestoreSelection() ) {
            restoreSelectionAction.setEnabled( true );
        }
    }
    
    /** 
     * A state class to keep track of past and current selections and to determine when we can
     * restore an old selection.
     */
    private class SelectionState {
        // null OR empty representative
        private final ProgramSelection NUMPTY_SELECTION = new ProgramSelection(); 
        private ProgramSelection activeSelection = NUMPTY_SELECTION;
        private ProgramSelection previousRestoreSelection = NUMPTY_SELECTION;
        
        ProgramSelection getSelectionToRestore() {
            if ( previousRestoreSelection == null || previousRestoreSelection.isEmpty() ) {
                throw new AssertException( "Tried to restore a selection with no " +
                    "previous selection saved" );
            }
            return previousRestoreSelection;
        }
        
        void pushSelection( ProgramSelection newSelection ) {
            // only store a selection for later use if it is valid (restorable) and it is not 
            // the same as the incoming selection
            
            if ( newSelection == null ) {
                newSelection = NUMPTY_SELECTION;
            }
            
            if ( activeSelection.equals( newSelection ) ) {
                return;
            }
            
            if ( !NUMPTY_SELECTION.equals( activeSelection ) ) {
                previousRestoreSelection = activeSelection;
            }
            
            activeSelection = newSelection;
        }
        
        boolean canRestoreSelection() {
            if ( previousRestoreSelection == null || previousRestoreSelection.isEmpty() ) {
                return false;
            }
            
            if ( previousRestoreSelection.equals( activeSelection ) ) {
                return false;
            }
            
            
            return true;
        }
    }
}
