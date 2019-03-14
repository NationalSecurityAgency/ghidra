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
package ghidra.app.util.viewer.format.actions;

import ghidra.app.util.HelpTopics;
import ghidra.app.util.viewer.format.*;
import ghidra.util.HelpLocation;
import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.widgets.OptionDialog;

/**
 * Action for adding all fields to the current format.
 */
public class ResetAllFormatsAction extends DockingAction {

	private FormatManager formatMgr;
	private FieldHeader panel;
	/**
	 * Constructor takes the CodeBrowserPlugin that created it and the header
	 * component so that it can be repainted when fields are added.
	 * @param owner the action owner
	 * @param formatMgr the format manager
	 */
    public ResetAllFormatsAction(String owner, FormatManager formatMgr, FieldHeader panel) {
        super("Reset All Formats", owner, false);
        this.panel = panel;
        this.formatMgr = formatMgr;
        
        setPopupMenuData( new MenuData( new String[] {"Reset All Formats"}, null, "format" ) );
		setEnabled(true);
		setHelpLocation(new HelpLocation(HelpTopics.CODE_BROWSER, "Reset All Formats"));
    }

    @Override
    public boolean isEnabledForContext(ActionContext context) {
    	return context.getContextObject() instanceof FieldHeaderLocation;
    }
    
    /**
     * Method called when the action is invoked.
     */
    @Override
    public void actionPerformed(ActionContext context) {
        int userChoice = OptionDialog.showOptionDialog( panel, "Reset All Formats?", 
            "There is no undo for this action.\n" +
            "Are you sure you want to reset all formats?", "Continue", 
            OptionDialog.WARNING_MESSAGE );
        if ( userChoice == OptionDialog.CANCEL_OPTION ) {
            return;
        }
        
		formatMgr.setDefaultFormats();
		panel.getHeaderTab().update();
	}

}

