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
import ghidra.app.util.viewer.format.FieldHeader;
import ghidra.app.util.viewer.format.FieldHeaderLocation;
import ghidra.util.HelpLocation;
import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;

/**
 * Action for removing fields
 */
public class RemoveFieldAction extends DockingAction {
	private FieldHeaderLocation loc;
	private FieldHeader panel;

	public RemoveFieldAction(String owner, FieldHeader panel) {
		super("Remove Field", owner, false);
		this.panel = panel;

		setPopupMenuData( new MenuData( new String[] {"Remove Field"}, null, "field" ) );
		setEnabled(true);
		setHelpLocation(new HelpLocation(HelpTopics.CODE_BROWSER, "Remove Field"));
	}

	@Override
    public boolean isEnabledForContext(ActionContext context) {
	    Object contextObject = context.getContextObject();
		if (contextObject instanceof FieldHeaderLocation) {
			loc = (FieldHeaderLocation)contextObject;
			return loc.getFieldFactory() != null;
		}
		return false;
	}

    @Override
    public void actionPerformed(ActionContext context) {
    	panel.setTabLock( true );
		loc.getModel().removeFactory(loc.getRow(), loc.getColumn());
	}

}

