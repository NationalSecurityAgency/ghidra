/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.app.plugin.core.analysis;

import ghidra.app.util.query.AddressAlignmentListener;
import ghidra.framework.plugintool.Plugin;
import docking.ActionContext;
import docking.action.MenuData;
import docking.action.ToggleDockingAction;

public class UpdateAlignmentAction extends ToggleDockingAction implements AddressAlignmentListener {

	Plugin plugin;
	int alignment;
	FindReferencesTableModel model;

	public UpdateAlignmentAction(Plugin plugin, FindReferencesTableModel model, int alignment) {
		super("UpdateAlignmentAction"+Integer.toString(alignment), plugin.getName());
		this.plugin = plugin;
		this.alignment = alignment;
		this.model = model;
		
		String[] menuPath = new String[] {"Alignment", Integer.toString(alignment)};
        setPopupMenuData( new MenuData( menuPath ) );
        setMenuBarData( new MenuData( menuPath ) );
		setEnabled(true);
		setSelected(model.getAlignment() == alignment);
		model.addAlignmentListener(this);
	}
	
	@Override
	public void dispose() {
		model.removeAlignmentListener(this);
		super.dispose();
	}

	@Override
    public void actionPerformed(ActionContext context) {
		int currentAlignment = model.getAlignment();
		if (currentAlignment != alignment) {
			model.setAlignment(alignment);
		}
	}
	
	public void alignmentChanged() {
		setSelected(model.getAlignment() == alignment);
	}
	
	public void alignmentPermissionChanged() {
		setSelected(model.getAlignment() == alignment);
	}
}
