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
package ghidra.app.plugin.core.codebrowser;

import java.awt.Component;
import java.util.*;

import javax.swing.ImageIcon;
import javax.swing.JTable;
import javax.swing.table.TableModel;

import docking.ActionContext;
import docking.action.*;
import ghidra.app.events.ProgramSelectionPluginEvent;
import ghidra.framework.plugintool.Plugin;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramSelection;
import resources.*;



/**
 * An action for creating a {@link ProgramSelection} from rows of an {@link AddressRangeTableModel}
 * using either the min addresses or the max addresses
 */
public class SelectEndpointsAction extends DockingAction {
	private Program program;
	private AddressRangeTableModel model;
	private Plugin plugin;
	private RangeEndpoint endpoint;

	enum RangeEndpoint {
		MIN, MAX
	}

	/**
	 * Creates an action which selects the endpoint of a range based on {@code RangeEndpoint}
	 * @param plugin plugin
	 * @param program program
	 * @param model model 
	 * @param endpoint left or right endpoint
	 */
	public SelectEndpointsAction(Plugin plugin, Program program,
			AddressRangeTableModel model, RangeEndpoint endpoint) {
		super("Select " + endpoint.name(), plugin.getName());
		this.program = program;
		this.model = model;
		this.plugin = plugin;
		this.endpoint = endpoint;
		init();
	}

	@Override
	public boolean isAddToPopup(ActionContext context) {
		return true;
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		return !getSelectedRanges(context).isEmpty();
	}

	@Override
	public void actionPerformed(ActionContext context) {
		AddressSet selection = new AddressSet();
		for (AddressRangeInfo rangeInfo : model.getLastSelectedObjects()) {
			if (endpoint.equals(RangeEndpoint.MIN)) {
				selection.add(rangeInfo.min());
			}
			else {
				selection.add(rangeInfo.max());
			}
		}
		plugin.getTool()
				.firePluginEvent(new ProgramSelectionPluginEvent(plugin.getName(),
					new ProgramSelection(selection), program));
	}

	private void init() {
		ImageIcon icon = null;
		String menuText = null;
		String description = null;
		int height = Icons.MAKE_SELECTION_ICON.getIconHeight()/2;
		int weight = Icons.MAKE_SELECTION_ICON.getIconWidth()/2;
		MultiIconBuilder iconBuilder = new MultiIconBuilder(Icons.MAKE_SELECTION_ICON);
		if (endpoint.equals(RangeEndpoint.MIN)) {
			iconBuilder.addIcon(Icons.UP_ICON, weight, height, QUADRANT.UL);
			icon = iconBuilder.build();
			menuText = "Select Min Endpoints";
			description =
				"Makes a Program Selection from the minimum addresses in the selected rows";
		}
		else {
			iconBuilder.addIcon(Icons.DOWN_ICON, weight, height, QUADRANT.LL);
			icon = iconBuilder.build();
			menuText = "Select Max Endpoints";
			description =
				"Makes a Program Selection from the maximum addresses in the selected rows";
		}
		setPopupMenuData(new MenuData(new String[] { menuText }, icon));
		setToolBarData(new ToolBarData(icon));
		setDescription(description);
	}

	private List<AddressRangeInfo> getSelectedRanges(ActionContext context) {
		Component component = context.getSourceComponent();
		if (!(component instanceof JTable table)) {
			return Collections.emptyList();
		}

		TableModel tableModel = table.getModel();
		if (model != tableModel) {
			return Collections.emptyList();
		}

		List<AddressRangeInfo> ranges = new ArrayList<>();
		for (int row : table.getSelectedRows()) {
			ranges.add(model.getRowObject(row));
		}

		return ranges;
	}

}
