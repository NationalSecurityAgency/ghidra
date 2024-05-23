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
package ghidra.app.plugin.core.functioncompare.actions;

import static ghidra.util.datastruct.Duo.Side.*;

import java.awt.event.*;
import java.util.List;

import javax.swing.Icon;
import javax.swing.JComboBox;

import docking.ActionContext;
import docking.action.ToggleDockingAction;
import docking.action.ToolBarData;
import ghidra.app.plugin.core.functioncompare.MultiFunctionComparisonPanel;
import ghidra.app.plugin.core.functioncompare.MultiFunctionComparisonProvider;
import ghidra.app.services.GoToService;
import ghidra.app.util.viewer.util.CodeComparisonPanel;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.HTMLUtilities;
import ghidra.util.HelpLocation;
import ghidra.util.datastruct.Duo.Side;
import resources.Icons;

/**
 * Toggle Action designed to be used with a {@link MultiFunctionComparisonProvider}. 
 * When toggled on, a GoTo event will be issued for the function displayed in
 * the comparison panel after the following events:
 * <ul>
 *   <li>focus is gained on either the left or right panels</li>
 *   <li>the function displayed in a comparison panel changes</li>
 * </ul>
 * Note that the GoTo will only operate on the comparison panel that 
 * <b>has focus</b>. eg: If the left panel has focus but the user changes the
 * function being viewed in the right panel, no GoTo will be issued.
 */
public class NavigateToFunctionAction extends ToggleDockingAction {

	private GoToService goToService;

	private static final Icon NAV_FUNCTION_ICON = Icons.NAVIGATE_ON_INCOMING_EVENT_ICON;

	private MultiFunctionComparisonPanel comparisonPanel;

	/**
	 * Constructor
	 * 
	 * @param provider the function comparison provider containing this action
	 */
	public NavigateToFunctionAction(MultiFunctionComparisonProvider provider) {
		super("Navigate To Selected Function", provider.getName());
		comparisonPanel = (MultiFunctionComparisonPanel) provider.getComponent();

		goToService = provider.getTool().getService(GoToService.class);

		setEnabled(true);
		setSelected(false);
		ToolBarData newToolBarData = new ToolBarData(NAV_FUNCTION_ICON);
		setToolBarData(newToolBarData);
		setDescription(HTMLUtilities.toHTML("Toggle <b>On</b> means to navigate to whatever " +
			"function is selected in the comparison panel, when focus changes or" +
			"a new function is selected."));
		setHelpLocation(
			new HelpLocation(MultiFunctionComparisonPanel.HELP_TOPIC, "Navigate_To_Function"));

		addFocusListeners();
		addChangeListeners();
	}

	@Override
	public void actionPerformed(ActionContext context) {
		JComboBox<Function> combo = comparisonPanel.getFocusedComponent();
		Function f = (Function) combo.getSelectedItem();
		goToService.goTo(f.getEntryPoint(), f.getProgram());
	}

	/**
	 * Adds a listener to each of the function selection widgets in the 
	 * comparison provider. When a new function is selected, a GoTo event
	 * is generated for the entry point of the function.
	 * 
	 */
	private void addChangeListeners() {
		JComboBox<Function> sourceCombo = comparisonPanel.getSourceComponent();
		JComboBox<Function> targetCombo = comparisonPanel.getTargetComponent();
		sourceCombo.addItemListener(new PanelItemListener(LEFT));
		targetCombo.addItemListener(new PanelItemListener(RIGHT));

	}

	/**
	 * Adds a listener to each panel in the function comparison provider, 
	 * triggered when focus has been changed. If focused is gained in a panel,
	 * a GoTo event is issued containing the function start address.
	 */
	private void addFocusListeners() {
		List<CodeComparisonPanel> panels = comparisonPanel.getComparisonPanels();

		for (CodeComparisonPanel panel : panels) {
			panel.getComparisonComponent(LEFT)
					.addFocusListener(new PanelFocusListener(panel, Side.LEFT));
			panel.getComparisonComponent(RIGHT)
					.addFocusListener(new PanelFocusListener(panel, Side.RIGHT));
		}
	}

	private class PanelItemListener implements ItemListener {
		private Side side;

		PanelItemListener(Side side) {
			this.side = side;
		}

		@Override
		public void itemStateChanged(ItemEvent e) {
			if (e.getStateChange() != ItemEvent.SELECTED) {
				return;
			}
			if (comparisonPanel.getFocusedSide() != side) {
				return;
			}

			if (isSelected()) {
				JComboBox<?> combo = (JComboBox<?>) e.getSource();
				Function f = (Function) combo.getSelectedItem();
				goToService.goTo(f.getEntryPoint(), f.getProgram());
			}
		}

	}

	private class PanelFocusListener extends FocusAdapter {
		private CodeComparisonPanel panel;
		private Side side;

		PanelFocusListener(CodeComparisonPanel panel, Side side) {
			this.panel = panel;
			this.side = side;
		}

		@Override
		public void focusGained(FocusEvent e) {
			if (!isSelected()) {
				return;
			}
			Program program = panel.getProgram(side);
			AddressSetView addresses = panel.getAddresses(side);
			if (program != null && addresses != null && !addresses.isEmpty()) {
				goToService.goTo(addresses.getMinAddress(), program);
			}
		}
	}
}
