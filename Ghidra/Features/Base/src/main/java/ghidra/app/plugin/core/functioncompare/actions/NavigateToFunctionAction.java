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

import java.awt.event.*;
import java.util.List;

import javax.swing.ImageIcon;

import docking.action.ToggleDockingAction;
import docking.action.ToolBarData;
import docking.widgets.fieldpanel.internal.FieldPanelCoordinator;
import ghidra.app.plugin.core.functioncompare.*;
import ghidra.app.services.GoToService;
import ghidra.app.util.viewer.util.CodeComparisonPanel;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.util.HTMLUtilities;
import ghidra.util.HelpLocation;
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

	private static final ImageIcon NAV_FUNCTION_ICON = Icons.NAVIGATE_ON_INCOMING_EVENT_ICON;

	/**
	 * Constructor
	 * 
	 * @param provider the function comparison provider containing this action
	 */
	public NavigateToFunctionAction(MultiFunctionComparisonProvider provider) {
		super("Navigate To Selected Function", provider.getName());

		goToService = provider.getTool().getService(GoToService.class);

		setEnabled(true);
		setSelected(false);
		ToolBarData newToolBarData = new ToolBarData(NAV_FUNCTION_ICON);
		setToolBarData(newToolBarData);
		setDescription(
			HTMLUtilities.toHTML("Toggle <b>On</b> means to navigate to whatever " +
				"function is selected in the comparison panel, when focus changes or" +
				"a new function is selected."));
		setHelpLocation(
			new HelpLocation(MultiFunctionComparisonPanel.HELP_TOPIC, "Navigate_To_Function"));

		addFocusListeners(provider);
		addChangeListeners(provider);
	}

	/**
	 * Adds a listener to each of the function selection widgets in the 
	 * comparison provider. When a new function is selected, a GoTo event
	 * is generated for the entry point of the function.
	 * 
	 * @param provider the function comparison provider
	 */
	private void addChangeListeners(MultiFunctionComparisonProvider provider) {
		MultiFunctionComparisonPanel panel = (MultiFunctionComparisonPanel) provider.getComponent();

		panel.getSourceComponent().addItemListener(new ItemListener() {
			@Override
			public void itemStateChanged(ItemEvent e) {
				if (e.getStateChange() != ItemEvent.SELECTED) {
					return;
				}

				if (panel.getFocusedComponent() != panel.getSourceComponent()) {
					return;
				}

				if (NavigateToFunctionAction.this.isSelected()) {
					Function f = (Function) panel.getSourceComponent().getSelectedItem();
					goToService.goTo(f.getEntryPoint(), f.getProgram());
				}
			}
		});

		panel.getTargetComponent().addItemListener(new ItemListener() {
			@Override
			public void itemStateChanged(ItemEvent e) {
				if (e.getStateChange() != ItemEvent.SELECTED) {
					return;
				}

				if (panel.getFocusedComponent() != panel.getTargetComponent()) {
					return;
				}

				if (NavigateToFunctionAction.this.isSelected()) {
					Function f = (Function) panel.getTargetComponent().getSelectedItem();
					goToService.goTo(f.getEntryPoint(), f.getProgram());
				}
			}
		});
	}

	/**
	 * Adds a listener to each panel in the function comparison provider, 
	 * triggered when focus has been changed. If focused is gained in a panel,
	 * a GoTo event is issued containing the function start address.
	 * 
	 * @param provider the function comparison provider
	 */
	private void addFocusListeners(MultiFunctionComparisonProvider provider) {

		FunctionComparisonPanel mainPanel = provider.getComponent();
		List<CodeComparisonPanel<? extends FieldPanelCoordinator>> panels =
			mainPanel.getComparisonPanels();

		for (CodeComparisonPanel<? extends FieldPanelCoordinator> panel : panels) {

			panel.getRightFieldPanel().addFocusListener(new FocusAdapter() {

				@Override
				public void focusGained(FocusEvent e) {
					if (NavigateToFunctionAction.this.isSelected()) {

						Address addr = null;

						if (panel.getRightFunction() != null) {
							addr = panel.getRightFunction().getBody().getMinAddress();
						}
						else if (panel.getRightData() != null) {
							addr = panel.getRightData().getAddress();
						}
						else if (panel.getRightAddresses() != null) {
							addr = panel.getRightAddresses().getMinAddress();
						}

						goToService.goTo(addr, panel.getRightProgram());
					}
				}
			});

			panel.getLeftFieldPanel().addFocusListener(new FocusAdapter() {

				@Override
				public void focusGained(FocusEvent e) {
					if (NavigateToFunctionAction.this.isSelected()) {
						Address addr = null;

						if (panel.getLeftFunction() != null) {
							addr = panel.getLeftFunction().getBody().getMinAddress();
						}
						else if (panel.getLeftData() != null) {
							addr = panel.getLeftData().getAddress();
						}
						else if (panel.getLeftAddresses() != null) {
							addr = panel.getLeftAddresses().getMinAddress();
						}

						goToService.goTo(addr, panel.getLeftProgram());
					}
				}

			});
		}
	}
}
