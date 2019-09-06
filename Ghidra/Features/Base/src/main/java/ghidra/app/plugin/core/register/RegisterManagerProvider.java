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
package ghidra.app.plugin.core.register;

import java.awt.event.MouseEvent;

import javax.swing.*;

import docking.ActionContext;
import docking.WindowPosition;
import docking.action.*;
import ghidra.app.context.ProgramActionContext;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ChangeManager;
import ghidra.util.HelpLocation;
import ghidra.util.task.SwingUpdateManager;
import resources.Icons;
import resources.ResourceManager;

public class RegisterManagerProvider extends ComponentProviderAdapter {
	private static final Icon DELETE_REGISTER_VALUES_ICON =
		ResourceManager.loadImage("images/edit-delete.png");
	private static final Icon SELECT_REGISTER_VALUES_ICON =
		ResourceManager.loadImage("images/text_align_justify.png");
	private static final Icon FILTER_ICON = ResourceManager.loadImage("images/textfield.png");
	static final ImageIcon REGISTER_ICON = ResourceManager.loadImage("images/registerGroup.png");
	private static Icon RECV_LOCATION_ICON = Icons.NAVIGATE_ON_INCOMING_EVENT_ICON;

	private Program program;

	private JSplitPane splitPane;
	private RegisterTree tree;
	private RegisterValuesPanel values;

	private DockingAction deleteRegisterValuesAction;

	private DockingAction selectRegisterValuesAction;
	private ToggleDockingAction showDefaultRegisterValuesAction;
	private DomainObjectListener domainObjectListener;
	private ToggleDockingAction filterRegistersAction;
	private SwingUpdateManager updateMgr;

	private ToggleDockingAction followLocationToggleAction;
	protected boolean followLocation;

	RegisterManagerProvider(PluginTool tool, String owner) {
		super(tool, "Register Manager", owner, ProgramActionContext.class);
		buildComponent();

		setHelpLocation(new HelpLocation("RegisterPlugin", "Register_Manager"));
		setIcon(REGISTER_ICON);
		addToToolbar();
		setDefaultWindowPosition(WindowPosition.WINDOW);

		updateMgr = new SwingUpdateManager(500, () -> update());
		domainObjectListener = new MyDomainObjectListener();
	}

	private void buildComponent() {
		splitPane = new JSplitPane();
		tree = new RegisterTree();
		values = new RegisterValuesPanel(tool, this);
		splitPane.setLeftComponent(tree);
		splitPane.setRightComponent(values);
		splitPane.setDividerLocation(0.3);

		tree.addGTreeSelectionListener(e -> showRegister());

		values.getTable().getSelectionModel().addListSelectionListener(e -> {
			JTable table = values.getTable();
			deleteRegisterValuesAction.setEnabled(table.getSelectedRowCount() > 0);
			selectRegisterValuesAction.setEnabled(table.getSelectedRowCount() > 0);
		});

	}

	void createActions() {
		HelpLocation helpLocation = new HelpLocation("RegisterPlugin", "tool_buttons");
		deleteRegisterValuesAction = new DockingAction("Delete Register Value Ranges", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				values.deleteSelectedRanges();
			}
		};
		deleteRegisterValuesAction.setEnabled(false);
		deleteRegisterValuesAction.setToolBarData(new ToolBarData(DELETE_REGISTER_VALUES_ICON));
		deleteRegisterValuesAction.setPopupMenuData(
			new MenuData(new String[] { "Delete Register Value Ranges" }));
		deleteRegisterValuesAction.setDescription("Delete Register Value Ranges");
		deleteRegisterValuesAction.setHelpLocation(helpLocation);
		tool.addLocalAction(this, deleteRegisterValuesAction);

		selectRegisterValuesAction = new DockingAction("Select Register Value Ranges", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				values.selectedRanges();
			}
		};
		selectRegisterValuesAction.setEnabled(false);
		selectRegisterValuesAction.setToolBarData(new ToolBarData(SELECT_REGISTER_VALUES_ICON));
		selectRegisterValuesAction.setPopupMenuData(
			new MenuData(new String[] { "Select Register Value Ranges" }));
		selectRegisterValuesAction.setDescription("Select Register Value Ranges");
		selectRegisterValuesAction.setHelpLocation(helpLocation);
		tool.addLocalAction(this, selectRegisterValuesAction);

		showDefaultRegisterValuesAction =
			new ToggleDockingAction("Show default register values", getName()) {
				@Override
				public void actionPerformed(ActionContext context) {
					values.setShowDefaultValues(showDefaultRegisterValuesAction.isSelected());
				}
			};
		showDefaultRegisterValuesAction.setSelected(false);
		showDefaultRegisterValuesAction.setDescription(
			"Toggles showing of default register values");
		showDefaultRegisterValuesAction.setMenuBarData(
			new MenuData(new String[] { "Show Default Values" }));
		showDefaultRegisterValuesAction.setHelpLocation(
			new HelpLocation("RegisterPlugin", "menu_actions"));
		tool.addLocalAction(this, showDefaultRegisterValuesAction);

		filterRegistersAction = new ToggleDockingAction("Filter Registers", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				tree.setFiltered(filterRegistersAction.isSelected());
			}
		};
		filterRegistersAction.setSelected(false);
		filterRegistersAction.setDescription(
			"Toggles filtering out registers that don't have values or default values.");
		filterRegistersAction.setToolBarData(new ToolBarData(FILTER_ICON));
		filterRegistersAction.setHelpLocation(helpLocation);
		tool.addLocalAction(this, filterRegistersAction);

		followLocationToggleAction = new ToggleDockingAction("Follow location changes", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				followLocation = followLocationToggleAction.isSelected();
			}
		};
		followLocationToggleAction.setEnabled(true);
		followLocationToggleAction.setHelpLocation(helpLocation);
		followLocationToggleAction.setToolBarData(new ToolBarData(RECV_LOCATION_ICON, "NavAction"));
		tool.addLocalAction(this, followLocationToggleAction);

	}

	private void showRegister() {
		Register register = tree.getSelectedRegister();
		values.setRegister(register);
	}

	@Override
	public void componentHidden() {
		values.setIsShowing(false);
	}

	@Override
	public void componentShown() {
		values.setIsShowing(true);
	}

	@Override
	public ActionContext getActionContext(MouseEvent event) {
		if (program == null) {
			return null;
		}
		return new ProgramActionContext(this, program);
	}

	@Override
	public JComponent getComponent() {
		return splitPane;
	}

	public void setProgram(Program program) {
		if (this.program != null) {
			this.program.removeListener(domainObjectListener);
		}
		this.program = program;
		if (program != null) {
			program.addListener(domainObjectListener);
		}

		tree.setProgram(program);
		values.setProgram(program);
	}

	public void selectRegister(Register register) {
		tree.selectRegister(register);
	}

	void dispose() {
		updateMgr.dispose();
		tree.dispose();
		values.dispose();
	}

	protected void update() {
		showRegister();
		tree.updateFilterList();
	}

	class MyDomainObjectListener implements DomainObjectListener {
		@Override
		public void domainObjectChanged(DomainObjectChangedEvent ev) {
			if (ev.containsEvent(ChangeManager.DOCR_REGISTER_VALUES_CHANGED) ||
				ev.containsEvent(DomainObject.DO_OBJECT_RESTORED)) {
				updateMgr.update();

			}
		}
	}

	void scheduleUpdate() {
		updateMgr.update();
	}

	public Register getSelectedRegister() {
		return tree.getSelectedRegister();
	}

	public void setLocation(Register register, Address address) {
		if (!followLocation) {
			return;
		}
		if (register != null) {
			tree.selectRegister(register);
		}
		values.setAddress(address);
	}

}
