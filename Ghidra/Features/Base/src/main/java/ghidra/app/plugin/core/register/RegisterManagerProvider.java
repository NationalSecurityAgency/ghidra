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

import static ghidra.framework.model.DomainObjectEvent.*;
import static ghidra.program.util.ProgramEvent.*;

import java.awt.event.MouseEvent;
import java.math.BigInteger;

import javax.swing.*;

import docking.ActionContext;
import docking.WindowPosition;
import docking.action.ToggleDockingAction;
import docking.action.builder.ActionBuilder;
import docking.action.builder.ToggleActionBuilder;
import generic.theme.GIcon;
import ghidra.app.cmd.register.SetRegisterCmd;
import ghidra.app.context.ProgramActionContext;
import ghidra.framework.cmd.Command;
import ghidra.framework.model.DomainObjectChangedEvent;
import ghidra.framework.model.DomainObjectListener;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;
import ghidra.util.table.GhidraTable;
import ghidra.util.task.SwingUpdateManager;
import resources.Icons;

public class RegisterManagerProvider extends ComponentProviderAdapter {
	private static final Icon DELETE_REGISTER_VALUES_ICON = Icons.DELETE_ICON;
	private static final Icon SELECT_REGISTER_VALUES_ICON = Icons.MAKE_SELECTION_ICON;
	private static final Icon FILTER_ICON = Icons.CONFIGURE_FILTER_ICON;
	static final Icon REGISTER_ICON = new GIcon("icon.plugin.register.provider");
	private static Icon RECV_LOCATION_ICON = Icons.NAVIGATE_ON_INCOMING_EVENT_ICON;

	private Program program;

	private JSplitPane splitPane;
	private RegisterTree tree;
	private RegisterValuesPanel values;

	private ToggleDockingAction showDefaultValuesAction;
	private DomainObjectListener domainObjectListener;
	private ToggleDockingAction filterRegistersAction;
	private SwingUpdateManager updateMgr;

	private boolean followLocation = false;
	private Address currentAddress;

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
			contextChanged();
		});

		tree.setAccessibleNamePrefix("Register Manager");

		GhidraTable table = values.getTable();
		String namePrefix = "Register Manager Values";
		table.setAccessibleNamePrefix(namePrefix);
	}

	void createActions() {
		HelpLocation helpLocation = new HelpLocation("RegisterPlugin", "tool_buttons");

		new ActionBuilder("Add Register Value Range", getOwner())
				.toolBarIcon(Icons.ADD_ICON)
				.popupMenuPath("Add Value Range")
				.popupMenuIcon(Icons.ADD_ICON)
				.description("Add a new register value range")
				.helpLocation(helpLocation)
				.withContext(RegisterManagerContext.class)
				.enabledWhen(c -> c.getSelectedRegister() != null)
				.onAction(c -> addRange(c.getSelectedRegister()))
				.buildAndInstallLocal(this);

		new ActionBuilder("Delete Register Value Ranges", getOwner())
				.toolBarIcon(DELETE_REGISTER_VALUES_ICON)
				.popupMenuPath("Delete Register Value Ranges")
				.popupMenuIcon(DELETE_REGISTER_VALUES_ICON)
				.description("Delete selected register value ranges")
				.helpLocation(helpLocation)
				.withContext(RegisterManagerContext.class)
				.enabledWhen(c -> c.hasSelectedRegisterValueRanges())
				.onAction(c -> values.deleteSelectedRanges())
				.buildAndInstallLocal(this);

		new ActionBuilder("Select Register Value Ranges", getOwner())
				.toolBarIcon(SELECT_REGISTER_VALUES_ICON)
				.popupMenuPath("Select Register Value Ranges")
				.popupMenuIcon(SELECT_REGISTER_VALUES_ICON)
				.helpLocation(helpLocation)
				.description("Create a program selection from the selected rows")
				.withContext(RegisterManagerContext.class)
				.enabledWhen(c -> c.hasSelectedRegisterValueRanges())
				.onAction(c -> values.selectRanges())
				.buildAndInstallLocal(this);

		showDefaultValuesAction =
			new ToggleActionBuilder("Show Default Register Values", getOwner())
					.menuPath("Show Default Values")
					.description("Toggles showing of default register values")
					.helpLocation(helpLocation)
					.selected(false)
					.onAction(c -> updateShowingDefaultRegisterValues())
					.buildAndInstallLocal(this);

		filterRegistersAction = new ToggleActionBuilder("Filter Registers", getOwner())
				.toolBarIcon(FILTER_ICON)
				.description("Toggles showing only registers with values or default values")
				.helpLocation(helpLocation)
				.selected(false)
				.onAction(c -> tree.setFiltered(filterRegistersAction.isSelected()))
				.buildAndInstallLocal(this);

		new ToggleActionBuilder("Follow location changes", getOwner())
				.toolBarIcon(RECV_LOCATION_ICON)
				.toolBarGroup("NavAction")
				.description(
					"If selected, auto select register and value range from listing location")
				.helpLocation(helpLocation)
				.selected(false)
				.onAction(c -> followLocation = !followLocation)
				.buildAndInstallLocal(this);
	}

	private void updateShowingDefaultRegisterValues() {
		values.setShowDefaultValues(showDefaultValuesAction.isSelected());
	}

	private void addRange(Register register) {
		EditRegisterValueDialog dialog =
			new EditRegisterValueDialog(register, currentAddress, currentAddress, null, program);
		dialog.setTitle("Add Value Range");
		tool.showDialog(dialog, this);

		if (!dialog.wasCancelled()) {
			Address start = dialog.getStartAddress();
			Address end = dialog.getEndAddress();
			BigInteger value = dialog.getValue();
			Command<Program> command = new SetRegisterCmd(register, start, end, value);
			tool.execute(command, program);
		}
	}

	private void showRegister() {
		Register register = tree.getSelectedRegister();
		values.setRegister(register);
		contextChanged();
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
		return new RegisterManagerContext(program, tree.getSelectedRegister(),
			values.hasSelectedRows());
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
			if (ev.contains(REGISTER_VALUES_CHANGED, RESTORED)) {
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
		currentAddress = address;
		if (!followLocation) {
			return;
		}
		if (register != null) {
			tree.selectRegister(register);
		}
		values.setAddress(address);
	}

	private class RegisterManagerContext extends ProgramActionContext {
		private Register register;
		private boolean hasSelectedRows;

		RegisterManagerContext(Program program, Register register, boolean hasSelectedRows) {
			super(RegisterManagerProvider.this, program);
			this.register = register;
			this.hasSelectedRows = hasSelectedRows;
		}

		public boolean hasSelectedRegisterValueRanges() {
			return hasSelectedRows;
		}

		public Register getSelectedRegister() {
			return register;
		}
	}

}
