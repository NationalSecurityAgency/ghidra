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
package ghidra.features.bsim.gui.overview;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.List;

import javax.swing.JComponent;
import javax.swing.JPanel;

import docking.ActionContext;
import docking.WindowPosition;
import docking.action.builder.ActionBuilder;
import generic.lsh.vector.LSHVectorFactory;
import ghidra.app.context.ProgramActionContext;
import ghidra.app.events.ProgramSelectionPluginEvent;
import ghidra.app.services.GoToService;
import ghidra.features.bsim.gui.BSimSearchPlugin;
import ghidra.features.bsim.gui.search.dialog.BSimSearchSettings;
import ghidra.features.bsim.gui.search.results.BSimSearchInfoDisplayDialog;
import ghidra.features.bsim.query.BSimServerInfo;
import ghidra.features.bsim.query.protocol.ResponseNearestVector;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.util.HelpLocation;
import ghidra.util.table.*;
import resources.Icons;

/**
 * ComponentProvider to display the results of a BSim Overview query
 */
public class BSimOverviewProvider extends ComponentProviderAdapter {
	private static final String PROVIDER_WINDOW_GROUP = "bsim.overview";

	private static final String NAME = "BSim Function Overview";

	private JComponent component;
	private BSimSearchPlugin plugin;
	private Program program;
	private BSimOverviewModel overviewModel;
	private GhidraTable table;

	private BSimServerInfo serverInfo;

	private BSimSearchSettings settings;

	public BSimOverviewProvider(BSimSearchPlugin plugin, BSimServerInfo serverInfo, Program program,
			LSHVectorFactory vFactory, BSimSearchSettings settings) {
		super(plugin.getTool(), NAME, plugin.getName());
		this.plugin = plugin;
		this.serverInfo = serverInfo;
		this.program = program;
		this.settings = settings;

		setHelpLocation(new HelpLocation(BSimSearchPlugin.HELP_TOPIC, "BSim_Overview_Results"));
		setDefaultWindowPosition(WindowPosition.WINDOW);
		setWindowGroup(PROVIDER_WINDOW_GROUP);
		setWindowMenuGroup("BSim");

		// do this before setTitle() so that the windowing updates properly
		setTabText(program.getName() + " -- " + serverInfo);
		setTitle(NAME);
		setTransient();

		component = buildComponent(vFactory);

		tool.addComponentProvider(this, true);

		createActions();
		updateSubTitle();
	}

	public Program getProgram() {
		return program;
	}

	@Override
	public JComponent getComponent() {
		return component;
	}

	private void createActions() {
		addLocalAction(new SelectionNavigationAction(plugin, table));
		HelpLocation help =
			new HelpLocation(BSimSearchPlugin.HELP_TOPIC, "Overview_Search_Info_Action");
		new ActionBuilder("Search Info", getName()).toolBarIcon(Icons.INFO_ICON)
				.helpLocation(help)
				.onAction(c -> showSearchInfo())
				.buildAndInstallLocal(this);

		new ActionBuilder("Make Selection", getOwner()).popupMenuPath("Make Selection")
				.description("Make a selection using selected rows")
				.helpLocation(
					new HelpLocation(BSimSearchPlugin.HELP_TOPIC, "Overview_Make_Selection"))
				.toolBarIcon(Icons.MAKE_SELECTION_ICON)
				.enabledWhen(c -> table.getSelectedRowCount() > 0)
				.onAction(c -> makeSelection())
				.buildAndInstallLocal(this);

		new ActionBuilder("Overview BSim Search From Dialog", getOwner())
				.popupMenuPath("Search Selected Functions...")
				.description(
					"Displays the BSim Simliar Functions Search Dialog with the selected funtions.")
				.helpLocation(new HelpLocation(BSimSearchPlugin.HELP_TOPIC,
					"Overview_Initiate_Search_Dialog"))
				.enabledWhen(c -> table.getSelectedRowCount() > 0)
				.onAction(c -> initialBSimSearch(true))
				.buildAndInstallLocal(this);

		new ActionBuilder("Overview BSim Search", getOwner())
				.popupMenuPath("Search Selected Functions")
				.description("Performs a BSim Similar Functions Search on the selected functions.")
				.helpLocation(
					new HelpLocation(BSimSearchPlugin.HELP_TOPIC, "Overview_Initiate_Search"))
				.enabledWhen(c -> table.getSelectedRowCount() > 0)
				.onAction(c -> initialBSimSearch(false))
				.buildAndInstallLocal(this);
	}

	private void showSearchInfo() {
		tool.showDialog(new BSimSearchInfoDisplayDialog(serverInfo, settings, true));
	}

	private void initialBSimSearch(boolean showDialog) {
		List<Address> selectedFunctionAddresses = new ArrayList<>();
		int[] selectedRows = table.getSelectedRows();
		List<BSimOverviewRowObject> rowObjects = overviewModel.getRowObjects(selectedRows);
		for (BSimOverviewRowObject rowObject : rowObjects) {
			selectedFunctionAddresses.add(rowObject.getFunctionEntryPoint());
		}
		plugin.doBSimSearch(program, selectedFunctionAddresses, showDialog);
	}

	private void makeSelection() {
		ProgramSelection selection = table.getProgramSelection();
		if (program == null || program.isClosed() || selection.getNumAddresses() == 0) {
			return;
		}
		GoToService service = tool.getService(GoToService.class);
		if (service != null) {
			service.goTo(new ProgramLocation(program, selection.getMinAddress()));
		}
		tool.firePluginEvent(new ProgramSelectionPluginEvent(getName(), selection, program));
	}

	private void updateSubTitle() {
		int rowCount = overviewModel.getRowCount();
		int unfilteredCount = overviewModel.getUnfilteredRowCount();

		StringBuilder buf = new StringBuilder();
		buf.append(program.getName());
		buf.append(" (");
		buf.append(rowCount);
		buf.append(" functions");
		if (rowCount != unfilteredCount) {
			buf.append(" (out of ").append(unfilteredCount).append(')');
		}
		buf.append(")");
		setSubTitle(buf.toString());
	}

	private JComponent buildComponent(LSHVectorFactory vectorFactory) {
		JPanel panel = new JPanel(new BorderLayout());

		overviewModel = new BSimOverviewModel(tool, program, vectorFactory);
		GhidraFilterTable<BSimOverviewRowObject> filterTable =
			new GhidraFilterTable<>(overviewModel);
		table = filterTable.getTable();
		table.getSelectionModel().addListSelectionListener(e -> notifyContextChanged());
		table.setNavigateOnSelectionEnabled(true);

		overviewModel.addTableModelListener(e -> updateSubTitle());

		filterTable.installNavigation(tool);

		panel.setPreferredSize(new Dimension(600, 400));
		panel.add(filterTable, BorderLayout.CENTER);
		return panel;
	}

	private void notifyContextChanged() {
		tool.contextChanged(this);
	}

	public void overviewResultAdded(ResponseNearestVector result) {
		overviewModel.addResult(result);
	}

	public void setFinalOverviewResults(ResponseNearestVector result) {
		overviewModel.reload(program, result);

		component.revalidate();
	}

	@Override
	public void componentHidden() {
		super.componentHidden();
		if (plugin != null) {
			plugin.providerClosed(this);
		}
	}

	@Override
	public ActionContext getActionContext(MouseEvent event) {
		if (program == null) {
			return null;
		}
		return new ProgramActionContext(this, program, table);
	}

	@Override
	public String toString() {
		return getTitle();
	}

	@Override
	public final int hashCode() {
		return super.hashCode();
	}

	@Override
	public final boolean equals(Object obj) {
		return super.equals(obj);
	}

//==================================================================================================
// Test methods
//==================================================================================================
	BSimOverviewModel getModel() {
		return overviewModel;
	}

}
