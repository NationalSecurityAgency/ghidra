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
package ghidra.app.plugin.core.scalartable;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.event.MouseEvent;

import javax.swing.*;
import javax.swing.border.Border;

import docking.*;
import docking.help.HelpService;
import docking.widgets.label.GLabel;
import docking.widgets.table.GTableFilterPanel;
import docking.widgets.table.TableFilter;
import ghidra.app.plugin.core.scalartable.RangeFilterTextField.FilterType;
import ghidra.app.services.GoToService;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.util.ProgramSelection;
import ghidra.util.HelpLocation;
import ghidra.util.table.*;
import ghidra.util.table.actions.DeleteTableRowAction;
import ghidra.util.table.actions.MakeProgramSelectionAction;
import resources.ResourceManager;

/**
 * Displays the results of a query from the {@link ScalarSearchPlugin}. Consists of 2 components:
 * <ul>
 * <li>The scalar table that is displayed to the user
 * <li>The range filter that allows the user to filter the scalar table via a min and max value.
 * </ul>
 */
public class ScalarSearchProvider extends ComponentProviderAdapter {

	public static final ImageIcon ICON = ResourceManager.loadImage("images/dataW.gif");

	private ScalarSearchPlugin plugin;

	private GhidraThreadedTablePanel<ScalarRowObject> threadedTablePanel;
	private GTableFilterPanel<ScalarRowObject> filter;
	private JComponent mainComponent;
	private JPanel mainPanel;
	private GhidraTable scalarTable;
	private ScalarSearchModel scalarModel;

	private ProgramSelection currentSelection;
	private Program program;
	private String primarySubTitle;

	// TODO these are inconsistent with the other search results windows; these are no longer
	// needed due to the new column filtering
	private RangeFilterTextField minField;
	private RangeFilterTextField maxField;

	ScalarSearchProvider(ScalarSearchPlugin plugin, ProgramSelection currentSelection) {

		super(plugin.getTool(), "Scalar Table", plugin.getName());
		this.currentSelection = currentSelection;
		this.program = plugin.getCurrentProgram();

		this.plugin = plugin;
		setHelpLocation(new HelpLocation(plugin.getName(), "Scalar_Table"));
		mainComponent = createWorkPanel();

		setIcon(ICON);

		setTransient();
		setDefaultWindowPosition(WindowPosition.WINDOW);
		setWindowGroup("SCALAR_TABLE_SEARCH");

		tool.addComponentProvider(this, false);

		createActions();
	}

	@Override
	public String getWindowSubMenuName() {
		return "Search";
	}

	void updateSearchRangeValues(ScalarSearchDialog dialog) {

		long minValue = dialog.getMinSearchValue();
		long maxValue = dialog.getMaxSearchValue();

		scalarModel.initialize(plugin.getCurrentProgram(), minValue, maxValue);

		String minValueText = dialog.getMinSearchValueText();
		String maxValueText = dialog.getMaxSearchValueText();
		updateTitle(minValueText, maxValueText);
	}

	private void updateTitle(String minValueText, String maxValueText) {

		StringBuilder buffy = new StringBuilder("Scalar Search");

		if (minValueText.equals(maxValueText)) {
			buffy.append(" [filter: ").append(minValueText).append(']'); // single scalar search
		}
		else if (!isDefaultFilterRange(minValueText, maxValueText)) {
			buffy.append(" [filter: ")
					.append(minValueText)
					.append(" - ")
					.append(
						maxValueText)
					.append(']');
		}

		setTitle(buffy.toString());

		buffy = new StringBuilder();
		if (currentSelection != null) {
			buffy.append("in Selection: " + getSelectionAsString(currentSelection));
		}

		buffy.append(" (").append(plugin.getCurrentProgram().getName()).append(')');

		primarySubTitle = buffy.toString();
		setSubTitle(primarySubTitle);
	}

	private boolean isDefaultFilterRange(String min, String max) {
		int minValue = minField.getLimitValue();
		int maxValue = maxField.getLimitValue();
		return min.equals(Integer.toString(minValue)) && max.equals(Integer.toString(maxValue));
	}

	@Override
	public void componentShown() {
		scalarModel.reload();
	}

	@Override
	public ActionContext getActionContext(MouseEvent event) {
		return new ScalarSearchContext(this, scalarTable);
	}

	@Override
	public JComponent getComponent() {
		return mainComponent;
	}

	@Override
	public HelpLocation getHelpLocation() {
		return new HelpLocation(plugin.getName(), plugin.getName());
	}

	public Program getProgram() {
		return program;
	}

	public ScalarSearchModel getScalarModel() {
		return scalarModel;
	}

	void programClosed(Program p) {
		if (p == program) {
			closeComponent();
		}
	}

	void dispose() {
		closeComponent();
		threadedTablePanel.dispose();
		filter.dispose();
	}

	ProgramSelection getSelection() {
		return scalarTable.getProgramSelection();
	}

	void reload() {
		if (isVisible()) {
			scalarModel.reload();
		}
	}

	GhidraTable getTable() {
		return scalarTable;
	}

	private JComponent createWorkPanel() {

		scalarModel = new ScalarSearchModel(plugin, currentSelection);

		threadedTablePanel = new GhidraThreadedTablePanel<>(scalarModel, 1000);
		scalarTable = threadedTablePanel.getTable();

		filter = new GTableFilterPanel<>(scalarTable, scalarModel);

		scalarTable.setName("ScalarTable");
		scalarTable.setAutoLookupColumn(ScalarSearchModel.PREVIEW_COLUMN);
		scalarTable.setAutoResizeMode(JTable.AUTO_RESIZE_SUBSEQUENT_COLUMNS);
		scalarTable.setPreferredScrollableViewportSize(new Dimension(400, 400));
		scalarTable.setRowSelectionAllowed(true);
		scalarTable.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
		scalarTable.getSelectionModel().addListSelectionListener(e -> notifyContextChanged());

		filter.setSecondaryFilter(new ScalarTableSecondaryFilter());

		scalarModel.addTableModelListener(
			e -> setSubTitle(primarySubTitle + ' ' + scalarModel.getRowCount() + " items"));

		GoToService goToService = tool.getService(GoToService.class);
		scalarTable.installNavigation(goToService, goToService.getDefaultNavigatable());

		mainPanel = new JPanel(new BorderLayout());
		mainPanel.add(threadedTablePanel, BorderLayout.CENTER);

		JPanel filterPanel = new JPanel(new BorderLayout());
		filterPanel.add(filter, BorderLayout.NORTH);

		filterPanel.add(new RangeFilterPanel(), BorderLayout.SOUTH);

		mainPanel.add(filterPanel, BorderLayout.SOUTH);

		return mainPanel;
	}

	GTableFilterPanel<ScalarRowObject> getFilterPanel() {
		return filter;
	}

	private void notifyContextChanged() {
		tool.contextChanged(this);
	}

	private String getSelectionAsString(ProgramSelection selection) {
		Address min = selection.getMinAddress();
		Address max = selection.getMaxAddress();
		long n = selection.getNumAddresses();
		return "[" + min + ", " + max + "; " + n + " addresses]";
	}

	private void createActions() {

		tool.addLocalAction(this, new MakeProgramSelectionAction(plugin, scalarTable));
		tool.addLocalAction(this, new SelectionNavigationAction(plugin, getTable()));

		GhidraTable table = threadedTablePanel.getTable();
		tool.addLocalAction(this, new DeleteTableRowAction(table, plugin.getName()));
	}

//==================================================================================================
// TODO Delete - the custom filtering code below this line needs to be deleted, as it is now
//               replaced by the column filtering
//==================================================================================================	

	private class RangeFilterPanel extends JPanel {

		RangeFilterPanel() {
			Border lowerBorder = BorderFactory.createLoweredBevelBorder();

			setLayout(new BoxLayout(this, BoxLayout.LINE_AXIS));

			setBorder(lowerBorder);

			add(Box.createHorizontalStrut(4));
			add(new GLabel("Min:"));
			add(Box.createHorizontalStrut(19));

			minField = createFilterWidget(FilterType.MIN);
			add(minField.getComponent());

			add(Box.createHorizontalStrut(10));

			add(new GLabel("Max:"));
			add(Box.createHorizontalStrut(5));
			maxField = createFilterWidget(FilterType.MAX);
			add(maxField.getComponent());

			HelpService help = DockingWindowManager.getHelpService();
			help.registerHelp(this, new HelpLocation(plugin.getName(), "Filter_Scalars"));
		}

		private RangeFilterTextField createFilterWidget(FilterType filterType) {
			RangeFilterTextField rangefilter = new RangeFilterTextField(filterType, program);
			rangefilter.addChangeListener(e -> {
				scalarModel.reFilter();
			});
			return rangefilter;
		}
	}

	/**
	 * Table filter for the range filter that will check the rowObject, in this case
	 * InstructionRowObject, and check if the scalar for that object fits
	 * within the minFilterValue and the maxFilterValue
	 */
	private class ScalarTableSecondaryFilter implements TableFilter<ScalarRowObject> {

		@Override
		public boolean acceptsRow(ScalarRowObject rowObject) {

			Scalar scalar = rowObject.getScalar();
			if (scalar == null) {
				return false;
			}

			long value = scalar.getSignedValue();
			if (value < minField.getFilterValue()) {
				return false;
			}

			if (value > maxField.getFilterValue()) {
				return false;
			}

			return true;
		}

		@Override
		public boolean isSubFilterOf(TableFilter<?> tableFilter) {
			if (!(tableFilter instanceof ScalarTableSecondaryFilter)) {
				return false;
			}

			// for this to work we would have to have this filter keep state to
			// know what values were used at the time of the filter
			return false;
		}
	}
}
