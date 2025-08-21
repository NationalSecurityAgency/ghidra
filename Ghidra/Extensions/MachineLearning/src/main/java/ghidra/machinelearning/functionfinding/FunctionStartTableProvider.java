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
package ghidra.machinelearning.functionfinding;

import static ghidra.framework.model.DomainObjectEvent.*;
import static ghidra.program.util.ProgramEvent.*;

import java.awt.*;

import javax.swing.*;

import ghidra.framework.model.DomainObjectChangedEvent;
import ghidra.framework.model.DomainObjectListener;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;
import ghidra.util.table.*;

/**
 * A {@link ComponentProviderAdapter} for displaying tables of addresses that are likely
 * function starts
 */
public class FunctionStartTableProvider extends ProgramAssociatedComponentProviderAdapter
		implements DomainObjectListener {

	private JComponent component;
	private FunctionStartTableModel model;
	private RandomForestFunctionFinderPlugin plugin;
	private Program program;
	private RandomForestRowObject modelRow;
	private AddressSetView toClassify;
	private boolean debug;
	private String subTitle;
	private GhidraTable startTable;
	private GhidraThreadedTablePanel<FunctionStartRowObject> tablePanel;

	/**
	 * Constructs a table provider for the table of addresses to classify.  If {@code debug}
	 * is true, a debug version of the table will be created.
	 * 
	 * @param plugin owning plugin
	 * @param program program containing addresses to classify
	 * @param toClassify addresses to classify
	 * @param modelRow model to apply
	 * @param debug whether to display debug version of table
	 */
	public FunctionStartTableProvider(RandomForestFunctionFinderPlugin plugin, Program program,
			AddressSetView toClassify, RandomForestRowObject modelRow, boolean debug) {
		super(
			debug ? "Debug: Test Set Errors in " + program.getDomainFile().getPathname()
					: "Potential Functions in " + program.getDomainFile().getPathname(),
			plugin.getName(), program, plugin);
		this.program = program;
		this.plugin = plugin;
		this.modelRow = modelRow;
		this.toClassify = toClassify;
		this.debug = debug;
		subTitle = "Pre-bytes:" + modelRow.getNumPreBytes() + "  Initial bytes:" +
			modelRow.getNumInitialBytes() + " Sampling Factor:" + modelRow.getSamplingFactor();
		component = build();
		program.addListener(this);
		String anchor = debug ? "DebugModelTable" : "FunctionStartTable";
		setHelpLocation(new HelpLocation(plugin.getName(), anchor));
	}

	@Override
	public JComponent getComponent() {
		return component;
	}

	@Override
	public void domainObjectChanged(DomainObjectChangedEvent ev) {
		if (!isVisible()) {
			return;
		}
		if (ev.contains(RESTORED, FUNCTION_ADDED, FUNCTION_REMOVED, CODE_ADDED, CODE_REMOVED,
			CODE_REPLACED, REFERENCE_TYPE_CHANGED, REFERENCE_ADDED, REFERENCE_REMOVED)) {
			model.reload();
			contextChanged();
		}
	}

	/**
	 * Returns the underlying {@link GhidraTable}
	 * @return table
	 */
	GhidraTable getTable() {
		return startTable;
	}

	/**
	 * Returns the table model of this provider.
	 * @return table model
	 */
	FunctionStartTableModel getTableModel() {
		return model;
	}

	private JComponent build() {
		JPanel panel = new JPanel(new BorderLayout());
		Component table = buildTablePanel();
		panel.add(table, BorderLayout.CENTER);
		return panel;
	}

	private Component buildTablePanel() {
		model = new FunctionStartTableModel(plugin.getTool(), program, toClassify, modelRow, debug);
		tablePanel = new GhidraThreadedTablePanel<>(model, 1000);
		startTable = tablePanel.getTable();
		startTable.setName("Potential Functions in " + model.getProgram().getName());

		startTable.installNavigation(tool);
		startTable.setNavigateOnSelectionEnabled(true);
		startTable.setAutoResizeMode(JTable.AUTO_RESIZE_SUBSEQUENT_COLUMNS);
		startTable.setPreferredScrollableViewportSize(new Dimension(900, 300));
		startTable.setRowSelectionAllowed(true);
		startTable.getSelectionModel().addListSelectionListener(e -> tool.contextChanged(this));

		model.addTableModelListener(e -> {
			int rowCount = model.getRowCount();
			int unfilteredCount = model.getUnfilteredRowCount();

			StringBuilder buffy = new StringBuilder();

			buffy.append(" ").append(rowCount).append(" items");
			if (rowCount != unfilteredCount) {
				buffy.append(" (of ").append(unfilteredCount).append(" )");
			}

			setSubTitle(subTitle + buffy.toString());
		});

		JPanel container = new JPanel(new BorderLayout());
		container.add(tablePanel, BorderLayout.CENTER);
		var tableFilterPanel = new GhidraTableFilterPanel<>(startTable, model);
		container.add(tableFilterPanel, BorderLayout.SOUTH);

		return container;
	}
}
