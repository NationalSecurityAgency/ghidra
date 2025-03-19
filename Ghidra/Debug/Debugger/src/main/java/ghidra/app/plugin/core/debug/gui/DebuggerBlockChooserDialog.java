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
package ghidra.app.plugin.core.debug.gui;

import java.awt.BorderLayout;
import java.util.*;
import java.util.Map.Entry;
import java.util.function.Function;

import javax.swing.*;
import javax.swing.table.TableColumn;
import javax.swing.table.TableColumnModel;

import docking.ReusableDialogComponentProvider;
import docking.widgets.table.*;
import docking.widgets.table.ColumnSortState.SortDirection;
import docking.widgets.table.DefaultEnumeratedColumnTableModel.EnumeratedTableColumn;
import ghidra.app.services.DebuggerStaticMappingService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.util.ProgramLocation;
import ghidra.trace.model.memory.TraceMemoryRegion;
import ghidra.trace.model.modules.TraceSection;
import ghidra.util.table.GhidraTableFilterPanel;

public class DebuggerBlockChooserDialog extends ReusableDialogComponentProvider {
	public static class MemoryBlockRow {
		private final Program program;
		private final MemoryBlock block;
		private double score;

		protected MemoryBlockRow(Program program, MemoryBlock block) {
			this.program = program;
			this.block = block;
		}

		public Program getProgram() {
			return program;
		}

		public MemoryBlock getBlock() {
			return block;
		}

		public String getProgramName() {
			return program.getName();
		}

		public String getBlockName() {
			return block.getName();
		}

		public Address getMinAddress() {
			return block.getStart();
		}

		public Address getMaxAddress() {
			return block.getEnd();
		}

		public long getLength() {
			return block.getSize();
		}

		public double getScore() {
			return score;
		}

		public double score(TraceSection section, long snap, DebuggerStaticMappingService service) {
			if (section == null) {
				return score = 0;
			}
			return score = service.proposeSectionMap(section, snap, program, block).computeScore();
		}

		public double score(TraceMemoryRegion region, long snap,
				DebuggerStaticMappingService service) {
			if (region == null) {
				return score = 0;
			}
			return score = service.proposeRegionMap(region, snap, program, block).computeScore();
		}

		public ProgramLocation getProgramLocation() {
			return new ProgramLocation(program, block.getStart());
		}
	}

	enum MemoryBlockTableColumns
		implements EnumeratedTableColumn<MemoryBlockTableColumns, MemoryBlockRow> {
		SCORE("Score", Double.class, MemoryBlockRow::getScore, SortDirection.DESCENDING),
		PROGRAM("Program", String.class, MemoryBlockRow::getProgramName, SortDirection.ASCENDING),
		BLOCK("Block", String.class, MemoryBlockRow::getBlockName, SortDirection.ASCENDING),
		START("Start Address", Address.class, MemoryBlockRow::getMinAddress, SortDirection.ASCENDING),
		END("End Address", Address.class, MemoryBlockRow::getMaxAddress, SortDirection.ASCENDING),
		LENGTH("Length", Long.class, MemoryBlockRow::getLength, SortDirection.ASCENDING);

		<T> MemoryBlockTableColumns(String header, Class<T> cls, Function<MemoryBlockRow, T> getter,
				SortDirection dir) {
			this.header = header;
			this.cls = cls;
			this.getter = getter;
			this.dir = dir;
		}

		private final String header;
		private final Function<MemoryBlockRow, ?> getter;
		private final Class<?> cls;
		private final SortDirection dir;

		@Override
		public String getHeader() {
			return header;
		}

		@Override
		public Class<?> getValueClass() {
			return cls;
		}

		@Override
		public Object getValueOf(MemoryBlockRow row) {
			return getter.apply(row);
		}

		@Override
		public SortDirection defaultSortDirection() {
			return dir;
		}
	}

	final EnumeratedColumnTableModel<MemoryBlockRow> tableModel;

	GTable table;
	GhidraTableFilterPanel<MemoryBlockRow> filterPanel;

	private Entry<Program, MemoryBlock> chosen;

	public DebuggerBlockChooserDialog(PluginTool tool) {
		super("Memory Blocks", true, true, true, false);
		tableModel =
			new DefaultEnumeratedColumnTableModel<>(tool, "Blocks", MemoryBlockTableColumns.class);
		populateComponents();
	}

	/* testing */
	public EnumeratedColumnTableModel<MemoryBlockRow> getTableModel() {
		return tableModel;
	}

	/* testing */
	public GhidraTableFilterPanel<MemoryBlockRow> getTableFilterPanel() {
		return filterPanel;
	}

	protected void populateComponents() {
		JPanel panel = new JPanel(new BorderLayout());

		table = new GTable(tableModel);
		table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		panel.add(new JScrollPane(table));

		filterPanel = new GhidraTableFilterPanel<>(table, tableModel);
		filterPanel.getAccessibleContext().setAccessibleName("Filter");
		panel.add(filterPanel, BorderLayout.SOUTH);
		panel.getAccessibleContext().setAccessibleName("Debugger Block Chooser");
		addWorkPanel(panel);

		addOKButton();
		addCancelButton();

		table.getSelectionModel().addListSelectionListener(evt -> {
			okButton.setEnabled(filterPanel.getSelectedItems().size() == 1);
			// Prevent empty selection
		});

		// TODO: Adjust column widths?
		TableColumnModel columnModel = table.getColumnModel();

		TableColumn startCol = columnModel.getColumn(MemoryBlockTableColumns.START.ordinal());
		startCol.setCellRenderer(CustomToStringCellRenderer.MONO_OBJECT);

		TableColumn endCol = columnModel.getColumn(MemoryBlockTableColumns.END.ordinal());
		endCol.setCellRenderer(CustomToStringCellRenderer.MONO_OBJECT);

		TableColumn lenCol = columnModel.getColumn(MemoryBlockTableColumns.LENGTH.ordinal());
		lenCol.setCellRenderer(CustomToStringCellRenderer.MONO_ULONG_HEX);
	}

	public Map.Entry<Program, MemoryBlock> chooseBlock(PluginTool tool, TraceSection section,
			long snap, Collection<Program> programs) {
		DebuggerStaticMappingService service = tool.getService(DebuggerStaticMappingService.class);
		return chooseBlock(tool, programs, rec -> rec.score(section, snap, service));
	}

	public Map.Entry<Program, MemoryBlock> chooseBlock(PluginTool tool, TraceMemoryRegion region,
			long snap, Collection<Program> programs) {
		DebuggerStaticMappingService service = tool.getService(DebuggerStaticMappingService.class);
		return chooseBlock(tool, programs, rec -> rec.score(region, snap, service));
	}

	protected Map.Entry<Program, MemoryBlock> chooseBlock(PluginTool tool,
			Collection<Program> programs, Function<MemoryBlockRow, Double> scorer) {
		setBlocksFromPrograms(programs);
		computeScores(scorer);
		selectHighestScoringBlock();
		tool.showDialog(this);
		return getChosen();
	}

	protected void computeScores(Function<MemoryBlockRow, Double> scorer) {
		for (MemoryBlockRow rec : tableModel.getModelData()) {
			scorer.apply(rec);
		}
	}

	protected void setBlocksFromPrograms(Collection<Program> programs) {
		this.tableModel.clear();
		List<MemoryBlockRow> rows = new ArrayList<>();
		for (Program program : programs) {
			for (MemoryBlock block : program.getMemory().getBlocks()) {
				rows.add(new MemoryBlockRow(program, block));
			}
		}
		this.tableModel.addAll(rows);
	}

	protected void selectHighestScoringBlock() {
		MemoryBlockRow best = null;
		for (MemoryBlockRow rec : tableModel.getModelData()) {
			if (best == null || rec.getScore() > best.getScore()) {
				best = rec;
			}
		}
		if (best != null) {
			filterPanel.setSelectedItem(best);
		}
	}

	@Override
	protected void okCallback() {
		MemoryBlockRow sel = filterPanel.getSelectedItem();
		this.chosen = sel == null ? null : Map.entry(sel.program, sel.block);
		close();
	}

	@Override
	protected void cancelCallback() {
		this.chosen = null;
		close();
	}

	public Entry<Program, MemoryBlock> getChosen() {
		return chosen;
	}
}
