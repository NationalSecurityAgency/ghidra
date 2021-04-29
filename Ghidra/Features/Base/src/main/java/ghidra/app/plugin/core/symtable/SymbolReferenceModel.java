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
package ghidra.app.plugin.core.symtable;

import java.awt.Component;
import java.util.Iterator;

import javax.swing.JLabel;

import docking.widgets.table.*;
import ghidra.app.services.BlockModelService;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockModel;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.util.ProgramLocation;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.table.AddressBasedTableModel;
import ghidra.util.table.column.AbstractGhidraColumnRenderer;
import ghidra.util.table.column.GColumnRenderer;
import ghidra.util.table.field.*;
import ghidra.util.task.TaskMonitor;

public class SymbolReferenceModel extends AddressBasedTableModel<Reference> {

	static final int ADDRESS_COLUMN = 0;
	static final int LABEL_COL = 1;
	static final int SUBROUTINE_COL = 2;
	static final int ACCESS_COL = 3;
	static final int PREVIEW_COL = 4;

	static final String ADDR_COL_NAME = "Address";
	static final String LABEL_COL_NAME = "Label";
	static final String SUBROUTINE_COL_NAME = "Subroutine";
	static final String ACCESS_COL_NAME = "Access";
	static final String PREVIEW_COL_NAME = "Preview";

	static final int REFS_TO = 0;
	static final int INSTR_REFS_FROM = 1;
	static final int DATA_REFS_FROM = 2;

	private Symbol currentSymbol;
	private ReferenceManager refManager;
	private int showRefMode = REFS_TO;
	private BlockModelService blockModelService;
	private boolean isDisposed;

	SymbolReferenceModel(BlockModelService bms, PluginTool tool) {
		super("Symbol References", tool, null, null);

		this.blockModelService = bms;
	}

	@Override
	protected TableColumnDescriptor<Reference> createTableColumnDescriptor() {
		TableColumnDescriptor<Reference> descriptor = new TableColumnDescriptor<>();

		descriptor.addVisibleColumn(
			DiscoverableTableUtils.adaptColumForModel(this, new ReferenceFromAddressTableColumn()),
			1, true);
		descriptor.addVisibleColumn(
			DiscoverableTableUtils.adaptColumForModel(this, new ReferenceFromLabelTableColumn()));
		descriptor.addVisibleColumn(new SubroutineTableColumn());
		descriptor.addVisibleColumn(new AccessTableColumn());
		descriptor.addVisibleColumn(
			DiscoverableTableUtils.adaptColumForModel(this, new ReferenceFromPreviewTableColumn()));

		return descriptor;
	}

	String getDescription() {
		if (isDisposed) {
			return null;
		}
		String description = "";
		if (currentSymbol != null) {
			description += currentSymbol.getName() + ": ";
		}
		int count = filteredData.size();
		description += count + " Reference";
		if (count != 1) {
			description += "s";//make plural...
		}
		return description;
	}

	@Override
	public void dispose() {
		isDisposed = true;
		super.dispose();
	}

	@Override
	public void setProgram(Program prog) {
		if (isDisposed) {
			return;
		}

		if (prog == null) {
			super.setProgram(null);
			refManager = null;
		}
		else {
			super.setProgram(prog);
			refManager = prog.getReferenceManager();
		}
		currentSymbol = null;
		reload();
	}

	void setCurrentSymbol(Symbol symbol) {
		this.currentSymbol = symbol;
		reload();
	}

	void symbolAdded(Symbol symbol) {
		checkRefs(symbol);
	}

	void symbolRemoved(Symbol symbol) {
		if (currentSymbol != null && currentSymbol.getID() == symbol.getID()) {
			setCurrentSymbol(null);
		}
	}

	void symbolChanged(Symbol symbol) {
		if (currentSymbol != null && currentSymbol.equals(symbol)) {
			return;
		}
		checkRefs(symbol);
	}

	private void checkRefs(Symbol symbol) {
		Iterator<Reference> iter = filteredData.iterator();
		while (iter.hasNext()) {
			Reference ref = iter.next();
			if (ref.getFromAddress().equals(symbol.getAddress())) {
				reload();
				return;
			}
		}
	}

	void showReferencesTo() {
		showRefMode = REFS_TO;
		reload();
	}

	void showInstructionReferencesFrom() {
		showRefMode = INSTR_REFS_FROM;
		reload();
	}

	void showDataReferencesFrom() {
		showRefMode = DATA_REFS_FROM;
		reload();
	}

	@Override
	protected void doLoad(Accumulator<Reference> accumulator, TaskMonitor monitor)
			throws CancelledException {
		if (currentSymbol == null || getProgram() == null) {
			return;
		}

		switch (showRefMode) {
			case REFS_TO:
				loadToReferences(accumulator, monitor);
				break;
			case INSTR_REFS_FROM:
				loadFromReferences(accumulator, true, monitor);
				break;
			case DATA_REFS_FROM:
				loadFromReferences(accumulator, false, monitor);
				break;
		}
	}

	private void loadToReferences(Accumulator<Reference> accumulator, TaskMonitor monitor)
			throws CancelledException {
		if (refManager == null) {
			return;
		}

		Reference[] refs = currentSymbol.getReferences(monitor);
		for (Reference ref : refs) {
			monitor.checkCanceled();
			accumulator.add(ref);
		}
	}

	private void loadFromReferences(Accumulator<Reference> accumulator, boolean isInstr,
			TaskMonitor monitor) throws CancelledException {

		CodeBlockModel blockModel = blockModelService.getActiveSubroutineModel(getProgram());
		CodeBlock block = blockModel.getCodeBlockAt(currentSymbol.getAddress(), TaskMonitor.DUMMY);
		if (block == null) {
			return;
		}
		InstructionIterator ii = getProgram().getListing().getInstructions(block, true);
		while (ii.hasNext()) {
			monitor.checkCanceled();
			Instruction instr = ii.next();
			Reference[] references = instr.getReferencesFrom();
			for (Reference reference : references) {
				RefType rt = reference.getReferenceType();
				if (isInstr) {
					if (rt.isFlow()) {
						accumulator.add(reference);
					}
					else if (instr.getFlowType().isComputed() && references.length == 1 &&
						rt == RefType.READ) {
						accumulator.add(reference);
					}
				}
				else {
					if (rt.isData()) {
						accumulator.add(reference);
					}
				}
			}
		}
	}

	private static String getReferenceType(RefType type) {
		if (type == RefType.THUNK) {
			return "Thunk";
		}

		if (type.isRead() && type.isWrite()) {
			return "RW";
		}
		if (type.isRead()) {
			return "Read";
		}
		if (type.isWrite()) {
			return "Write";
		}
		if (type.isData()) {
			return "Data";
		}
		if (type.isCall()) {
			return "Call";
		}
		if (type.isJump()) {
			return (type.isConditional() ? "Branch" : "Jump");
		}
		return "Unknown";
	}

	private static Symbol getSymbol(Address fromAddress, String symbolName,
			BlockModelService blockModelService, Program program) {

		SymbolTable symbolTable = program.getSymbolTable();
		SymbolIterator iterator = symbolTable.getSymbols(symbolName);
		while (iterator.hasNext()) {
			Symbol symbol = iterator.next();
			CodeBlockModel blockModel = blockModelService.getActiveSubroutineModel(program);
			CodeBlock[] blocks = getCodeBlocksContainingSymbol(symbol, blockModel);
			if (blocks == null || blocks.length == 0) {
				continue;
			}

			for (CodeBlock block : blocks) {
				if (block.contains(fromAddress)) {
					return symbol;
				}
			}
		}
		return null;
	}

	private static CodeBlock[] getCodeBlocksContainingSymbol(Symbol symbol,
			CodeBlockModel blockModel) {
		return getCodeBlocksContainingAddress(symbol.getAddress(), blockModel);
	}

	private static CodeBlock[] getCodeBlocksContainingAddress(Address address,
			CodeBlockModel blockModel) {
		try {
			return blockModel.getCodeBlocksContaining(address, TaskMonitor.DUMMY);
		}
		catch (CancelledException e) {
			// can't happen--dummy monitor
		}
		return null;
	}

	private static String getSubroutineName(Reference reference, BlockModelService service,
			Program program, CodeBlockModel model) {

		Address address = reference.getFromAddress();
		CodeBlock[] blocks = getCodeBlocksContainingAddress(address, model);
		if (blocks != null && blocks.length > 0) {
			return blocks[0].getName();
		}
		return null;
	}

	@Override
	public Address getAddress(int row) {
		return (Address) getValueAt(row, ADDRESS_COLUMN);
	}

//==================================================================================================
// Inner Classes
//==================================================================================================    

	private static class SubroutineTableColumn
			extends AbstractProgramBasedDynamicTableColumn<Reference, String>
			implements ProgramLocationTableColumn<Reference, String> {

		private Program cachedProgram;
		private CodeBlockModel cachedModel;

		@Override
		public String getColumnName() {
			return "Subroutine";
		}

		@Override
		public String getValue(Reference rowObject, Settings settings, Program program,
				ServiceProvider serviceProvider) throws IllegalArgumentException {

			BlockModelService service = serviceProvider.getService(BlockModelService.class);
			CodeBlockModel model = getCodeBlockModel(program, service);
			return getSubroutineName(rowObject, service, program, model);
		}

		private CodeBlockModel getCodeBlockModel(Program program, BlockModelService service) {
			if (cachedModel == null || program != cachedProgram) {
				CodeBlockModel model = service.getActiveSubroutineModel(program);
				cachedModel = model;
			}

			cachedProgram = program;
			return cachedModel;
		}

		@Override
		public ProgramLocation getProgramLocation(Reference rowObject, Settings settings,
				Program program, ServiceProvider serviceProvider) {

			BlockModelService service = serviceProvider.getService(BlockModelService.class);
			CodeBlockModel model = getCodeBlockModel(program, service);
			String subroutineName = getSubroutineName(rowObject, service, program, model);
			if (subroutineName == null) {
				return null;
			}

			Symbol symbol = getSymbol(rowObject.getFromAddress(), subroutineName, service, program);
			if (symbol != null) {
				return symbol.getProgramLocation();
			}

			return null;
		}
	}

	private static class AccessTableColumn
			extends AbstractProgramBasedDynamicTableColumn<Reference, RefType> {

		private AccessCellRenderer accessRenderer = new AccessCellRenderer();

		@Override
		public String getColumnName() {
			return "Access";
		}

		@Override
		public RefType getValue(Reference rowObject, Settings settings, Program program,
				ServiceProvider serviceProvider) throws IllegalArgumentException {

			Listing listing = program.getListing();
			RefType referenceType = rowObject.getReferenceType();
			if (referenceType == RefType.INDIRECTION) {
				Instruction instruction = listing.getInstructionAt(rowObject.getFromAddress());
				if (instruction != null) {
					FlowType flowType = instruction.getFlowType();
					return flowType;
				}
			}
			return referenceType;
		}

		@Override
		public GColumnRenderer<RefType> getColumnRenderer() {
			return accessRenderer;
		}

		private class AccessCellRenderer extends AbstractGhidraColumnRenderer<RefType> {

			@Override
			public Component getTableCellRendererComponent(GTableCellRenderingData data) {

				JLabel label = (JLabel) super.getTableCellRendererComponent(data);

				RefType refType = (RefType) data.getValue();
				label.setText(getReferenceType(refType));

				return label;
			}

			@Override
			public String getFilterString(RefType t, Settings settings) {
				return getReferenceType(t);
			}
		}
	}
}
