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

import java.util.ConcurrentModificationException;
import java.util.List;

import docking.widgets.table.*;
import ghidra.app.cmd.function.DeleteFunctionCmd;
import ghidra.app.cmd.label.DeleteLabelCmd;
import ghidra.app.cmd.label.RenameLabelCmd;
import ghidra.docking.settings.Settings;
import ghidra.framework.cmd.Command;
import ghidra.framework.cmd.CompoundCmd;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.*;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.util.Msg;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.datastruct.LongArrayList;
import ghidra.util.exception.CancelledException;
import ghidra.util.table.AddressBasedTableModel;
import ghidra.util.table.column.*;
import ghidra.util.table.field.*;
import ghidra.util.task.TaskMonitor;

class SymbolTableModel extends AddressBasedTableModel<SymbolRowObject> {
	static final int LABEL_COL = 0;
	static final int LOCATION_COL = 1;
	static final int TYPE_COL = 2;
	static final int DATATYPE_COL = 3;
	static final int NAMESPACE_COL = 4;
	static final int SOURCE_COL = 5;
	static final int REFS_COL = 6;

	static final String LABEL_COL_NAME = "Labels";
	static final String LOCATION_COL_NAME = "Location";
	static final String TYPE_COL_NAME = "Type";
	static final String DATATYPE_COL_NAME = "Datatype";
	static final String REFS_COL_NAME = "# Refs";
	static final String NAMESPACE_COL_NAME = "Namespace";
	static final String SOURCE_COL_NAME = "Source";

	private SymbolProvider provider;
	private PluginTool tool;
	private SymbolTable symbolTable;
	private ReferenceManager refMgr;
	private Symbol lastSymbol;
	private SymbolFilter filter;

	SymbolTableModel(SymbolProvider provider, PluginTool tool) {
		super("Symbols", tool, null, null);
		this.provider = provider;
		this.tool = tool;
		this.filter = new NewSymbolFilter();
	}

	@Override
	protected TableColumnDescriptor<SymbolRowObject> createTableColumnDescriptor() {
		TableColumnDescriptor<SymbolRowObject> descriptor = new TableColumnDescriptor<>();

		descriptor.addVisibleColumn(new NameTableColumn(), 1, true);
		descriptor.addVisibleColumn(new LocationTableColumn());
		descriptor.addVisibleColumn(
			DiscoverableTableUtils.adaptColumForModel(this, new SymbolTypeTableColumn()));
		descriptor.addVisibleColumn(new DataTypeTableColumn());
		descriptor.addVisibleColumn(new NamespaceTableColumn());
		descriptor.addVisibleColumn(new SourceTableColumn());
		descriptor.addVisibleColumn(new ReferenceCountTableColumn());
		descriptor.addVisibleColumn(new OffcutReferenceCountTableColumn());

		descriptor.addHiddenColumn(new PinnedTableColumn());
		descriptor.addHiddenColumn(new UserTableColumn());
		descriptor.addHiddenColumn(new OriginalNameColumn());

		return descriptor;
	}

	void setFilter(SymbolFilter filter) {
		this.filter = filter;
		reload();
	}

	Symbol getSymbol(long symbolID) {
		if (symbolTable != null) {
			return symbolTable.getSymbol(symbolID);
		}
		return null;
	}

	@Override
	public void dispose() {
		super.dispose();
		symbolTable = null;
		refMgr = null;
		lastSymbol = null;
		provider = null;
	}

	void reload(Program prog) {
		cancelAllUpdates();
		this.lastSymbol = null;
		if (prog != null) {
			this.setProgram(prog);
			this.symbolTable = prog.getSymbolTable();
			this.refMgr = prog.getReferenceManager();
			reload();
		}
		else {
			this.setProgram(null);
			this.symbolTable = null;
			this.refMgr = null;
		}
	}

	public int getKeyCount() {
		if (symbolTable != null) {
			int cnt = symbolTable.getNumSymbols();
			if (filter.acceptsDefaultLabelSymbols()) {
				cnt += refMgr.getReferenceDestinationCount();
			}
			return cnt;
		}
		return 0;
	}

	@Override
	protected void doLoad(Accumulator<SymbolRowObject> accumulator, TaskMonitor monitor)
			throws CancelledException {
		if (symbolTable == null) {
			return;
		}
		SymbolIterator it;
//		if (filter.acceptsOnlyCodeSymbols()) {
//			it = symbolTable.getSymbolIterator(true);
//		}
//		else {
		it = symbolTable.getDefinedSymbols();
//		}

		monitor.initialize(getKeyCount());
		int value = 0;
		while (it.hasNext()) {
			monitor.setProgress(value++);
			monitor.checkCanceled();
			Symbol s = it.next();
			if (filter.accepts(s, getProgram())) {
				accumulator.add(new SymbolRowObject(s.getID()));
			}
		}
		if (filter.acceptsDefaultLabelSymbols()) {
			AddressIterator addrIt = refMgr.getReferenceDestinationIterator(
				getProgram().getAddressFactory().getAddressSet(), true);
			while (addrIt.hasNext()) {
				monitor.setProgress(value++);
				monitor.checkCanceled();
				Address a = addrIt.next();
				Symbol s = symbolTable.getPrimarySymbol(a);
				if (s.isDynamic() && filter.accepts(s, getProgram())) {
					accumulator.add(new SymbolRowObject(s.getID()));
				}
			}
		}
	}

	@Override
	public boolean isSortable(int columnIndex) {
		return true;
	}

	@Override
	public boolean isCellEditable(int key, int columnIndex) {
		return columnIndex == LABEL_COL;
	}

	@Override
	public void setValueAt(Object aValue, int row, int columnIndex) {
		if (provider == null || symbolTable == null || aValue == null) {
			return;
		}
		if (row < 0 || row >= filteredData.size()) {
			return;
		}

		SymbolRowObject rowObject = filteredData.get(row);
		Symbol symbol = symbolTable.getSymbol(rowObject.getKey());
		if (symbol == null) {
			return;
		}

		switch (columnIndex) {
			case LABEL_COL:
				try {
					String newName = aValue.toString();
					if (!symbol.getName().equals(newName)) {
						Command renameCmd =
							new RenameLabelCmd(symbol.getAddress(), symbol.getName(), newName,
								symbol.getParentNamespace(), SourceType.USER_DEFINED);

						if (!tool.execute(renameCmd, getProgram())) {
							Msg.showError(getClass(), provider.getComponent(),
								"Error Renaming Symbol", renameCmd.getStatusMsg());
						}
					}
				}
				catch (ConcurrentModificationException exc) {
					Msg.showError(getClass(), provider.getComponent(), "Invalid Symbol",
						"Symbol no longer valid.");
				}
				break;
		}
	}

	@Override
	public ProgramLocation getProgramLocation(int row, int column) {
		Symbol s = (Symbol) getValueAt(row, LABEL_COL);
		if (s != null) {
			return s.getProgramLocation();
		}
		return null;
	}

	public ProgramLocation getProgramLocation(int row) {
		return (ProgramLocation) getValueAt(row, LOCATION_COL);
	}

	@Override
	public ProgramSelection getProgramSelection(int[] rows) {
		AddressSet set = new AddressSet();
		for (int element : rows) {
			AddressBasedLocation symbolLocation = getSymbolLocation(getRowObject(element));
			if (symbolLocation.isMemoryLocation()) {
				set.add(symbolLocation.getAddress());
			}
		}
		return new ProgramSelection(set);
	}

	@Override
	public void reload() {
		lastSymbol = null;
		super.reload();
	}

	void symbolAdded(Symbol s) {
		if (filter.accepts(s, getProgram())) {
			addObject(new SymbolRowObject(s.getID()));
			lastSymbol = s;
		}
	}

	void symbolRemoved(long symbolID) {
		if (lastSymbol != null && lastSymbol.getID() == symbolID) {
			lastSymbol = null;
		}
		removeObject(new SymbolRowObject(symbolID));
	}

	void symbolChanged(Symbol s) {
		SymbolRowObject symbolRowObject = new SymbolRowObject(s.getID());
		if (filter.accepts(s, getProgram())) {
			updateObject(symbolRowObject);
		}
		else {
			removeObject(symbolRowObject);
		}
	}

	void delete(List<SymbolRowObject> rowObjects) {
		if (rowObjects == null || rowObjects.size() == 0) {
			return;
		}
		tool.setStatusInfo("");
		LongArrayList deleteList = new LongArrayList();
		CompoundCmd cmd = new CompoundCmd("Delete symbol(s)");
		for (int i = 0; i < rowObjects.size(); i++) {
			Symbol symbol = symbolTable.getSymbol(rowObjects.get(i).getKey());
			if (symbol == null) {
				continue;
			}
			if (symbol.isDynamic()) {
				Symbol[] symbols = symbolTable.getSymbols(symbol.getAddress());
				if (symbols.length == 1) {
					tool.setStatusInfo("Unable to delete symbol: " + symbol.getName());
					continue;//can't delete dynamic symbols...
				}
			}
			deleteList.add(rowObjects.get(i).getKey());
			String label = symbol.getName();
			if (symbol.getSymbolType() == SymbolType.FUNCTION) {
				Function function = (Function) symbol.getObject();
				boolean ignoreMissingFunction = function.isThunk();
				cmd.add(new DeleteFunctionCmd(symbol.getAddress(), ignoreMissingFunction));
				if (symbol.getSource() != SourceType.DEFAULT) {
					// remove label which gets created when non-default function is removed
					cmd.add(new DeleteLabelCmd(symbol.getAddress(), label,
						symbol.getParentNamespace()));
				}
			}
			else {
				cmd.add(
					new DeleteLabelCmd(symbol.getAddress(), label, symbol.getParentNamespace()));
			}
		}
		if (cmd.size() == 0) {
			return;
		}
		if (tool.execute(cmd, getProgram())) {
			for (int k = 0; k < deleteList.size(); k++) {
				removeObject(new SymbolRowObject(deleteList.get(k)));
			}
			updateNow();
		}
		else {
			tool.setStatusInfo(cmd.getStatusMsg());
			reload();
		}
	}

	public SymbolFilter getFilter() {
		return filter;
	}

	@Override
	public Class<?> getSortedColumnClass(int columnIndex) {
		if (columnIndex == LOCATION_COL) {
			return Address.class;
		}
		return super.getSortedColumnClass(columnIndex);
	}

	public static int getPreferredWidth(int columnIndex) {
		switch (columnIndex) {
			case LABEL_COL:
				return 140;
			case LOCATION_COL:
				return 40;
			case DATATYPE_COL:
			case TYPE_COL:
			case SOURCE_COL:
				return 30;
			case NAMESPACE_COL:
				return 80;
			case REFS_COL:
				return 20;
		}
		return 40;
	}

	@Override
	public Address getAddress(int row) {
		Symbol symbol = symbolTable.getSymbol(getRowObject(row).getKey());
		if (symbol == null) {
			return null;
		}
		return symbol.getAddress();
	}

	Symbol getSymbolForRowObject(SymbolRowObject storageObject) {
		if (symbolTable == null) {
			return null;
		}

		long key = storageObject.getKey();
		Symbol localSymbol = lastSymbol;
		if (localSymbol == null || localSymbol.getID() != key) {
			localSymbol = lastSymbol = symbolTable.getSymbol(key);
		}
		return localSymbol;
	}

	AddressBasedLocation getSymbolLocation(SymbolRowObject rowObject) {
		Symbol s = getSymbolForRowObject(rowObject);
		if (s == null) {
			return new AddressBasedLocation();
		}
		SymbolType type = s.getSymbolType();
		if (type == SymbolType.PARAMETER || type == SymbolType.LOCAL_VAR) {
			// Must use special location object for variables which renders variable storage
			// location since this can't be obtained from just a variable storage address
			return new VariableSymbolLocation((Variable) s.getObject());
		}
		return new AddressBasedLocation(program, s.getAddress());
	}

//==================================================================================================
// Table Column Classes
//==================================================================================================

	private class NameTableColumn
			extends AbstractProgramBasedDynamicTableColumn<SymbolRowObject, Symbol> {

		@Override
		public String getColumnName() {
			return "Name";
		}

		@Override
		public Symbol getValue(SymbolRowObject rowObject, Settings settings, Program p,
				ServiceProvider svcProvider) throws IllegalArgumentException {
			return getSymbolForRowObject(rowObject);
		}
	}

	private class PinnedTableColumn
			extends AbstractProgramBasedDynamicTableColumn<SymbolRowObject, Boolean> {

		private PinnedRenderer renderer = new PinnedRenderer();

		@Override
		public String getColumnName() {
			return "Pinned";
		}

		@Override
		public Boolean getValue(SymbolRowObject rowObject, Settings settings, Program p,
				ServiceProvider svcProvider) throws IllegalArgumentException {
			Symbol symbol = getSymbolForRowObject(rowObject);
			if (symbol == null) {
				return null;
			}
			return symbol.isPinned();
		}

		@Override
		public GColumnRenderer<Boolean> getColumnRenderer() {
			return renderer;
		}

		private class PinnedRenderer extends GBooleanCellRenderer
				implements AbstractWrapperTypeColumnRenderer<Boolean> {
			// body is handled by parents
		}
	}

	private class LocationTableColumn
			extends AbstractProgramLocationTableColumn<SymbolRowObject, AddressBasedLocation> {

		@Override
		public String getColumnName() {
			return "Location";
		}

		@Override
		public AddressBasedLocation getValue(SymbolRowObject rowObject, Settings settings,
				Program p, ServiceProvider svcProvider) throws IllegalArgumentException {
			return getSymbolLocation(rowObject);
		}

		@Override
		public ProgramLocation getProgramLocation(SymbolRowObject rowObject, Settings settings,
				Program p, ServiceProvider svcProvider) {
			Symbol symbol = getSymbolForRowObject(rowObject);
			if (symbol == null) {
				return null;
			}
			return symbol.getProgramLocation();
		}
	}

	private class VariableSymbolLocation extends AddressBasedLocation {

		VariableSymbolLocation(Variable variable) {
			super(variable.getSymbol().getAddress(), variable.getVariableStorage().toString());
		}
	}

	private class DataTypeTableColumn
			extends AbstractProgramBasedDynamicTableColumn<SymbolRowObject, String> {

		@Override
		public String getColumnName() {
			return "Data Type";
		}

		@Override
		public String getValue(SymbolRowObject rowObject, Settings settings, Program p,
				ServiceProvider svcProvider) throws IllegalArgumentException {

			Symbol symbol = getSymbolForRowObject(rowObject);
			if (symbol == null) {
				return null;
			}

			DataType dt = null;
			Object obj = symbol.getObject();
			if (obj instanceof Data) {
				dt = ((Data) obj).getDataType();
			}
			else if (obj instanceof Function) {
				dt = ((Function) obj).getReturnType();
			}
			else if (obj instanceof Variable) {
				dt = ((Variable) obj).getDataType();
			}
			else if (obj instanceof ExternalLocation) {
				dt = ((ExternalLocation) obj).getDataType();
			}
			if (dt != null) {
				return dt.getDisplayName();
			}
			return "";
		}
	}

	private class NamespaceTableColumn
			extends AbstractProgramBasedDynamicTableColumn<SymbolRowObject, String> {

		@Override
		public String getColumnName() {
			return "Namespace";
		}

		@Override
		public String getValue(SymbolRowObject rowObject, Settings settings, Program p,
				ServiceProvider svcProvider) throws IllegalArgumentException {
			Symbol symbol = getSymbolForRowObject(rowObject);
			if (symbol == null) {
				return null;
			}

			return symbol.getParentNamespace().getName(true);
		}
	}

	private class SourceTableColumn
			extends AbstractProgramBasedDynamicTableColumn<SymbolRowObject, SourceType> {

		private GColumnRenderer<SourceType> renderer = new AbstractGColumnRenderer<SourceType>() {
			@Override
			protected String getText(Object value) {
				if (value == null) {
					return "";
				}
				return ((SourceType) value).getDisplayString();
			}

			@Override
			public String getFilterString(SourceType t, Settings settings) {
				return getText(t);
			}
		};

		@Override
		public String getColumnName() {
			return "Source";
		}

		@Override
		public GColumnRenderer<SourceType> getColumnRenderer() {
			return renderer;
		}

		@Override
		public SourceType getValue(SymbolRowObject rowObject, Settings settings, Program p,
				ServiceProvider svcProvider) throws IllegalArgumentException {
			Symbol symbol = getSymbolForRowObject(rowObject);
			if (symbol == null) {
				return null;
			}

			return symbol.getSource();
		}
	}

	private class ReferenceCountTableColumn
			extends AbstractProgramBasedDynamicTableColumn<SymbolRowObject, Integer> {

		@Override
		public String getColumnName() {
			return "Reference Count";
		}

		@Override
		public Integer getValue(SymbolRowObject rowObject, Settings settings, Program p,
				ServiceProvider svcProvider) throws IllegalArgumentException {
			Symbol symbol = getSymbolForRowObject(rowObject);
			if (symbol == null) {
				return null;
			}

			return Integer.valueOf(symbol.getReferenceCount());
		}
	}

	private class OffcutReferenceCountTableColumn
			extends AbstractProgramBasedDynamicTableColumn<SymbolRowObject, Integer> {

		@Override
		public String getColumnName() {
			return "Offcut Ref Count";
		}

		@Override
		public Integer getValue(SymbolRowObject rowObject, Settings settings, Program p,
				ServiceProvider svcProvider) throws IllegalArgumentException {

			Symbol symbol = getSymbolForRowObject(rowObject);
			if (symbol == null) {
				return null;
			}

			Address address = symbol.getAddress();
			int count = 0;
			if (address.isMemoryAddress()) {
				CodeUnit codeUnit = p.getListing().getCodeUnitContaining(address);
				if (codeUnit != null) {
					AddressSet set =
						new AddressSet(codeUnit.getMinAddress(), codeUnit.getMaxAddress());
					set.deleteRange(address, address);
					ReferenceManager referenceManager = p.getReferenceManager();
					AddressIterator it =
						referenceManager.getReferenceDestinationIterator(set, true);
					while (it.hasNext()) {
						it.next();
						count++;
					}
				}
			}
			return Integer.valueOf(count);
		}
	}

	private class UserTableColumn
			extends AbstractProgramBasedDynamicTableColumn<SymbolRowObject, String> {

		@Override
		public String getColumnName() {
			return "User";
		}

		@Override
		public String getColumnDescription() {
			return "The user that created or last edited this symbol.";
		}

		@Override
		public String getValue(SymbolRowObject rowObject, Settings settings, Program p,
				ServiceProvider svcProvider) throws IllegalArgumentException {

			Symbol symbol = getSymbolForRowObject(rowObject);
			if (symbol == null) {
				return null;
			}

			SourceType source = symbol.getSource();
			if (source != SourceType.USER_DEFINED) {
				return null;
			}

			Address address = symbol.getAddress();
			LabelHistory[] labelHistory = symbolTable.getLabelHistory(address);
			if (labelHistory.length > 0) {
				return labelHistory[0].getUserName();
			}

			return null;
		}

	}

	private class OriginalNameColumn
			extends AbstractProgramBasedDynamicTableColumn<SymbolRowObject, String> {

		@Override
		public String getColumnName() {
			return "Original Imported Name";
		}

		@Override
		public String getColumnDescription() {
			return "The orignal (pre-demangled) import name (External Symbols Only)";
		}

		@Override
		public String getValue(SymbolRowObject rowObject, Settings settings, Program p,
				ServiceProvider svcProvider) throws IllegalArgumentException {

			Symbol symbol = getSymbolForRowObject(rowObject);
			if (symbol == null || !symbol.isExternal()) {
				return null;
			}
			SymbolType symbolType = symbol.getSymbolType();
			if (symbolType != SymbolType.FUNCTION && symbolType != SymbolType.LABEL) {
				return null;
			}
			ExternalManager externalManager = p.getExternalManager();
			ExternalLocation externalLocation = externalManager.getExternalLocation(symbol);
			if (externalLocation != null) {
				return externalLocation.getOriginalImportedName();
			}
			return null;
		}

	}

}
