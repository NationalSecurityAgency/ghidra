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

import java.util.*;

import docking.widgets.table.*;
import ghidra.app.cmd.function.DeleteFunctionCmd;
import ghidra.app.cmd.label.DeleteLabelCmd;
import ghidra.app.cmd.label.RenameLabelCmd;
import ghidra.app.util.template.TemplateSimplifier;
import ghidra.docking.settings.Settings;
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
import ghidra.util.table.AddressBasedTableModel;
import ghidra.util.table.column.*;
import ghidra.util.table.field.*;

public abstract class AbstractSymbolTableModel extends AddressBasedTableModel<SymbolRowObject> {

	private static final Comparator<SymbolRowObject> NAME_COL_COMPARATOR = (s1, s2) -> {
		return s1.toString().compareToIgnoreCase(s2.toString());
	};

	public static final int LABEL_COL = 0;
	public static final int LOCATION_COL = 1;
	public static final int TYPE_COL = 2;
	public static final int DATA_TYPE_COL = 3;
	public static final int NAMESPACE_COL = 4;
	public static final int SOURCE_COL = 5;
	public static final int REFS_COL = 6;

	private PluginTool tool;
	protected SymbolTable symbolTable;
	protected ReferenceManager refMgr;
	protected SymbolRowObject lastSymbol;
	protected SymbolFilter filter;

	protected SymbolRenderer symbolRenderer = new SymbolRenderer();

	AbstractSymbolTableModel(PluginTool tool) {
		super("Symbols", tool, null, null);
		this.tool = tool;
		this.filter = new NewSymbolFilter();
	}

	@Override
	protected TableColumnDescriptor<SymbolRowObject> createTableColumnDescriptor() {
		TableColumnDescriptor<SymbolRowObject> descriptor = new TableColumnDescriptor<>();

		descriptor.addVisibleColumn(new NameTableColumn());
		descriptor.addVisibleColumn(new LocationTableColumn(), 1, true);
		descriptor.addVisibleColumn(new SymbolTypeTableColumn());
		descriptor.addHiddenColumn(new DataTypeTableColumn());
		descriptor.addVisibleColumn(new NamespaceTableColumn());
		descriptor.addVisibleColumn(new SourceTableColumn());
		descriptor.addVisibleColumn(new ReferenceCountTableColumn());
		descriptor.addVisibleColumn(new OffcutReferenceCountTableColumn());

		descriptor.addHiddenColumn(new PinnedTableColumn());
		descriptor.addHiddenColumn(new UserTableColumn());
		descriptor.addHiddenColumn(new OriginalNameColumn());
		descriptor.addHiddenColumn(new SimplifiedNameColumn());

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
	public boolean isSortable(int columnIndex) {
		return true;
	}

	@Override
	public boolean isCellEditable(int key, int columnIndex) {
		return columnIndex == LABEL_COL;
	}

	@Override
	public void setValueAt(Object aValue, int row, int columnIndex) {
		if (symbolTable == null || aValue == null) {
			return;
		}
		if (row < 0 || row >= filteredData.size()) {
			return;
		}

		Symbol symbol = filteredData.get(row).getSymbol();
		if (symbol == null || symbol.isDeleted()) {
			return;
		}

		if (columnIndex != LABEL_COL) {
			return;
		}

		String newName = aValue.toString();
		if (symbol.getName().equals(newName)) {
			return;
		}

		RenameLabelCmd cmd = new RenameLabelCmd(symbol, newName, SourceType.USER_DEFINED);
		if (!tool.execute(cmd, getProgram())) {
			Msg.showError(getClass(), null, "Error Renaming Symbol", cmd.getStatusMsg());
		}
	}

	@Override
	public ProgramLocation getProgramLocation(int row, int column) {
		Symbol s = (Symbol) getValueAt(row, LABEL_COL);
		if (s == null || s.isDeleted()) {
			return null;
		}
		return s.getProgramLocation();
	}

	public ProgramLocation getProgramLocation(int row) {
		return (ProgramLocation) getValueAt(row, LOCATION_COL);
	}

	@Override
	public ProgramSelection getProgramSelection(int[] rows) {
		AddressSet set = new AddressSet();
		for (int element : rows) {
			AddressBasedLocation symbolLocation =
				getSymbolLocation(getRowObject(element).getSymbol());
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
			lastSymbol = new SymbolRowObject(s);
			addObject(lastSymbol);
		}
	}

	void symbolRemoved(long symbolId) {
		SymbolRowObject deletedSymbol = new DeletedSymbolRowObject(program, symbolId);
		if (deletedSymbol.equals(lastSymbol)) {
			lastSymbol = null;
		}
		removeObject(deletedSymbol);
	}

	void symbolChanged(Symbol s) {
		if (filter.accepts(s, getProgram())) {
			updateObject(new SymbolRowObject(s));
		}
		else {
			// the symbol may be in the table, as it could have passed the filter before the change
			removeObject(new SymbolRowObject(s));
		}
	}

	void delete(List<Symbol> rowObjects) {
		if (rowObjects == null || rowObjects.isEmpty()) {
			return;
		}

		tool.setStatusInfo("");
		List<Symbol> deleteList = new LinkedList<>();
		CompoundCmd<Program> cmd = new CompoundCmd<>("Delete symbol(s)");
		for (Symbol symbol : rowObjects) {
			if (symbol.isDynamic()) {
				continue; // can't delete dynamic symbols...
			}

			deleteList.add(symbol);
			String label = symbol.getName();
			Address address = symbol.getAddress();
			if (symbol.getSymbolType() == SymbolType.FUNCTION) {
				Function function = (Function) symbol.getObject();
				boolean ignoreMissingFunction = function.isThunk();
				cmd.add(new DeleteFunctionCmd(address, ignoreMissingFunction));
				if (symbol.getSource() != SourceType.DEFAULT) {
					// remove label which gets created when non-default function is removed
					cmd.add(new DeleteLabelCmd(address, label, symbol.getParentNamespace()));
				}
			}
			else {
				cmd.add(new DeleteLabelCmd(address, label, symbol.getParentNamespace()));
			}
		}
		if (cmd.size() == 0) {
			return;
		}

		if (tool.execute(cmd, getProgram())) {
			for (Symbol s : deleteList) {
				removeObject(new SymbolRowObject(s));
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
	public Address getAddress(int row) {
		SymbolRowObject rowObject = getRowObject(row);
		if (rowObject == null) {
			return null;
		}
		Symbol symbol = rowObject.getSymbol();
		if (symbol == null || symbol.isDeleted()) {
			return null;
		}
		return symbol.getAddress();
	}

	private AddressBasedLocation getSymbolLocation(Symbol s) {
		if (s == null) {
			return new AddressBasedLocation();
		}
		SymbolType type = s.getSymbolType();
		if (type == SymbolType.PARAMETER || type == SymbolType.LOCAL_VAR) {
			// Must use special location object for variables which renders variable storage
			// location since this can't be obtained from just a variable storage address
			Variable object = (Variable) s.getObject();
			if (object == null) {
				return null;
			}
			return new VariableSymbolLocation(object);
		}
		return new AddressBasedLocation(program, s.getAddress());
	}

	@Override
	protected Comparator<SymbolRowObject> createSortComparator(int columnIndex) {
		DynamicTableColumn<SymbolRowObject, ?, ?> column = getColumn(columnIndex);
		if (column instanceof NameTableColumn) {
			// note: we use our own name comparator to increase sorting speed for the name
			//       column.  This works because this comparator is called for each *row object*
			//       allowing the comparator to compare the Symbols based on name instead of
			//       having to use the table model's code for getting a column value for the
			//       row object.   The code for retrieving a column value is slower than just
			//       working with the row object directly.  See
			//       ThreadedTableModel.getCachedColumnValueForRow for more info.
			return NAME_COL_COMPARATOR;
		}
		return super.createSortComparator(columnIndex);
	}

	public SymbolRenderer getSymbolRenderer() {
		return symbolRenderer;
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
			return rowObject.getSymbol();
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
			Symbol symbol = rowObject.getSymbol();
			if (symbol == null || symbol.isDeleted()) {
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
			Symbol symbol = rowObject.getSymbol();
			return getSymbolLocation(symbol);
		}

		@Override
		public ProgramLocation getProgramLocation(SymbolRowObject rowObject, Settings settings,
				Program p, ServiceProvider svcProvider) {
			Symbol symbol = rowObject.getSymbol();
			if (symbol == null || symbol.isDeleted()) {
				return null;
			}
			return symbol.getProgramLocation();
		}
	}

	private class SymbolTypeTableColumn
			extends AbstractProgramBasedDynamicTableColumn<SymbolRowObject, String> {

		@Override
		public String getColumnName() {
			return "Type";
		}

		@Override
		public String getValue(SymbolRowObject rowObject, Settings settings, Program p,
				ServiceProvider svcProvider) throws IllegalArgumentException {
			Symbol symbol = rowObject.getSymbol();
			if (symbol == null || symbol.isDeleted()) {
				return null;
			}

			// Note: this call is slow.  If we decide that filtering/sorting on this value is
			//       important, then this should be cached
			return SymbolUtilities.getSymbolTypeDisplayName(symbol);
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
			Symbol symbol = rowObject.getSymbol();
			if (symbol == null || symbol.isDeleted()) {
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
			Symbol symbol = rowObject.getSymbol();
			if (symbol == null || symbol.isDeleted() || symbol.isDynamic()) {
				return null;
			}
			return symbol.getParentNamespace().getName(true);
		}
	}

	private class SourceTableColumn
			extends AbstractProgramBasedDynamicTableColumn<SymbolRowObject, SourceType> {

		private GColumnRenderer<SourceType> renderer = new AbstractGColumnRenderer<>() {
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
			Symbol symbol = rowObject.getSymbol();
			if (symbol == null || symbol.isDeleted()) {
				return null;
			}

			return symbol.getSource();
		}
	}

	private class ReferenceCountTableColumn
			extends AbstractProgramBasedDynamicTableColumn<SymbolRowObject, Integer> {

		private ReferenceCountRenderer renderer = new ReferenceCountRenderer();

		@Override
		public String getColumnName() {
			return "Reference Count";
		}

		@Override
		public Integer getValue(SymbolRowObject rowObject, Settings settings, Program p,
				ServiceProvider svcProvider) throws IllegalArgumentException {
			Symbol symbol = rowObject.getSymbol();
			if (symbol == null || symbol.isDeleted()) {
				return null;
			}
			return Integer.valueOf(symbol.getReferenceCount());
		}

		@Override
		public GColumnRenderer<Integer> getColumnRenderer() {
			return renderer;
		}

		// this renderer disables the default text filtering; this column is only filterable
		// via the column constraint filtering
		private class ReferenceCountRenderer extends GTableCellRenderer
				implements AbstractWrapperTypeColumnRenderer<Integer> {
			// body is handled by parents
		}
	}

	private class OffcutReferenceCountTableColumn
			extends AbstractProgramBasedDynamicTableColumn<SymbolRowObject, Integer> {

		private OffcutReferenceCountRenderer renderer = new OffcutReferenceCountRenderer();

		@Override
		public String getColumnName() {
			return "Offcut Ref Count";
		}

		@Override
		public Integer getValue(SymbolRowObject rowObject, Settings settings, Program p,
				ServiceProvider svcProvider) throws IllegalArgumentException {
			Symbol symbol = rowObject.getSymbol();
			if (symbol == null || symbol.isDeleted()) {
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

		@Override
		public GColumnRenderer<Integer> getColumnRenderer() {
			return renderer;
		}

		// this renderer disables the default text filtering; this column is only filterable
		// via the column constraint filtering
		private class OffcutReferenceCountRenderer extends GTableCellRenderer
				implements AbstractWrapperTypeColumnRenderer<Integer> {
			// body is handled by parents
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
			Symbol symbol = rowObject.getSymbol();
			if (symbol == null || symbol.isDeleted()) {
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

	class OriginalNameColumn
			extends AbstractProgramBasedDynamicTableColumn<SymbolRowObject, String> {

		@Override
		public String getColumnName() {
			return "Original Imported Name";
		}

		@Override
		public String getColumnDescription() {
			return "The original (pre-demangled) import name (External Symbols Only)";
		}

		@Override
		public String getValue(SymbolRowObject rowObject, Settings settings, Program p,
				ServiceProvider svcProvider) throws IllegalArgumentException {
			Symbol symbol = rowObject.getSymbol();
			if (symbol == null || symbol.isDeleted()) {
				return null;
			}

			if (!symbol.isExternal()) {
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

	private class SimplifiedNameColumn
			extends AbstractProgramBasedDynamicTableColumn<SymbolRowObject, String> {

		private TemplateSimplifier simplifier = new TemplateSimplifier();

		@Override
		public String getColumnName() {
			return "Simplified Name";
		}

		@Override
		public String getColumnDescription() {
			return "The symbol name with less complicated template arguments";
		}

		@Override
		public String getValue(SymbolRowObject rowObject, Settings settings, Program p,
				ServiceProvider svcProvider) throws IllegalArgumentException {

			Symbol symbol = rowObject.getSymbol();
			if (symbol == null || symbol.isDeleted()) {
				return null;
			}

			String name = symbol.getName();
			return simplifier.simplify(name);
		}
	}

}
