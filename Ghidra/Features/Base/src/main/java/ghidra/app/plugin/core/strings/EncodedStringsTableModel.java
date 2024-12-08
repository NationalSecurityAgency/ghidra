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
package ghidra.app.plugin.core.strings;

import java.lang.Character.UnicodeScript;
import java.util.*;
import java.util.stream.Collectors;

import javax.swing.JTable;
import javax.swing.table.TableModel;

import docking.widgets.table.TableColumnDescriptor;
import generic.theme.GThemeDefaults;
import ghidra.app.services.StringValidatorQuery;
import ghidra.app.services.StringValidityScore;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.framework.plugintool.ServiceProviderStub;
import ghidra.program.model.address.*;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.table.AddressBasedTableModel;
import ghidra.util.table.column.AbstractGColumnRenderer;
import ghidra.util.table.column.GColumnRenderer;
import ghidra.util.table.field.AbstractProgramLocationTableColumn;
import ghidra.util.table.field.AddressBasedLocation;
import ghidra.util.task.TaskMonitor;

class EncodedStringsTableModel extends AddressBasedTableModel<EncodedStringsRow> {

	private UnicodeScriptColumn unicodeScriptColumn;
	private ValidStringColumn validStringColumn;

	private AddressSetView selectedAddresses;
	private AddressSetView filteredAddresses;
	private boolean singleStringMode;

	private ModelState state;

	EncodedStringsTableModel(Program program, AddressSetView selectedAddresses) {
		super("Encoded Strings Table", new ServiceProviderStub(), program, null, true);
		this.selectedAddresses = selectedAddresses;
		this.singleStringMode = selectedAddresses.getNumAddresses() == 1;
		this.state = new ModelState(null, null);
	}

	public EncodedStringsFilterStats getStats() {
		return state.stats;
	}

	@Override
	public void dispose() {
		state = new ModelState(null, null);
		super.dispose();
	}

	@Override
	protected TableColumnDescriptor<EncodedStringsRow> createTableColumnDescriptor() {
		TableColumnDescriptor<EncodedStringsRow> descriptor = new TableColumnDescriptor<>();

		this.validStringColumn = new ValidStringColumn();
		this.unicodeScriptColumn = new UnicodeScriptColumn();

		descriptor.addVisibleColumn(new DataLocationColumn(), 1, true);
		descriptor.addVisibleColumn(new StringRepColumn());
		descriptor.addHiddenColumn(new RefCountColumn());
		descriptor.addHiddenColumn(new OffcutRefCountColumn());
		descriptor.addVisibleColumn(unicodeScriptColumn);
		descriptor.addVisibleColumn(validStringColumn);
		descriptor.addVisibleColumn(new LengthColumn());
		descriptor.addHiddenColumn(new ByteLengthColumn());

		return descriptor;
	}

	@Override
	protected void doLoad(Accumulator<EncodedStringsRow> accumulator, TaskMonitor monitor)
			throws CancelledException {

		Program localProgram = program;
		ModelState state = this.state;

		if (state == null || localProgram == null || state.options == null) {
			return;
		}

		if (state.previousData != null) {
			// used cached strings and re-filter
			EncodedStringsFilterStats newStats = new EncodedStringsFilterStats();
			for (EncodedStringsRow row : state.previousData) {
				if (row.matches(state.options, newStats)) {
					accumulator.add(row);
				}
			}
			state.stats = newStats;
			return;
		}

		Listing listing = localProgram.getListing();
		if (filteredAddresses == null) {
			filteredAddresses = singleStringMode
					? UndefinedStringIterator.getSingleStringEndAddrRange(localProgram,
						selectedAddresses)
					: new AddressSet(selectedAddresses);
			filteredAddresses =
				filteredAddresses.intersect(localProgram.getMemory().getAllInitializedAddressSet());

			monitor.setIndeterminate(true);
			monitor.initialize(0, "Finding undefined address ranges");
			// Note: this can be slow for large programs 
			filteredAddresses = listing.getUndefinedRanges(filteredAddresses, false, monitor);
			monitor.setIndeterminate(false);
		}

		int align = 1;
		if (state.options.alignStartOfString()) {
			align = localProgram.getDataTypeManager()
					.getDataOrganization()
					.getSizeAlignment(state.options.charSize());
		}

		List<EncodedStringsRow> allStrings = new ArrayList<>();
		EncodedStringsFilterStats newStats = new EncodedStringsFilterStats();
		UndefinedStringIterator usi = new UndefinedStringIterator(localProgram, filteredAddresses,
			state.options.charSize(), align, state.options.breakOnRef(), singleStringMode,
			state.options.stringDT(), state.options.settings(), monitor);

		for (StringDataInstance sdi : usi) {
			monitor.checkCancelled();

			StringInfo stringInfo = StringInfo.fromString(sdi.getStringValue());
			int refCount = localProgram.getReferenceManager().getReferenceCountTo(sdi.getAddress());
			int offcutRefCount = getOffcutRefCount(localProgram,
				new AddressRangeImpl(sdi.getAddress(), sdi.getEndAddress()));
			boolean isValid = true;
			if (state.options.stringValidator() != null) {
				StringValidatorQuery svq =
					new StringValidatorQuery(stringInfo.stringValue(), stringInfo);
				StringValidityScore score =
					state.options.stringValidator().getStringValidityScore(svq);
				isValid = score.isScoreAboveThreshold();
			}

			EncodedStringsRow row =
				new EncodedStringsRow(sdi, stringInfo, refCount, offcutRefCount, isValid);

			allStrings.add(row);

			if (row.matches(state.options, newStats)) {
				accumulator.add(row);
			}
			if (singleStringMode) {
				break;
			}
		}

		state.stats = newStats;
		state.previousData = allStrings;
	}

	@Override
	public ProgramSelection getProgramSelection(int[] rows) {
		AddressSet set = new AddressSet();
		for (int elementIndex : rows) {
			EncodedStringsRow row = filteredData.get(elementIndex);
			set.add(row.sdi().getAddressRange());
		}
		return new ProgramSelection(set);
	}

	public void removeRows(List<EncodedStringsRow> rows) {
		for (EncodedStringsRow row : rows) {
			removeObject(row);
		}
	}

	public void setOptions(EncodedStringsOptions options) {
		boolean canReusePrevData = options.equivalentStringCreationOptions(state.options);
		ModelState newState = new ModelState(options, canReusePrevData ? state.previousData : null);
		this.state = newState;
		clearData();
		reload();
	}

	@Override
	public Address getAddress(int row) {
		return getRowObject(row).sdi().getAddress();
	}

	private int getOffcutRefCount(Program localProgram, AddressRange range) {
		int offcutRefCount = 0;
		Address prevAddr = range.getMinAddress(); // this also allows us to skip the first addr of the range
		for (Address address : localProgram.getReferenceManager()
				.getReferenceDestinationIterator(new AddressSet(range), true)) {
			if (!address.equals(prevAddr)) {
				offcutRefCount++;
				prevAddr = address;
			}
		}
		return offcutRefCount;
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private static class DataLocationColumn
			extends AbstractProgramLocationTableColumn<EncodedStringsRow, AddressBasedLocation> {

		@Override
		public String getColumnName() {
			return "Location";
		}

		@Override
		public AddressBasedLocation getValue(EncodedStringsRow rowObject, Settings settings,
				Program program, ServiceProvider serviceProvider) throws IllegalArgumentException {
			return new AddressBasedLocation(program, rowObject.sdi().getAddress());
		}

		@Override
		public ProgramLocation getProgramLocation(EncodedStringsRow rowObject, Settings settings,
				Program program, ServiceProvider serviceProvider) {
			return new ProgramLocation(program, rowObject.sdi().getAddress());
		}

	}

	private static class StringRepColumn
			extends AbstractProgramLocationTableColumn<EncodedStringsRow, EncodedStringsRow> {

		private StringRepCellRenderer renderer = new StringRepCellRenderer();

		@Override
		public String getColumnName() {
			return "String";
		}

		@Override
		public EncodedStringsRow getValue(EncodedStringsRow rowObject, Settings settings,
				Program program, ServiceProvider serviceProvider) throws IllegalArgumentException {
			return rowObject;
		}

		@Override
		public ProgramLocation getProgramLocation(EncodedStringsRow rowObject, Settings settings,
				Program program, ServiceProvider serviceProvider) {
			return new ProgramLocation(program, rowObject.sdi().getAddress());
		}

		@Override
		public GColumnRenderer<EncodedStringsRow> getColumnRenderer() {
			return renderer;
		}

		private class StringRepCellRenderer extends AbstractGColumnRenderer<EncodedStringsRow> {

			@Override
			protected String getText(Object value) {
				return value instanceof EncodedStringsRow rowValue
						? rowValue.sdi().getStringRepresentation()
						: "";
			}

			@Override
			public String getFilterString(EncodedStringsRow t, Settings settings) {
				return getText(t);
			}

			@Override
			protected void setForegroundColor(JTable table, TableModel model, Object value) {
				if (value instanceof EncodedStringsRow rowValue &&
					rowValue.stringInfo().hasCodecError()) {
					setForeground(GThemeDefaults.Colors.Tables.ERROR_UNSELECTED);
				}
				else {
					super.setForegroundColor(table, model, value);
				}
			}
		}
	}

	private static class UnicodeScriptColumn
			extends AbstractProgramLocationTableColumn<EncodedStringsRow, String> {

		@Override
		public String getColumnName() {
			return "Unicode Script";
		}

		@Override
		public String getValue(EncodedStringsRow rowObject, Settings settings, Program program,
				ServiceProvider serviceProvider) throws IllegalArgumentException {

			Set<UnicodeScript> scripts = rowObject.stringInfo().scripts();
			String formattedColStr =
				scripts.stream().map(UnicodeScript::name).collect(Collectors.joining(","));

			return formattedColStr;
		}

		@Override
		public ProgramLocation getProgramLocation(EncodedStringsRow rowObject, Settings settings,
				Program program, ServiceProvider serviceProvider) {
			return new ProgramLocation(program, rowObject.sdi().getAddress());
		}
	}

	private static class RefCountColumn
			extends AbstractProgramLocationTableColumn<EncodedStringsRow, Integer> {

		@Override
		public String getColumnName() {
			return "Reference Count";
		}

		@Override
		public Integer getValue(EncodedStringsRow rowObject, Settings settings, Program program,
				ServiceProvider serviceProvider) throws IllegalArgumentException {

			return rowObject.refCount();
		}

		@Override
		public ProgramLocation getProgramLocation(EncodedStringsRow rowObject, Settings settings,
				Program program, ServiceProvider serviceProvider) {
			return new ProgramLocation(program, rowObject.sdi().getAddress());
		}
	}

	private static class OffcutRefCountColumn
			extends AbstractProgramLocationTableColumn<EncodedStringsRow, Integer> {

		@Override
		public String getColumnName() {
			return "Offcut Reference Count";
		}

		@Override
		public Integer getValue(EncodedStringsRow rowObject, Settings settings, Program program,
				ServiceProvider serviceProvider) throws IllegalArgumentException {

			return rowObject.offcutCount();
		}

		@Override
		public ProgramLocation getProgramLocation(EncodedStringsRow rowObject, Settings settings,
				Program program, ServiceProvider serviceProvider) {
			return new ProgramLocation(program, rowObject.sdi().getAddress());
		}
	}

	private static class ValidStringColumn
			extends AbstractProgramLocationTableColumn<EncodedStringsRow, Boolean> {

		@Override
		public String getColumnName() {
			return "Is Valid String";
		}

		@Override
		public Boolean getValue(EncodedStringsRow rowObject, Settings settings, Program program,
				ServiceProvider serviceProvider) throws IllegalArgumentException {

			return rowObject.validString();
		}

		@Override
		public ProgramLocation getProgramLocation(EncodedStringsRow rowObject, Settings settings,
				Program program, ServiceProvider serviceProvider) {
			return new ProgramLocation(program, rowObject.sdi().getAddress());
		}
	}

	private static class LengthColumn
			extends AbstractProgramLocationTableColumn<EncodedStringsRow, Integer> {

		@Override
		public String getColumnName() {
			return "Length";
		}

		@Override
		public Integer getValue(EncodedStringsRow rowObject, Settings settings, Program program,
				ServiceProvider serviceProvider) throws IllegalArgumentException {

			return rowObject.stringInfo().stringValue().length();
		}

		@Override
		public ProgramLocation getProgramLocation(EncodedStringsRow rowObject, Settings settings,
				Program program, ServiceProvider serviceProvider) {
			return new ProgramLocation(program, rowObject.sdi().getAddress());
		}
	}

	private static class ByteLengthColumn
			extends AbstractProgramLocationTableColumn<EncodedStringsRow, Integer> {

		@Override
		public String getColumnName() {
			return "Byte Length";
		}

		@Override
		public Integer getValue(EncodedStringsRow rowObject, Settings settings, Program program,
				ServiceProvider serviceProvider) throws IllegalArgumentException {

			return rowObject.sdi().getDataLength();
		}

		@Override
		public ProgramLocation getProgramLocation(EncodedStringsRow rowObject, Settings settings,
				Program program, ServiceProvider serviceProvider) {
			return new ProgramLocation(program, rowObject.sdi().getAddress());
		}
	}

	private static class ModelState {
		final EncodedStringsOptions options;
		Collection<EncodedStringsRow> previousData;
		EncodedStringsFilterStats stats = new EncodedStringsFilterStats();

		ModelState(EncodedStringsOptions options, Collection<EncodedStringsRow> previousData) {
			this.options = options;
			this.previousData = previousData;
		}
	}

}
