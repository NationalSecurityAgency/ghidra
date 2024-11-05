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
package ghidra.app.plugin.core.search;

import java.awt.Component;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;
import java.util.regex.Pattern;

import docking.widgets.table.*;
import ghidra.app.plugin.core.navigation.locationreferences.LocationReferenceContext;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.*;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.table.GhidraProgramTableModel;
import ghidra.util.table.column.AbstractGhidraColumnRenderer;
import ghidra.util.table.column.GColumnRenderer;
import ghidra.util.table.field.AbstractProgramBasedDynamicTableColumn;
import ghidra.util.table.field.FunctionNameTableColumn;
import ghidra.util.task.TaskMonitor;

public class DecompilerTextFinderTableModel extends GhidraProgramTableModel<TextMatch> {

	private String searchText;
	private boolean isRegex;
	private AddressSetView selection;
	private int searchLimit;

	protected DecompilerTextFinderTableModel(ServiceProvider serviceProvider, Program program,
			String searchText, boolean isRegex) {
		super("Decompiler Search", serviceProvider, program, null, true);
		this.searchText = searchText;
		this.isRegex = isRegex;
	}

	void setSelection(AddressSetView selection) {
		this.selection = selection;
	}

	void setSearchLimit(int limit) {
		this.searchLimit = limit;
	}

	@Override
	protected TableColumnDescriptor<TextMatch> createTableColumnDescriptor() {

		TableColumnDescriptor<TextMatch> descriptor = new TableColumnDescriptor<>();

		descriptor.addVisibleColumn(
			DiscoverableTableUtils.adaptColumForModel(this, new FunctionNameTableColumn()), 1,
			true);
		descriptor.addVisibleColumn(new LineNumberTableColumn(), 2, true);
		descriptor.addVisibleColumn(new ContextTableColumn());

		return descriptor;
	}

	@Override
	protected void doLoad(Accumulator<TextMatch> accumulator, TaskMonitor monitor)
			throws CancelledException {

		// Add a consumer that will monitor the count and stop the process on too many results
		AtomicInteger counter = new AtomicInteger();
		Consumer<TextMatch> limitedConsumer = tm -> {
			int count = counter.incrementAndGet();
			if (count >= searchLimit) {
				monitor.cancel();
			}

			accumulator.add(tm);
		};

		Pattern pattern;
		if (isRegex) {
			// note: we expect this to be a valid regex
			pattern = Pattern.compile(searchText);
		}
		else {
			String quoted = Pattern.quote(searchText);
			pattern = Pattern.compile(quoted, Pattern.CASE_INSENSITIVE);
		}

		DecompilerTextFinder finder = new DecompilerTextFinder();
		if (selection != null) {
			FunctionManager functionManager = program.getFunctionManager();
			FunctionIterator functions = functionManager.getFunctions(selection, true);
			finder.findText(program, pattern, functions, limitedConsumer, monitor);
		}
		else {
			finder.findText(program, pattern, limitedConsumer, monitor);
		}
	}

	@Override
	public Address getAddress(int row) {
		TextMatch match = getRowObject(row);
		if (match != null) {
			return match.getAddress();
		}
		return null;
	}

//=================================================================================================
//Inner Classes
//=================================================================================================		

	private class LineNumberTableColumn
			extends AbstractProgramBasedDynamicTableColumn<TextMatch, Integer> {

		@Override
		public Integer getValue(TextMatch rowObject, Settings settings, Program p,
				ServiceProvider sp) throws IllegalArgumentException {
			return rowObject.getLineNumber();
		}

		@Override
		public String getColumnName() {
			return "Line Number";
		}

		@Override
		public int getColumnPreferredWidth() {
			return 75;
		}
	}

	private class ContextTableColumn
			extends AbstractProgramBasedDynamicTableColumn<TextMatch, LocationReferenceContext> {

		private ContextCellRenderer renderer = new ContextCellRenderer();

		@Override
		public LocationReferenceContext getValue(TextMatch rowObject, Settings settings, Program p,
				ServiceProvider sp) throws IllegalArgumentException {
			return rowObject.getContext();
		}

		@Override
		public String getColumnName() {
			return "Context";
		}

		@Override
		public GColumnRenderer<LocationReferenceContext> getColumnRenderer() {
			return renderer;
		}
	}

	private class ContextCellRenderer
			extends AbstractGhidraColumnRenderer<LocationReferenceContext> {

		{
			// the context uses html
			setHTMLRenderingEnabled(true);
		}

		@Override
		public Component getTableCellRendererComponent(GTableCellRenderingData data) {

			// initialize
			super.getTableCellRendererComponent(data);

			TextMatch match = (TextMatch) data.getRowObject();
			LocationReferenceContext context = match.getContext();
			String text;
			if (match.isMultiLine()) {
				// multi-line matches create visual noise when showing colors, as of much of the 
				// entire line matches
				text = context.getPlainText();
			}
			else {
				text = context.getBoldMatchingText();
			}
			setText(text);
			return this;
		}

		@Override
		public String getFilterString(LocationReferenceContext context, Settings settings) {
			return context.getPlainText();
		}
	}
}
