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
package ghidra.util.table;

import java.awt.Color;
import java.awt.Component;
import java.util.Collection;
import java.util.function.Supplier;

import javax.swing.JLabel;

import docking.widgets.table.GTableCellRenderingData;
import generic.theme.GColor;
import ghidra.app.plugin.core.navigation.locationreferences.ReferenceUtils;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.util.HTMLUtilities;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.table.column.AbstractGColumnRenderer;
import ghidra.util.table.column.GColumnRenderer;
import ghidra.util.table.field.*;
import ghidra.util.task.TaskMonitor;

/**
 * Table model for showing the 'from' side of passed-in references.
 */
public class ReferencesFromTableModel extends AddressBasedTableModel<ReferenceEndpoint> {

	private Supplier<Collection<Reference>> refsSupplier;

	public ReferencesFromTableModel(Collection<Reference> refs, ServiceProvider sp,
			Program program) {
		super("References", sp, program, null);

		this.refsSupplier = () -> refs;

		addTableColumn(new ReferenceTypeTableColumn());
	}

	public ReferencesFromTableModel(Supplier<Collection<Reference>> refsSupplier,
			ServiceProvider sp, Program program) {
		super("References", sp, program, null);
		this.refsSupplier = refsSupplier;

		addTableColumn(new ReferenceTypeTableColumn());
	}

	@Override
	protected void doLoad(Accumulator<ReferenceEndpoint> accumulator, TaskMonitor monitor)
			throws CancelledException {

		Collection<Reference> xrefs = refsSupplier.get();
		for (Reference xref : xrefs) {
			boolean offcut = ReferenceUtils.isOffcut(program, xref.getToAddress());
			IncomingReferenceEndpoint endpoint = new IncomingReferenceEndpoint(xref, offcut);
			accumulator.add(endpoint);
		}
	}

	@Override
	public Address getAddress(int row) {
		ReferenceEndpoint rowObject = getRowObject(row);
		return rowObject.getAddress();
	}

	private class ReferenceTypeTableColumn
			extends AbstractProgramBasedDynamicTableColumn<ReferenceEndpoint, ReferenceEndpoint> {

		private ReferenceTypeTableCellRenderer renderer = new ReferenceTypeTableCellRenderer();

		@Override
		public ReferenceEndpoint getValue(ReferenceEndpoint rowObject, Settings settings,
				Program data, ServiceProvider sp) throws IllegalArgumentException {
			return rowObject;
		}

		@Override
		public String getColumnName() {
			return "Ref Type";
		}

		@Override
		public GColumnRenderer<ReferenceEndpoint> getColumnRenderer() {
			return renderer;
		}
	}

	private class ReferenceTypeTableCellRenderer
			extends AbstractGColumnRenderer<ReferenceEndpoint> {

		// " << OFFCUT >>"
		private static final String PLAIN_OFFCUT_TEXT = "<< OFFCUT >>";
		private static final String HTML_OFFCUT_TEXT = " &lt;&lt; OFFCUT &gt;&gt;";
		private static final Color OFFCUT_COLOR = new GColor("color.fg.table.offcut.unselected");

		ReferenceTypeTableCellRenderer() {
			setHTMLRenderingEnabled(true);
		}

		@Override
		public Component getTableCellRendererComponent(GTableCellRenderingData data) {

			// initialize
			JLabel label = (JLabel) super.getTableCellRendererComponent(data);

			ReferenceEndpoint rowObject = (ReferenceEndpoint) data.getValue();
			String text = asString(rowObject);
			label.setText(text);
			label.setToolTipText(rowObject.getReferenceType().getName());

			return label;
		}

		private String asString(ReferenceEndpoint t) {
			RefType refType = t.getReferenceType();
			String text = refType.getDisplayString();
			if (t.isOffcut()) {
				text = "<html>" + HTMLUtilities.colorString(OFFCUT_COLOR, text + HTML_OFFCUT_TEXT);
			}
			return text;
		}

		@Override
		public String getFilterString(ReferenceEndpoint t, Settings settings) {
			RefType refType = t.getReferenceType();
			String text = refType.getDisplayString();
			if (t.isOffcut()) {
				return text + PLAIN_OFFCUT_TEXT;
			}
			return text;
		}
	}
}
