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
package ghidra.features.base.quickfix;

import java.awt.Component;
import java.util.Map;
import java.util.Map.Entry;

import javax.swing.JLabel;

import docking.widgets.table.*;
import ghidra.docking.settings.Settings;
import ghidra.framework.model.DomainObjectChangedEvent;
import ghidra.framework.model.DomainObjectListener;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.HTMLUtilities;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.table.GhidraProgramTableModel;
import ghidra.util.table.column.AbstractGhidraColumnRenderer;
import ghidra.util.table.column.GColumnRenderer;
import ghidra.util.task.SwingUpdateManager;
import ghidra.util.task.TaskMonitor;

/**
 * Table model for {@link QuickFix}s
 */
public class QuickFixTableModel extends GhidraProgramTableModel<QuickFix>
		implements DomainObjectListener {
	private TableDataLoader<QuickFix> tableLoader;
	private SwingUpdateManager updateManager = new SwingUpdateManager(1000, this::refreshItems);
	private QuickFixRenderer quickFixRenderer = new QuickFixRenderer();

	protected QuickFixTableModel(Program program, String modelName, ServiceProvider serviceProvider,
			TableDataLoader<QuickFix> loader) {
		super(modelName, serviceProvider, program, null);
		this.tableLoader = loader;

		program.addListener(this);
	}

	@Override
	public void dispose() {
		updateManager.dispose();
		if (program != null) {
			program.removeListener(this);
		}
		program = null;
		super.dispose();
	}

	@Override
	protected void doLoad(Accumulator<QuickFix> accumulator, TaskMonitor monitor)
			throws CancelledException {
		tableLoader.loadData(accumulator, monitor);
	}

	@Override
	protected TableColumnDescriptor<QuickFix> createTableColumnDescriptor() {
		TableColumnDescriptor<QuickFix> descriptor = new TableColumnDescriptor<>();

		descriptor.addVisibleColumn(new OriginalValueColumn(), 1, true);
		descriptor.addHiddenColumn(new CurrentValueColumn());
		descriptor.addVisibleColumn(new PreviewColumn());
		descriptor.addVisibleColumn(new ActionColumn());
		descriptor.addVisibleColumn(new TypeColumn());
		descriptor.addHiddenColumn(new AddressColumn());
		descriptor.addHiddenColumn(new PathColumn());
		descriptor.addVisibleColumn(new QuickFixStatusColumn());

		return descriptor;
	}

	@Override
	public ProgramLocation getProgramLocation(int modelRow, int modelColumn) {
		if (modelRow < 0 || modelRow >= filteredData.size()) {
			return null;
		}

		QuickFix quickFix = filteredData.get(modelRow);
		return quickFix.getProgramLocation();
	}

	@Override
	public void domainObjectChanged(DomainObjectChangedEvent ev) {
		updateManager.update();
	}

	private void refreshItems() {
		fireTableDataChanged();
	}

	private class QuickFixStatusColumn
			extends AbstractDynamicTableColumnStub<QuickFix, QuickFixStatus> {

		QuickFixStatusRenderer renderer = new QuickFixStatusRenderer();

		@Override
		public String getColumnName() {
			return "Status";
		}

		@Override
		public int getColumnPreferredWidth() {
			return 25;
		}

		@Override
		public QuickFixStatus getValue(QuickFix rowObject, Settings settings,
				ServiceProvider sp) throws IllegalArgumentException {
			return rowObject.getStatus();
		}

		@Override
		public GColumnRenderer<QuickFixStatus> getColumnRenderer() {
			return renderer;
		}
	}

	private class TypeColumn
			extends AbstractDynamicTableColumnStub<QuickFix, String> {

		@Override
		public String getColumnName() {
			return "Type";
		}

		@Override
		public int getColumnPreferredWidth() {
			return 100;
		}

		@Override
		public String getValue(QuickFix rowObject, Settings settings,
				ServiceProvider sp) throws IllegalArgumentException {
			return rowObject.getItemType();
		}
	}

	private class ActionColumn
			extends AbstractDynamicTableColumnStub<QuickFix, String> {

		@Override
		public String getColumnName() {
			return "Action";
		}

		@Override
		public int getColumnPreferredWidth() {
			return 75;
		}

		@Override
		public String getValue(QuickFix rowObject, Settings settings,
				ServiceProvider sp) throws IllegalArgumentException {
			return rowObject.getActionName();
		}
	}

	private class CurrentValueColumn
			extends AbstractDynamicTableColumnStub<QuickFix, String> {

		@Override
		public String getColumnName() {
			return "Current";
		}

		@Override
		public int getColumnPreferredWidth() {
			return 150;
		}

		@Override
		public String getValue(QuickFix rowObject, Settings settings,
				ServiceProvider sp) throws IllegalArgumentException {
			return rowObject.getCurrent();
		}

		@Override
		public GColumnRenderer<String> getColumnRenderer() {
			return quickFixRenderer;
		}

	}

	private class OriginalValueColumn
			extends AbstractDynamicTableColumnStub<QuickFix, String> {

		@Override
		public String getColumnName() {
			return "Original";
		}

		@Override
		public int getColumnPreferredWidth() {
			return 150;
		}

		@Override
		public String getValue(QuickFix rowObject, Settings settings,
				ServiceProvider sp) throws IllegalArgumentException {
			return rowObject.getOriginal();
		}

		@Override
		public GColumnRenderer<String> getColumnRenderer() {
			return quickFixRenderer;
		}

	}

	private class PreviewColumn
			extends AbstractDynamicTableColumnStub<QuickFix, String> {

		@Override
		public String getColumnName() {
			return "Preview";
		}

		@Override
		public int getColumnPreferredWidth() {
			return 150;
		}

		@Override
		public String getValue(QuickFix rowObject, Settings settings,
				ServiceProvider sp) throws IllegalArgumentException {
			return rowObject.getPreview();
		}

		@Override
		public GColumnRenderer<String> getColumnRenderer() {
			return quickFixRenderer;
		}
	}

	private class AddressColumn
			extends AbstractDynamicTableColumnStub<QuickFix, Address> {

		@Override
		public String getColumnName() {
			return "Address";
		}

		@Override
		public int getColumnPreferredWidth() {
			return 50;
		}

		@Override
		public Address getValue(QuickFix rowObject, Settings settings,
				ServiceProvider sp) throws IllegalArgumentException {
			return rowObject.getAddress();
		}
	}

	private class PathColumn
			extends AbstractDynamicTableColumnStub<QuickFix, String> {

		@Override
		public String getColumnName() {
			return "Path";
		}

		@Override
		public int getColumnPreferredWidth() {
			return 150;
		}

		@Override
		public String getValue(QuickFix rowObject, Settings settings,
				ServiceProvider sp) throws IllegalArgumentException {
			return rowObject.getPath();
		}
	}

	public class QuickFixRenderer extends AbstractGhidraColumnRenderer<String> {

		@Override
		public Component getTableCellRendererComponent(GTableCellRenderingData data) {

			JLabel renderer = (JLabel) super.getTableCellRendererComponent(data);

			QuickFix item = (QuickFix) data.getRowObject();
			StringBuilder buf = new StringBuilder();
			buf.append("<HTML>");
			buf.append("<TABLE>");
			addHtmlTableRow(buf, "Action", item.getActionName() + " " + item.getItemType());

			Address address = item.getAddress();
			if (address != null && address.isMemoryAddress()) {
				addHtmlTableRow(buf, "Address", address.toString());
			}
			addCustomTableRows(buf, item.getCustomToolTipData());

			addHtmlTableRow(buf, "Original", item.getOriginal());
			addHtmlTableRow(buf, "Preview", item.getPreview());
			addHtmlTableRow(buf, "Current", item.getCurrent());
			buf.append("</TABLE></HTML>");

			renderer.setToolTipText(buf.toString());

			return renderer;
		}

		private void addCustomTableRows(StringBuilder buf, Map<String, String> dataMap) {
			if (dataMap == null) {
				return;
			}
			for (Entry<String, String> entry : dataMap.entrySet()) {
				addHtmlTableRow(buf, entry.getKey(), entry.getValue());
			}
		}

		private void addHtmlTableRow(StringBuilder buf, String name, String value) {
			buf.append("<TR><TD><B>");
			buf.append(HTMLUtilities.escapeHTML(name));
			buf.append(":</B></TD><TD>");
			buf.append(HTMLUtilities.escapeHTML(value));
			buf.append("</TD></TR>");
		}

		@Override
		public String getFilterString(String t, Settings settings) {
			return t;
		}

	}

}
