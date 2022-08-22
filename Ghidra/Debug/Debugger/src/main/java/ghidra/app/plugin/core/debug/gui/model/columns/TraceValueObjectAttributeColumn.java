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
package ghidra.app.plugin.core.debug.gui.model.columns;

import java.awt.Color;
import java.awt.Component;
import java.util.Comparator;
import java.util.function.Function;

import javax.swing.JTable;

import docking.widgets.table.*;
import docking.widgets.table.sort.ColumnRenderedValueBackupComparator;
import docking.widgets.table.sort.DefaultColumnComparator;
import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.app.plugin.core.debug.gui.model.ColorsModified;
import ghidra.app.plugin.core.debug.gui.model.ObjectTableModel.ValueRow;
import ghidra.dbg.target.TargetAttacher.TargetAttachKindSet;
import ghidra.dbg.target.TargetBreakpointSpecContainer.TargetBreakpointKindSet;
import ghidra.dbg.target.TargetExecutionStateful.TargetExecutionState;
import ghidra.dbg.target.TargetMethod.TargetParameterMap;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.TargetSteppable.TargetStepKindSet;
import ghidra.dbg.target.schema.SchemaContext;
import ghidra.dbg.target.schema.TargetObjectSchema;
import ghidra.dbg.target.schema.TargetObjectSchema.AttributeSchema;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.trace.model.Trace;
import ghidra.trace.model.target.TraceObject;
import ghidra.trace.model.target.TraceObjectValue;
import ghidra.util.table.column.AbstractGColumnRenderer;
import ghidra.util.table.column.GColumnRenderer;

public class TraceValueObjectAttributeColumn
		extends AbstractDynamicTableColumn<ValueRow, ValueRow, Trace> {

	public class AttributeRenderer extends AbstractGColumnRenderer<ValueRow>
			implements ColorsModified.InTable {
		{
			setHTMLRenderingEnabled(true);
		}

		@Override
		public String getFilterString(ValueRow t, Settings settings) {
			return t.getAttributeDisplay(attributeName);
		}

		@Override
		public Component getTableCellRendererComponent(GTableCellRenderingData data) {
			super.getTableCellRendererComponent(data);
			ValueRow row = (ValueRow) data.getValue();
			setText(row.getAttributeHtmlDisplay(attributeName));
			setToolTipText(row.getAttributeToolTip(attributeName));
			setForeground(getForegroundFor(data.getTable(), row.isAttributeModified(attributeName),
				data.isSelected()));
			return this;
		}

		@Override
		public Color getDiffForeground(JTable table) {
			return diffColor;
		}

		@Override
		public Color getDiffSelForeground(JTable table) {
			return diffColorSel;
		}
	}

	public static Class<?> computeColumnType(SchemaContext ctx, AttributeSchema attributeSchema) {
		TargetObjectSchema schema = ctx.getSchema(attributeSchema.getSchema());
		Class<?> type = schema.getType();
		if (type == TargetObject.class) {
			return TraceObject.class;
		}
		if (type == TargetExecutionState.class) {
			return String.class;
		}
		if (type == TargetParameterMap.class) {
			return String.class;
		}
		if (type == TargetAttachKindSet.class) {
			return String.class;
		}
		if (type == TargetBreakpointKindSet.class) {
			return String.class;
		}
		if (type == TargetStepKindSet.class) {
			return String.class;
		}
		return type;
	}

	public static TraceValueObjectAttributeColumn fromSchema(SchemaContext ctx,
			AttributeSchema attributeSchema) {
		String name = attributeSchema.getName();
		Class<?> type = computeColumnType(ctx, attributeSchema);
		return new TraceValueObjectAttributeColumn(name, type);
	}

	private final String attributeName;
	private final Class<?> attributeType;
	private final AttributeRenderer renderer = new AttributeRenderer();
	private final Comparator<ValueRow> comparator;

	private Color diffColor = DebuggerResources.DEFAULT_COLOR_VALUE_CHANGED;
	private Color diffColorSel = DebuggerResources.DEFAULT_COLOR_VALUE_CHANGED_SEL;

	public TraceValueObjectAttributeColumn(String attributeName, Class<?> attributeType) {
		this.attributeName = attributeName;
		this.attributeType = attributeType;
		this.comparator = newTypedComparator();
	}

	@Override
	public String getColumnName() {
		/**
		 * TODO: These are going to have "_"-prefixed things.... Sure, they're "hidden", but if we
		 * remove them, we're going to hide important info. I'd like a way in the schema to specify
		 * which "interface attribute" an attribute satisfies. That way, the name can be
		 * human-friendly, but the interface can still find what it needs.
		 */
		return attributeName;
	}

	@Override
	public ValueRow getValue(ValueRow rowObject, Settings settings, Trace data,
			ServiceProvider serviceProvider) throws IllegalArgumentException {
		return rowObject;
	}

	@Override
	public GColumnRenderer<ValueRow> getColumnRenderer() {
		return renderer;
	}

	@Override
	public Comparator<ValueRow> getComparator(DynamicColumnTableModel<?> model, int columnIndex) {
		return comparator == null ? null
				: comparator.thenComparing(
					new ColumnRenderedValueBackupComparator<>(model, columnIndex));
	}

	protected Object getAttributeValue(ValueRow row) {
		TraceObjectValue edge = row.getAttribute(attributeName);
		return edge == null ? null : edge.getValue();
	}

	protected <C extends Comparable<C>> Comparator<ValueRow> newTypedComparator() {
		if (Comparable.class.isAssignableFrom(attributeType)) {
			@SuppressWarnings("unchecked")
			Class<C> cls = (Class<C>) attributeType.asSubclass(Comparable.class);
			Function<ValueRow, C> keyExtractor = r -> cls.cast(getAttributeValue(r));
			return Comparator.comparing(keyExtractor, new DefaultColumnComparator());
		}
		return null; // Opt for the default filter-string-based comparator
	}

	public void setDiffColor(Color diffColor) {
		this.diffColor = diffColor;
	}

	public void setDiffColorSel(Color diffColorSel) {
		this.diffColorSel = diffColorSel;
	}
}
