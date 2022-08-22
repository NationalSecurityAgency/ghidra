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
package ghidra.app.plugin.core.debug.gui.model;

import java.awt.Color;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import com.google.common.collect.*;

import docking.widgets.table.DynamicTableColumn;
import docking.widgets.table.TableColumnDescriptor;
import ghidra.app.plugin.core.debug.gui.model.ObjectTableModel.ValueRow;
import ghidra.app.plugin.core.debug.gui.model.columns.*;
import ghidra.dbg.target.schema.SchemaContext;
import ghidra.dbg.target.schema.TargetObjectSchema;
import ghidra.dbg.target.schema.TargetObjectSchema.AttributeSchema;
import ghidra.framework.plugintool.Plugin;
import ghidra.trace.model.Trace;
import ghidra.trace.model.target.TraceObject;
import ghidra.trace.model.target.TraceObjectValue;
import ghidra.util.HTMLUtilities;

public class ObjectTableModel extends AbstractQueryTableModel<ValueRow> {
	/** Initialized in {@link #createTableColumnDescriptor()}, which precedes this. */
	private TraceValueValColumn valueColumn;
	private TraceValueLifePlotColumn lifePlotColumn;

	protected static Stream<? extends TraceObjectValue> distinctCanonical(
			Stream<? extends TraceObjectValue> stream) {
		Set<TraceObject> seen = new HashSet<>();
		return stream.filter(value -> {
			if (!value.isCanonical()) {
				return true;
			}
			return seen.add(value.getChild());
		});
	}

	public interface ValueRow {
		String getKey();

		RangeSet<Long> getLife();

		TraceObjectValue getValue();

		/**
		 * Get a non-HTML string representing how this row's value should be sorted, filtered, etc.
		 * 
		 * @return the display string
		 */
		String getDisplay();

		/**
		 * Get an HTML string representing how this row's value should be displayed
		 * 
		 * @return the display string
		 */
		String getHtmlDisplay();

		String getToolTip();

		/**
		 * Determine whether the value in the row has changed since the diff coordinates
		 * 
		 * @return true if they differ, i.e., should be rendered in red
		 */
		boolean isModified();

		TraceObjectValue getAttribute(String attributeName);

		String getAttributeDisplay(String attributeName);

		String getAttributeHtmlDisplay(String attributeName);

		String getAttributeToolTip(String attributeName);

		boolean isAttributeModified(String attributeName);

	}

	protected abstract class AbstractValueRow implements ValueRow {
		protected final TraceObjectValue value;

		public AbstractValueRow(TraceObjectValue value) {
			this.value = value;
		}

		@Override
		public TraceObjectValue getValue() {
			return value;
		}

		@Override
		public String getKey() {
			return value.getEntryKey();
		}

		@Override
		public RangeSet<Long> getLife() {
			RangeSet<Long> life = TreeRangeSet.create();
			life.add(value.getLifespan());
			return life;
		}

		@Override
		public boolean isModified() {
			return isValueModified(getValue());
		}
	}

	protected class PrimitiveRow extends AbstractValueRow {
		public PrimitiveRow(TraceObjectValue value) {
			super(value);
		}

		@Override
		public String getDisplay() {
			return display.getPrimitiveValueDisplay(value.getValue());
		}

		@Override
		public String getHtmlDisplay() {
			return "<html>" +
				HTMLUtilities.escapeHTML(display.getPrimitiveValueDisplay(value.getValue()));
		}

		@Override
		public String getToolTip() {
			return display.getPrimitiveEdgeToolTip(value);
		}

		@Override
		public TraceObjectValue getAttribute(String attributeName) {
			return null;
		}

		@Override
		public String getAttributeDisplay(String attributeName) {
			return null;
		}

		@Override
		public String getAttributeHtmlDisplay(String attributeName) {
			return null;
		}

		@Override
		public String getAttributeToolTip(String attributeName) {
			return null;
		}

		@Override
		public boolean isAttributeModified(String attributeName) {
			return false;
		}
	}

	protected class ObjectRow extends AbstractValueRow {
		private final TraceObject object;

		public ObjectRow(TraceObjectValue value) {
			super(value);
			this.object = value.getChild();
		}

		public TraceObject getTraceObject() {
			return object;
		}

		@Override
		public String getDisplay() {
			return display.getEdgeDisplay(value);
		}

		@Override
		public String getHtmlDisplay() {
			return display.getEdgeHtmlDisplay(value);
		}

		@Override
		public String getToolTip() {
			return display.getEdgeToolTip(value);
		}

		@Override
		public TraceObjectValue getAttribute(String attributeName) {
			return object.getAttribute(getSnap(), attributeName);
		}

		@Override
		public String getAttributeDisplay(String attributeName) {
			return display.getEdgeDisplay(getAttribute(attributeName));
		}

		@Override
		public String getAttributeHtmlDisplay(String attributeName) {
			return display.getEdgeHtmlDisplay(getAttribute(attributeName));
		}

		@Override
		public String getAttributeToolTip(String attributeName) {
			return display.getEdgeToolTip(getAttribute(attributeName));
		}

		@Override
		public boolean isAttributeModified(String attributeName) {
			return isValueModified(getAttribute(attributeName));
		}
	}

	protected ValueRow rowForValue(TraceObjectValue value) {
		if (value.getValue() instanceof TraceObject) {
			return new ObjectRow(value);
		}
		return new PrimitiveRow(value);
	}

	protected static class ColKey {
		public static ColKey fromSchema(SchemaContext ctx, AttributeSchema attributeSchema) {
			String name = attributeSchema.getName();
			Class<?> type = TraceValueObjectAttributeColumn.computeColumnType(ctx, attributeSchema);
			return new ColKey(name, type);
		}

		private final String name;
		private final Class<?> type;
		private final int hash;

		public ColKey(String name, Class<?> type) {
			this.name = name;
			this.type = type;
			this.hash = Objects.hash(name, type);
		}

		@Override
		public boolean equals(Object obj) {
			if (obj == this) {
				return true;
			}
			if (!(obj instanceof ColKey)) {
				return false;
			}
			ColKey that = (ColKey) obj;
			if (!Objects.equals(this.name, that.name)) {
				return false;
			}
			if (this.type != that.type) {
				return false;
			}
			return true;
		}

		@Override
		public int hashCode() {
			return hash;
		}
	}

	// TODO: Save and restore these between sessions, esp., their settings
	private Map<ColKey, TraceValueObjectAttributeColumn> columnCache = new HashMap<>();

	protected ObjectTableModel(Plugin plugin) {
		super("Object Model", plugin);
	}

	@Override
	protected void traceChanged() {
		reloadAttributeColumns();
		updateTimelineMax();
		super.traceChanged();
	}

	@Override
	protected void queryChanged() {
		reloadAttributeColumns();
		super.queryChanged();
	}

	@Override
	protected void showHiddenChanged() {
		reloadAttributeColumns();
		super.showHiddenChanged();
	}

	@Override
	protected void maxSnapChanged() {
		updateTimelineMax();
		refresh();
	}

	protected void updateTimelineMax() {
		Long max = getTrace() == null ? null : getTrace().getTimeManager().getMaxSnap();
		Range<Long> fullRange = Range.closed(0L, max == null ? 1 : max + 1);
		lifePlotColumn.setFullRange(fullRange);
	}

	protected List<AttributeSchema> computeAttributeSchemas() {
		Trace trace = getTrace();
		ModelQuery query = getQuery();
		if (trace == null || query == null) {
			return List.of();
		}
		TargetObjectSchema rootSchema = trace.getObjectManager().getRootSchema();
		if (rootSchema == null) {
			return List.of();
		}
		SchemaContext ctx = rootSchema.getContext();
		return query.computeAttributes(trace)
				.filter(a -> isShowHidden() || !a.isHidden())
				.filter(a -> !ctx.getSchema(a.getSchema()).isCanonicalContainer())
				.collect(Collectors.toList());
	}

	protected void reloadAttributeColumns() {
		List<AttributeSchema> attributes;
		Trace trace = getTrace();
		ModelQuery query = getQuery();
		if (trace == null || query == null || trace.getObjectManager().getRootSchema() == null) {
			attributes = List.of();
		}
		else {
			SchemaContext ctx = trace.getObjectManager().getRootSchema().getContext();
			attributes = query.computeAttributes(trace)
					.filter(a -> isShowHidden() || !a.isHidden())
					.filter(a -> !ctx.getSchema(a.getSchema()).isCanonicalContainer())
					.collect(Collectors.toList());
		}
		resyncAttributeColumns(attributes);
	}

	protected Set<DynamicTableColumn<ValueRow, ?, ?>> computeAttributeColumns(
			Collection<AttributeSchema> attributes) {
		Trace trace = getTrace();
		if (trace == null) {
			return Set.of();
		}
		TargetObjectSchema rootSchema = trace.getObjectManager().getRootSchema();
		if (rootSchema == null) {
			return Set.of();
		}
		SchemaContext ctx = rootSchema.getContext();
		return attributes.stream()
				.map(as -> columnCache.computeIfAbsent(ColKey.fromSchema(ctx, as),
					ck -> TraceValueObjectAttributeColumn.fromSchema(ctx, as)))
				.collect(Collectors.toSet());
	}

	protected void resyncAttributeColumns(Collection<AttributeSchema> attributes) {
		Set<DynamicTableColumn<ValueRow, ?, ?>> columns =
			new HashSet<>(computeAttributeColumns(attributes));
		Set<DynamicTableColumn<ValueRow, ?, ?>> toRemove = new HashSet<>();
		for (int i = 0; i < getColumnCount(); i++) {
			DynamicTableColumn<ValueRow, ?, ?> exists = getColumn(i);
			if (!(exists instanceof TraceValueObjectAttributeColumn)) {
				continue;
			}
			if (!columns.remove(exists)) {
				toRemove.add(exists);
			}
		}
		removeTableColumns(toRemove);
		addTableColumns(columns);
	}

	@Override
	protected Stream<ValueRow> streamRows(Trace trace, ModelQuery query, Range<Long> span) {
		return distinctCanonical(query.streamValues(trace, span)
				.filter(v -> isShowHidden() || !v.isHidden()))
						.map(this::rowForValue);
	}

	@Override
	protected TableColumnDescriptor<ValueRow> createTableColumnDescriptor() {
		TableColumnDescriptor<ValueRow> descriptor = new TableColumnDescriptor<>();
		descriptor.addVisibleColumn(new TraceValueKeyColumn());
		descriptor.addVisibleColumn(valueColumn = new TraceValueValColumn());
		descriptor.addVisibleColumn(new TraceValueLifeColumn());
		descriptor.addHiddenColumn(lifePlotColumn = new TraceValueLifePlotColumn());
		return descriptor;
	}

	@Override
	public ValueRow findTraceObject(TraceObject object) {
		for (ValueRow row : getModelData()) {
			if (row.getValue().getValue() == object && row.getValue().isCanonical()) {
				return row;
			}
		}
		return null;
	}

	@Override
	public void setDiffColor(Color diffColor) {
		valueColumn.setDiffColor(diffColor);
		for (TraceValueObjectAttributeColumn column : columnCache.values()) {
			column.setDiffColor(diffColor);
		}
	}

	@Override
	public void setDiffColorSel(Color diffColorSel) {
		valueColumn.setDiffColorSel(diffColorSel);
		for (TraceValueObjectAttributeColumn column : columnCache.values()) {
			column.setDiffColorSel(diffColorSel);
		}
	}
}
