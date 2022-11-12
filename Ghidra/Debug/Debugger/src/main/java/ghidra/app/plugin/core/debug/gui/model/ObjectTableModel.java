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

import docking.widgets.table.DynamicTableColumn;
import docking.widgets.table.RangeCursorTableHeaderRenderer.SeekListener;
import docking.widgets.table.TableColumnDescriptor;
import ghidra.app.plugin.core.debug.gui.model.ObjectTableModel.ValueRow;
import ghidra.app.plugin.core.debug.gui.model.columns.*;
import ghidra.dbg.target.schema.SchemaContext;
import ghidra.dbg.target.schema.TargetObjectSchema;
import ghidra.dbg.target.schema.TargetObjectSchema.AttributeSchema;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.Lifespan.*;
import ghidra.trace.model.Trace;
import ghidra.trace.model.target.TraceObject;
import ghidra.trace.model.target.TraceObjectValue;
import ghidra.util.HTMLUtilities;

public class ObjectTableModel extends AbstractQueryTableModel<ValueRow> {

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

	public interface ValueProperty<T> {
		public Class<T> getType();

		public ValueRow getRow();

		public T getValue();

		default public String getDisplay() {
			T value = getValue();
			return value == null ? "" : value.toString();
		}

		default public String getHtmlDisplay() {
			return "<html>" + HTMLUtilities.escapeHTML(getDisplay());
		}

		default public String getToolTip() {
			return getDisplay();
		}

		default public boolean isModified() {
			return false;
		}
	}

	public static class ValueFixedProperty<T> implements ValueProperty<T> {
		private T value;

		public ValueFixedProperty(T value) {
			this.value = value;
		}

		@Override
		public Class<T> getType() {
			throw new UnsupportedOperationException();
		}

		@Override
		public ValueRow getRow() {
			throw new UnsupportedOperationException();
		}

		@Override
		public T getValue() {
			return value;
		}
	}

	public static abstract class ValueDerivedProperty<T> implements ValueProperty<T> {
		protected final ValueRow row;
		protected final Class<T> type;

		public ValueDerivedProperty(ValueRow row, Class<T> type) {
			this.row = row;
			this.type = type;
		}

		@Override
		public ValueRow getRow() {
			return row;
		}

		@Override
		public Class<T> getType() {
			return type;
		}
	}

	public static abstract class ValueAddressProperty extends ValueDerivedProperty<Address> {
		public ValueAddressProperty(ValueRow row) {
			super(row, Address.class);
		}

		@Override
		public String getHtmlDisplay() {
			Address value = getValue();
			return value == null ? ""
					: ("<html><body style='font-family:monospaced'>" +
						HTMLUtilities.escapeHTML(value.toString()));
		}
	}

	public record ValueAttribute<T> (ValueRow row, String name, Class<T> type)
			implements ValueProperty<T> {
		public TraceObjectValue getEntry() {
			return row.getAttributeEntry(name);
		}

		@Override
		public ValueRow getRow() {
			return row;
		}

		@Override
		public Class<T> getType() {
			return type;
		}

		@Override
		public T getValue() {
			TraceObjectValue entry = row.getAttributeEntry(name);
			return entry == null || !type.isInstance(entry.getValue()) ? null
					: type.cast(entry.getValue());
		}

		@Override
		public String getDisplay() {
			return row.getAttributeDisplay(name);
		}

		@Override
		public String getHtmlDisplay() {
			return row.getAttributeHtmlDisplay(name);
		}

		@Override
		public String getToolTip() {
			return row.getAttributeToolTip(name);
		}

		@Override
		public boolean isModified() {
			return row.isAttributeModified(name);
		}
	}

	public interface ValueRow {
		String getKey();

		long currentSnap();

		long previousSnap();

		LifeSet getLife();

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

		default <T> ValueAttribute<T> getAttribute(String attributeName, Class<T> type) {
			return new ValueAttribute<>(this, attributeName, type);
		}

		TraceObjectValue getAttributeEntry(String attributeName);

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
		public long currentSnap() {
			return getSnap();
		}

		@Override
		public long previousSnap() {
			return getTrace() == getDiffTrace() ? getDiffSnap() : getSnap();
		}

		@Override
		public LifeSet getLife() {
			MutableLifeSet life = new DefaultLifeSet();
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
		public TraceObjectValue getAttributeEntry(String attributeName) {
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
		public TraceObjectValue getAttributeEntry(String attributeName) {
			return object.getAttribute(getSnap(), attributeName);
		}

		@Override
		public String getAttributeDisplay(String attributeName) {
			return display.getEdgeDisplay(getAttributeEntry(attributeName));
		}

		@Override
		public String getAttributeHtmlDisplay(String attributeName) {
			return display.getEdgeHtmlDisplay(getAttributeEntry(attributeName));
		}

		@Override
		public String getAttributeToolTip(String attributeName) {
			return display.getEdgeToolTip(getAttributeEntry(attributeName));
		}

		@Override
		public boolean isAttributeModified(String attributeName) {
			return isValueModified(getAttributeEntry(attributeName));
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
			Class<?> type =
				TraceValueObjectAttributeColumn.computeAttributeType(ctx, attributeSchema);
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

	static class AutoAttributeColumn<T> extends TraceValueObjectAttributeColumn<T> {
		public static TraceValueObjectAttributeColumn<?> fromSchema(SchemaContext ctx,
				AttributeSchema attributeSchema) {
			String name = attributeSchema.getName();
			Class<?> type = computeAttributeType(ctx, attributeSchema);
			return new AutoAttributeColumn<>(name, type);
		}

		public AutoAttributeColumn(String attributeName, Class<T> attributeType) {
			super(attributeName, attributeType);
		}
	}

	// TODO: Save and restore these between sessions, esp., their settings
	private Map<ColKey, TraceValueObjectAttributeColumn<?>> columnCache = new HashMap<>();

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
		Lifespan fullRange = Lifespan.span(0L, max == null ? 1 : max + 1);
		int count = getColumnCount();
		for (int i = 0; i < count; i++) {
			DynamicTableColumn<ValueRow, ?, ?> column = getColumn(i);
			if (column instanceof TraceValueLifePlotColumn plotCol) {
				plotCol.setFullRange(fullRange);
			}
		}
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
					.filter(a -> !ctx.getSchema(a.getSchema()).isCanonicalContainer())
					.collect(Collectors.toList());
		}
		resyncAttributeColumns(attributes);
	}

	protected Set<DynamicTableColumn<ValueRow, ?, ?>> computeAttributeColumns(
			Collection<AttributeSchema> attributes) {
		if (attributes == null) {
			return Set.of();
		}
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
					ck -> AutoAttributeColumn.fromSchema(ctx, as)))
				.collect(Collectors.toSet());
	}

	protected void resyncAttributeColumns(Collection<AttributeSchema> attributes) {
		Map<Boolean, List<AttributeSchema>> byVisible = attributes == null ? Map.of()
				: attributes.stream()
						.collect(Collectors.groupingBy(a -> !a.isHidden() || isShowHidden()));
		Set<DynamicTableColumn<ValueRow, ?, ?>> visibleColumns =
			new HashSet<>(computeAttributeColumns(byVisible.get(true)));
		Set<DynamicTableColumn<ValueRow, ?, ?>> hiddenColumns =
			new HashSet<>(computeAttributeColumns(byVisible.get(false)));
		Set<DynamicTableColumn<ValueRow, ?, ?>> toRemove = new HashSet<>();
		for (int i = 0; i < getColumnCount(); i++) {
			DynamicTableColumn<ValueRow, ?, ?> exists = getColumn(i);
			if (!(exists instanceof AutoAttributeColumn)) {
				continue;
			}
			if (!visibleColumns.remove(exists) && !hiddenColumns.remove(exists)) {
				toRemove.add(exists);
			}
		}
		removeTableColumns(toRemove);
		addTableColumns(visibleColumns, true);
		addTableColumns(hiddenColumns, false);
	}

	@Override
	protected Stream<ValueRow> streamRows(Trace trace, ModelQuery query, Lifespan span) {
		return distinctCanonical(query.streamValues(trace, span)
				.filter(v -> isShowHidden() || !v.isHidden()))
						.map(this::rowForValue);
	}

	@Override
	protected TableColumnDescriptor<ValueRow> createTableColumnDescriptor() {
		TableColumnDescriptor<ValueRow> descriptor = new TableColumnDescriptor<>();
		descriptor.addVisibleColumn(new TraceValueKeyColumn());
		descriptor.addVisibleColumn(new TraceValueValColumn());
		descriptor.addVisibleColumn(new TraceValueLifeColumn());
		descriptor.addHiddenColumn(new TraceValueLifePlotColumn());
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

	/**
	 * Find the row whose object is the canonical ancestor to the given object
	 * 
	 * @param successor the given object
	 * @return the row or null
	 */
	public ValueRow findTraceObjectAncestor(TraceObject successor) {
		for (ValueRow row : getModelData()) {
			TraceObjectValue value = row.getValue();
			if (!value.isObject()) {
				continue;
			}
			if (!value.getChild().getCanonicalPath().isAncestor(successor.getCanonicalPath())) {
				continue;
			}
			return row;
		}
		return null;
	}

	@Override
	public void setDiffColor(Color diffColor) {
		int count = getColumnCount();
		for (int i = 0; i < count; i++) {
			DynamicTableColumn<ValueRow, ?, ?> column = getColumn(i);
			if (column instanceof TraceValueObjectAttributeColumn<?> attrCol) {
				attrCol.setDiffColor(diffColor);
			}
			else if (column instanceof TraceValueValColumn valCol) {
				valCol.setDiffColor(diffColor);
			}
		}
		for (TraceValueObjectAttributeColumn<?> column : columnCache.values()) {
			column.setDiffColor(diffColor);
		}
	}

	@Override
	public void setDiffColorSel(Color diffColorSel) {
		int count = getColumnCount();
		for (int i = 0; i < count; i++) {
			DynamicTableColumn<ValueRow, ?, ?> column = getColumn(i);
			if (column instanceof TraceValueObjectAttributeColumn<?> attrCol) {
				attrCol.setDiffColorSel(diffColorSel);
			}
			else if (column instanceof TraceValueValColumn valCol) {
				valCol.setDiffColorSel(diffColorSel);
			}
		}
		for (TraceValueObjectAttributeColumn<?> column : columnCache.values()) {
			column.setDiffColorSel(diffColorSel);
		}
	}

	@Override
	protected void snapChanged() {
		super.snapChanged();
		long snap = getSnap();
		int count = getColumnCount();
		for (int i = 0; i < count; i++) {
			DynamicTableColumn<ValueRow, ?, ?> column = getColumn(i);
			if (column instanceof TraceValueLifePlotColumn plotCol) {
				plotCol.setSnap(snap);
			}
		}
	}

	@Override
	public void addSeekListener(SeekListener listener) {
		int count = getColumnCount();
		for (int i = 0; i < count; i++) {
			DynamicTableColumn<ValueRow, ?, ?> column = getColumn(i);
			if (column instanceof TraceValueLifePlotColumn plotCol) {
				plotCol.addSeekListener(listener);
			}
		}
	}

	@Override
	public boolean isCellEditable(int rowIndex, int columnIndex) {
		initializeSorting();
		List<ValueRow> modelData = getModelData();

		if (rowIndex < 0 || rowIndex >= modelData.size()) {
			return false;
		}

		ValueRow t = modelData.get(rowIndex);
		return isColumnEditableForRow(t, columnIndex);
	}

	public final boolean isColumnEditableForRow(ValueRow t, int columnIndex) {
		if (columnIndex < 0 || columnIndex >= tableColumns.size()) {
			return false;
		}

		Trace dataSource = getDataSource();

		@SuppressWarnings("unchecked")
		DynamicTableColumn<ValueRow, ?, Trace> column =
			(DynamicTableColumn<ValueRow, ?, Trace>) tableColumns.get(columnIndex);
		if (!(column instanceof EditableColumn<ValueRow, ?, Trace> editable)) {
			return false;
		}
		return editable.isEditable(t, columnSettings.get(column), dataSource, serviceProvider);
	}

	@Override
	public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
		initializeSorting();
		List<ValueRow> modelData = getModelData();

		if (rowIndex < 0 || rowIndex >= modelData.size()) {
			return;
		}

		ValueRow t = modelData.get(rowIndex);
		setColumnValueForRow(t, aValue, columnIndex);
	}

	public void setColumnValueForRow(ValueRow t, Object aValue, int columnIndex) {
		if (columnIndex < 0 || columnIndex >= tableColumns.size()) {
			return;
		}

		Trace dataSource = getDataSource();

		@SuppressWarnings("unchecked")
		DynamicTableColumn<ValueRow, ?, Trace> column =
			(DynamicTableColumn<ValueRow, ?, Trace>) tableColumns.get(columnIndex);
		if (!(column instanceof EditableColumn<ValueRow, ?, Trace> editable)) {
			return;
		}
		Settings settings = columnSettings.get(column);
		if (!editable.isEditable(t, settings, dataSource, serviceProvider)) {
			return;
		}
		doSetValue(editable, t, aValue, settings, dataSource, serviceProvider);
	}

	@SuppressWarnings("unchecked")
	private static <ROW_TYPE, COLUMN_TYPE, DATA_SOURCE> void doSetValue(
			EditableColumn<ROW_TYPE, COLUMN_TYPE, DATA_SOURCE> editable, ROW_TYPE t,
			Object aValue, Settings settings, DATA_SOURCE dataSource,
			ServiceProvider serviceProvider) {
		editable.setValue(t, (COLUMN_TYPE) aValue, settings, dataSource, serviceProvider);
	}
}
