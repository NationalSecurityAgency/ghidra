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
package docking.widgets.table.constraint.dialog;

import java.util.*;

import org.apache.commons.collections4.CollectionUtils;

import docking.widgets.table.*;
import docking.widgets.table.constraint.ColumnConstraint;
import docking.widgets.table.constraint.ColumnTypeMapper;
import ghidra.docking.settings.Settings;
import ghidra.util.table.column.GColumnRenderer;
import ghidra.util.table.column.GColumnRenderer.ColumnConstraintFilterMode;

/**
 * This class provides all known {@link ColumnConstraint}s for a given table column.
 * 
 * <P>Class for maintaining information about a particular table's column for the purpose of 
 * configuring filters based on that column's values.  Instances of this class are generated 
 * by examining a table's column types and finding any {@link ColumnConstraint}s that support 
 * that type. If column constraints are found, a {@link ColumnFilterData} is created for that column 
 * which then allows filtering on that columns data via the column constraints mechanism (which
 * is different than the traditional text filter).
 *
 * @param <T> the column type.
 */
public class ColumnFilterData<T> implements Comparable<ColumnFilterData<T>> {

	private final String name;
	private final int modelIndex; // the index of the table model, not the table column model vie w
	private final List<ColumnConstraint<T>> applicableConstraints;
	private int viewIndex;  // the current view index of the column, can change if user moves,add, or deletes a column

	/**
	 * Constructs a new ColumnFilterData for a table column
	 *
	 * @param model the table model
	 * @param columnModelIndex the model index of the column 
	 * @param columnViewIndex the view index of the column
	 * @param columnClass the class (type) of the column
	 */
	public ColumnFilterData(RowObjectFilterModel<?> model, int columnModelIndex,
			int columnViewIndex, Class<T> columnClass) {
		this.modelIndex = columnModelIndex;
		this.viewIndex = columnViewIndex;
		this.name = model.getColumnName(columnModelIndex);

		this.applicableConstraints = initializeConstraints(model, columnClass);
	}

	private List<ColumnConstraint<T>> initializeConstraints(RowObjectFilterModel<?> model,
			Class<T> columnClass) {

		// 
		// Case 1: the column is not dynamic and thus has no way of overriding the column 
		//         constraint filtering mechanism.
		// 
		Collection<ColumnConstraint<T>> defaultConstraints =
			DiscoverableTableUtils.getColumnConstraints(columnClass);
		if (!(model instanceof DynamicColumnTableModel)) {
			return new ArrayList<>(defaultConstraints);
		}

		//
		// Case 2: the column is dynamic, but does not supply a specialized column renderer, 
		//         which is the means for overriding the column constraint filtering mechanism.
		//
		DynamicColumnTableModel<?> columnBasedModel = (DynamicColumnTableModel<?>) model;
		DynamicTableColumn<?, ?, ?> column = columnBasedModel.getColumn(modelIndex);
		GColumnRenderer<?> columnRenderer = column.getColumnRenderer();
		if (columnRenderer == null) {
			return new ArrayList<>(defaultConstraints);
		}

		//
		// Case 3: the column renderer has signaled that it uses only column constraint filtering
		//         and does not support the traditional text based filtering.
		//
		ColumnConstraintFilterMode mode = columnRenderer.getColumnConstraintFilterMode();
		if (mode == ColumnConstraintFilterMode.ALLOW_CONSTRAINTS_FILTER_ONLY) {
			return new ArrayList<>(defaultConstraints);
		}

		//
		// Case 4: the column supports text filtering.   Find any column constraints for the 
		//         column's type.  Then, create string-based constraints that will filter on
		//         the column's conversion from its type to a string (via 
		//         GColumnRenderer.getFilterString()).
		//
		@SuppressWarnings("unchecked") // See type note on the class below
		GColumnRenderer<T> asT = (GColumnRenderer<T>) columnRenderer;
		ColumnRendererMapper mapper = new ColumnRendererMapper(asT, columnBasedModel, modelIndex);
		Collection<ColumnConstraint<T>> rendererStringConstraints =
			DiscoverableTableUtils.getColumnConstraints(mapper);
		if (mode == ColumnConstraintFilterMode.ALLOW_RENDERER_STRING_FILTER_ONLY) {
			return new ArrayList<>(rendererStringConstraints);
		}

		// 
		// Case 5: the renderer supports both text filtering and column constraint filtering.
		//
		// assume: mode == ColumnConstraintFilterMode.ALLOW_ALL_FILTERS
		List<ColumnConstraint<T>> results = new ArrayList<>(rendererStringConstraints);
		results.addAll(defaultConstraints);
		return results;
	}

	/**
	 * Sets the viewIndex
	 *
	 * <P>This needs to be updated whenever columns are added, deleted, or moved.
	 * 
	 * @param viewIndex the new view index
	 */
	public void setViewIndex(int viewIndex) {
		this.viewIndex = viewIndex;
	}

	/**
	 * Returns the view index of the column
	 *
	 * @return the view index of the column.
	 */
	public int getViewIndex() {
		return viewIndex;
	}

	/**
	 * Returns true if the column represented by this data has applicable column filters.
	 *
	 * @return  true if the column represented by this data has applicable column filters.
	 */
	public boolean isFilterable() {
		return !applicableConstraints.isEmpty();
	}

	/**
	 * Returns the list of applicable constraints for this column
	 *
	 * @return the list of applicable constraints for this column
	 */
	public ColumnConstraint<?>[] getConstraints() {
		return applicableConstraints.stream().toArray(ColumnConstraint[]::new);
	}

	/**
	 * Returns the name of the column represented by this ColumnFilterData
	 *
	 * @return the name of the column represented by this ColumnFilterData
	 */
	public String getName() {
		return name;
	}

	@Override
	public String toString() {
		//@formatter:off
		return "{\n" +
			"\tname: " + name + ",\n" +
			"\tmodelColumn: " + modelIndex + ",\n" +
			"\tviewColumn: " + viewIndex + ",\n" +
			"\tconstraints: " + 
				CollectionUtils.collect(applicableConstraints, c -> c.asString()) +"\n" +
		"}";
		//@formatter:on
	}

	/**
	 * Returns the ColumnConstraint with the given name
	 *
	 * @param constraintName the name of the constraint to retrieve
	 * @return the ColumnConstraint with the given name.
	 */
	public ColumnConstraint<T> getConstraint(String constraintName) {
		for (ColumnConstraint<T> columnConstraint : applicableConstraints) {
			if (columnConstraint.getName().equals(constraintName)) {
				return columnConstraint;
			}
		}
		return null;
	}

	/**
	 * Returns the model index for the column represented by this class.
	 *
	 * @return  the model index for the column represented by this class.
	 */
	public int getColumnModelIndex() {
		return modelIndex;
	}

	/**
	 * Returns the first constraint in the list.
	 *
	 * @return the constraint
	 */
	public ColumnConstraint<T> getFirstConstraint() {
		return applicableConstraints.get(0);
	}

	// sort in the order the user sees the columns
	@Override
	public int compareTo(ColumnFilterData<T> o) {
		return viewIndex - o.viewIndex;
	}

	/**
	 * Replace the same named constraint with the given constraint.  This allows the
	 * column constraint to remember the last used value.
	 * @param value the constraint to be used to replace the existing one with the same name.
	 */
	public void replace(ColumnConstraint<T> value) {
		applicableConstraints.replaceAll(v -> {
			if (v.getName().equals(value.getName())) {
				return value;
			}
			return v;
		});

	}

	/**
	 * This class allows us to turn client columns of type <code>T</code> to a String.  We use 
	 * the renderer provided at construction time to generate a filter string when 
	 * {@link #convert(Object)} is called.
	 * 
	 * <P>Implementation Note:  the type 'T' here is used to satisfy the external client's 
	 *    expected list of constraints.  We will not be able to identify 'T' at runtime.  Rather,
	 *    our parent's {@link #getSourceType()} will simply be {@link Object}.   This is fine, as
	 *    this particular class will not have {@link #getSourceType()} called, due to how we 
	 *    are using it.  (Normally, the source type is used to find compatible constraints; we
	 *    are not using the discovery mechanism with this private class.)
	 */
	private class ColumnRendererMapper extends ColumnTypeMapper<T, String> {

		private GColumnRenderer<T> renderer;
		private DynamicColumnTableModel<?> model;
		private int columnModelIndex;

		ColumnRendererMapper(GColumnRenderer<T> renderer, DynamicColumnTableModel<?> model,
				int columnModelIndex) {
			this.renderer = renderer;
			this.model = model;
			this.columnModelIndex = columnModelIndex;
		}

		@Override
		public String convert(T value) {
			if (value == null) {
				return null;
			}
			Settings settings = model.getColumnSettings(columnModelIndex);
			String s = renderer.getFilterString(value, settings);
			return s;
		}
	}

}
