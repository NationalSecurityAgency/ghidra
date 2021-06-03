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
package docking.widgets.table.constraint;

import docking.widgets.table.constrainteditor.ColumnConstraintEditor;
import docking.widgets.table.constrainteditor.MappedColumnConstraintEditor;
import ghidra.util.SystemUtilities;

/**
 * Class that maps one type of column constraint into another.  Typically, these are created
 * automatically based on {@link ColumnTypeMapper} that are discovered by the system.  For example,
 * {@literal if you have a column type of "Foo", and you create a ColumnTypeMapper<Foo, String>, 
 * then all the} string constraints would now be available that column.
 *
 * @param <T> The column type
 * @param <M> the converted (mapped) type
 */
public class MappedColumnConstraint<T, M> implements ColumnConstraint<T> {

	private ColumnTypeMapper<T, M> mapper;
	private ColumnConstraint<M> delegate;

	/**
	 * Constructs a new Mapped ColumnConstraint
	 * @param mapper a mapper from from the column type to a mapped type.
	 * @param delegate the column constraint of the mapped type.
	 */
	public MappedColumnConstraint(ColumnTypeMapper<T, M> mapper, ColumnConstraint<M> delegate) {
		this.mapper = mapper;
		this.delegate = delegate;
	}

	@Override
	public boolean accepts(T value, TableFilterContext context) {
		M mappedValue = mapper.convert(value);
		return delegate.accepts(mappedValue, context);
	}

	@Override
	public String getName() {
		return delegate.getName();
	}

	@Override
	public Class<T> getColumnType() {
		return mapper.getSourceType();
	}

	@Override
	public ColumnConstraintEditor<T> getEditor(ColumnData<T> columnDataSource) {
		ColumnData<M> delegateSource = new DelegateColumnData(columnDataSource);
		ColumnConstraintEditor<M> delegateEditor = delegate.getEditor(delegateSource);
		return new MappedColumnConstraintEditor<>(this, delegateEditor);
	}

	@Override
	public String getGroup() {
		return delegate.getGroup();
	}

	@Override
	public String getConstraintValueString() {
		return delegate.getConstraintValueString();
	}

	@Override
	public ColumnConstraint<T> parseConstraintValue(String valueString, Object dataSource) {
		ColumnConstraint<M> newConstraint = delegate.parseConstraintValue(valueString, dataSource);
		return copy(newConstraint);
	}

	/**
	 * Creates a copy of this class using the same mapper but with a different mapped delegate.
	 * @param newDelegate the new M type delegate column constraint.
	 * @return  a copy of this class using the same mapper but with a different mapped delegate.
	 */
	public ColumnConstraint<T> copy(ColumnConstraint<M> newDelegate) {
		return new MappedColumnConstraint<>(mapper, newDelegate);

	}

	/**
	 * Returns the delegate constraint (current value for this mapped constraint)
	 * @return the delegate constraint.
	 */
	public ColumnConstraint<M> getDelegate() {
		return delegate;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((delegate == null) ? 0 : delegate.hashCode());
		result = prime * result + ((mapper == null) ? 0 : mapper.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		@SuppressWarnings("rawtypes")
		MappedColumnConstraint other = (MappedColumnConstraint) obj;
		if (!SystemUtilities.isEqual(delegate, other.delegate)) {
			return false;
		}
		return mapper.equals(other.mapper);
	}

	/**
	 * {@literal Class for converting a ColumnDataSource<T> to a ColumnDataSource<W> to be used when}
	 * getting the editor for the delegate{@literal ColumnConstraint<W>.}
	 */
	protected class DelegateColumnData implements ColumnData<M> {

		private ColumnData<T> columnDataSource;

		/**
		 * Constructor
		 * @param columnDataSource the{@literal ColumnDataSource<T>} whose T data will be converted to
		 * W data for the delegate editor.
		 */
		public DelegateColumnData(ColumnData<T> columnDataSource) {
			this.columnDataSource = columnDataSource;
		}

		@Override
		public String getColumnName() {
			return columnDataSource.getColumnName();
		}

		@Override
		public int getCount() {
			return columnDataSource.getCount();
		}

		@Override
		public M getColumnValue(int row) {
			return mapper.convert(columnDataSource.getColumnValue(row));
		}

		@Override
		public Object getTableDataSource() {
			return columnDataSource.getTableDataSource();
		}
	}

}
