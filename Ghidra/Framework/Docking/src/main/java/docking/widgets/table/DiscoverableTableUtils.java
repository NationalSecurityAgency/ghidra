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
package docking.widgets.table;

import java.lang.reflect.Method;
import java.util.*;

import docking.widgets.table.constraint.*;
import ghidra.util.classfinder.ClassSearcher;
import utilities.util.reflection.ReflectionUtilities;

public class DiscoverableTableUtils {
	private static List<ColumnConstraint<?>> columnConstraints;

	/**
	 * Returns a column object that is usable by the given model.
	 * <p>
	 * Dynamic columns and models work on row types.  This method allows clients to use columns
	 * with row types that differ from the model's row type, as long as a suitable mapper can
	 * be found.  If no mapper can be found, then an IllegalArgumentException is thrown.  Also,
	 * if the given column is of the correct type, then that column is returned.
	 *
	 * @param <ROW_TYPE> the <b>model's</b> row type
	 * @param <COLUMN_TYPE> the <b>model's</b> row type
	 * @param model the table model for which a column is needed
	 * @param column the column that you want to use with the given model
	 * @return a column object that is usable by the given model.
	 * @throws IllegalArgumentException if this method cannot figure out how to map the given
	 *         column's row type to the given model's row type.
	 */
	@SuppressWarnings("unchecked")
	// compile-time guarantee it is the correct type
	//@formatter:off
	public static <ROW_TYPE, COLUMN_TYPE, DATA_SOURCE>
			DynamicTableColumn<ROW_TYPE, COLUMN_TYPE, DATA_SOURCE> adaptColumForModel(
			GDynamicColumnTableModel<ROW_TYPE, COLUMN_TYPE> model,
			AbstractDynamicTableColumn<?, ?, ?> column) {
	//@formatter:on

		@SuppressWarnings("rawtypes")
		Class<? extends GDynamicColumnTableModel> implementationClass = model.getClass();
		List<Class<?>> modelTypeArguments = ReflectionUtilities.getTypeArguments(
			GDynamicColumnTableModel.class, implementationClass);
		Class<ROW_TYPE> tableRowClass = (Class<ROW_TYPE>) modelTypeArguments.get(0);

		List<Class<?>> columnTypeArguments = ReflectionUtilities.getTypeArguments(
			AbstractDynamicTableColumn.class, column.getClass());
		Class<?> columnRowClass = columnTypeArguments.get(0);

		if (tableRowClass == columnRowClass) {
			// the ROW_TYPE value is the same for the model and the column, so the given instance is
			// the right type
			return (DynamicTableColumn<ROW_TYPE, COLUMN_TYPE, DATA_SOURCE>) column;
		}

		Collection<DynamicTableColumn<ROW_TYPE, COLUMN_TYPE, DATA_SOURCE>> columns =
			getTableColumnForTypes(tableRowClass, column);
		if (columns.isEmpty()) {
			throw new IllegalArgumentException(
				"Do not know how to map column to model for types: " + columnRowClass + " and " +
					tableRowClass);
		}

		// not sure what to do when we have many results; just return one
		return columns.iterator().next();
	}

	/**
	 * Returns all "discovered" {@link AbstractDynamicTableColumn} classes that are compatible with the
	 * given class, which represents the object for a table's row.  For example, many tables use
	 * <code>Address</code> as the row type.  In this case, passing <code>Address.class</code> as the
	 * parameter to this method will return all {@link AbstractDynamicTableColumn}s that can provide column
	 * data by working with <code>Address</code> instances.
	 * 
	 * <p><u>Usage Notes:</u>  This class will not only discover {@link AbstractDynamicTableColumn}s
	 * that directly support the given class type, but will also use discovered
	 * {@link TableRowMapper} objects to create adapters that allow the
	 * use of table row data that does not exactly match the supported type of discovered
	 * {@link AbstractDynamicTableColumn} classes.  For example, suppose that a table's row type is
	 * <code>Address</code>.  This methods will return at least all {@link AbstractDynamicTableColumn}s
	 * that support <code>Address</code> data.  In order to support extra columns, Ghidra has
	 * created a {@link TableRowMapper} that can convert a <code>ProgramLocation</code> into an
	 * <code>Address</code>.  This method will find and use this mapper to return a
	 * {@link MappedTableColumn} instance (which is an {@link AbstractDynamicTableColumn}).  By doing
	 * this, any table that has <code>Address</code> objects as its row type can now use
	 * {@link AbstractDynamicTableColumn}s that support <code>ProgramLocations</code> in addition to
	 * <code>Address</code> objects.  These mappers provide a way for tables that have non-standard
	 * Ghidra data as their row type to take advantage of existing dynamic columns for standard
	 * Ghidra data (like ProgramLocations and Addresses).
	 * 
	 * @param rowTypeClass table's row type 
	 * @return the discovered column
	 */
	public static <ROW_TYPE> Collection<DynamicTableColumn<ROW_TYPE, ?, ?>> getDynamicTableColumns(
			Class<ROW_TYPE> rowTypeClass) {

		Collection<DynamicTableColumn<?, ?, ?>> columnExtensions = getTableColumExtensions();
		Set<DynamicTableColumn<ROW_TYPE, ?, ?>> dataSet = new HashSet<>();
		for (DynamicTableColumn<?, ?, ?> column : columnExtensions) {
			Collection<DynamicTableColumn<ROW_TYPE, Object, Object>> mappedColumns =
				getTableColumnForTypes(rowTypeClass, column);
			dataSet.addAll(mappedColumns);
		}

		return dataSet;
	}

	private static Collection<DynamicTableColumn<?, ?, ?>> getTableColumExtensions() {
		List<DynamicTableColumn<?, ?, ?>> list = new ArrayList<>();

		for (DynamicTableColumn<?, ?, ?> dynamicTableColumn : ClassSearcher.getInstances(
			DynamicTableColumn.class)) {
			list.add(dynamicTableColumn);
		}
		return list;
	}

	/**
	 * If the given <code>DynamicTableColumn</code> is a match for the given <code>rowTypeClass</code>, then
	 * it will be added to the given list.
	 * <p>
	 * <u>Implementation Notes:</u>
	 * This method does some odd things with Java Generics.  Specifically, it declares three
	 * generic types, but only relies on the caller of the method to provide one of those types.
	 * Further, in some cases the method uses the Generic wildcard '?' feature.  In one case it
	 * does not use this feature, since we need to create a new object, and the
	 * compiler requires that we have a type and not a wildcard to do this.  In this usage, we are
	 * just guaranteeing that the created type matches our needs, even though we don't know what
	 * that type actually is.
	 *
	 * @param <COLUMN_ROW_TYPE> A placeholder type for discovered column row types
	 *                          that may differ from the given TABLE_ROW_TYPE.
	 * @param <TABLE_ROW_TYPE>  The class of the table's row data
	 * @param <COLUMN_TYPE>     The type of object that the column generates from the call to
	 *                          column's <tt>getValue()</t> method.
	 * @param rowTypeClass      The class of the table's row data (with the same type as
	 * 						    COLUMN_ROW_TYPE)
	 * @param tableColumn       The column to add to the given collection if it supports the
	 *                          given <code>rowTypeClass</code>.
	 */
	@SuppressWarnings("unchecked")
	// Each cast is checked below (see notes)
	//@formatter:off
	private static <COLUMN_ROW_TYPE, TABLE_ROW_TYPE, COLUMN_TYPE, DATA_SOURCE>
		Collection<DynamicTableColumn<TABLE_ROW_TYPE, COLUMN_TYPE, DATA_SOURCE>> getTableColumnForTypes(
			Class<TABLE_ROW_TYPE> rowTypeClass, DynamicTableColumn<?, ?, ?> tableColumn) {

	//@formatter:on

		Set<DynamicTableColumn<TABLE_ROW_TYPE, COLUMN_TYPE, DATA_SOURCE>> set = new HashSet<>();

		// first, check for a direct match
		Class<?> supportedRowType = tableColumn.getSupportedRowType();
		if (supportedRowType == rowTypeClass) {
			// Safe cast:
			// We know that TABLE_ROW_TYPE is correct, since we just checked the classes for '=='
			set.add((DynamicTableColumn<TABLE_ROW_TYPE, COLUMN_TYPE, DATA_SOURCE>) tableColumn);
			return set;
		}

		// next, check to see if we can find a mapper to convert the actual ROW_TYPE
		// to the COLUMN_ROW_TYPE
		Collection<TableRowMapper<TABLE_ROW_TYPE, COLUMN_ROW_TYPE, DATA_SOURCE>> mappers =
			getTableRowObjectMapper(rowTypeClass, supportedRowType);
		if (mappers.isEmpty()) {
			return Collections.emptySet();
		}

		// Safe cast:
		// 1) We already know that COLUMN_ROW_TYPE is the same as 'supportedRowType',
		//    since the mapper is not null and that is one of the criteria for finding
		//    a mapper
		// 2) We don't know what COLUMN_ROW_TYPE actually is, but we don't care, as it is
		//    just a placeholder
		DynamicTableColumn<COLUMN_ROW_TYPE, COLUMN_TYPE, DATA_SOURCE> castColumn =
			(DynamicTableColumn<COLUMN_ROW_TYPE, COLUMN_TYPE, DATA_SOURCE>) tableColumn;
		return createMappedTableColumn(mappers, castColumn);
	}

	/**
	 * Returns a {@link TableRowMapper} for the given class types if one is found.  The
	 * returned mapper will know how to translate instances of <code>fromType</code> to
	 * <code>toType</code>.
	 *
	 * @param <ROW_TYPE> The type of row that is defined by the table
	 * @param <EXPECTED_TYPE> The type of row object that is desired
	 * @param fromType The <code>Class</code> object of the given row type
	 * @param toType The <code>Class</code> object of the desired row type
	 * @return a new TableRowMapper
	 */
	@SuppressWarnings({ "unchecked" }) 	// we verified before casting
	private static <ROW_TYPE, EXPECTED_TYPE, DATA_SOURCE> Collection<TableRowMapper<ROW_TYPE, EXPECTED_TYPE, DATA_SOURCE>> getTableRowObjectMapper(
			Class<ROW_TYPE> fromType, Class<?> toType) {

		Set<TableRowMapper<ROW_TYPE, EXPECTED_TYPE, DATA_SOURCE>> set = new HashSet<>();

		@SuppressWarnings("rawtypes")
		List<TableRowMapper> instances = ClassSearcher.getInstances(TableRowMapper.class);
		for (TableRowMapper<ROW_TYPE, EXPECTED_TYPE, DATA_SOURCE> mapper : instances) {
			if (mapper.getSourceType() == fromType && mapper.getDestinationType() == toType) {
				set.add(mapper);
			}
		}

		return set;
	}

	private static <ROW_TYPE, EXPECTED_TYPE, COLUMN_TYPE, DATA_SOURCE> Collection<DynamicTableColumn<ROW_TYPE, COLUMN_TYPE, DATA_SOURCE>> createMappedTableColumn(
			Collection<TableRowMapper<ROW_TYPE, EXPECTED_TYPE, DATA_SOURCE>> mappers,
			DynamicTableColumn<EXPECTED_TYPE, COLUMN_TYPE, DATA_SOURCE> wrappedColumn) {

		Set<DynamicTableColumn<ROW_TYPE, COLUMN_TYPE, DATA_SOURCE>> set = new HashSet<>();

		for (TableRowMapper<ROW_TYPE, EXPECTED_TYPE, DATA_SOURCE> mapper : mappers) {
			set.add(mapper.createMappedTableColumn(wrappedColumn));
		}

		return set;
	}

	/**
	 * Returns a list of all the {@link ColumnConstraint} that are capable of filtering the
	 * destination type of the given mapper.  The mapper will be used to create a mapped constraint
	 * that will be called with an instance of the type <code>T</code>.
	 * 
	 * @param mapper the mapper that will be used to convert
	 * @return a list of all the {@link ColumnConstraint} that are capable of filtering the
	 * 		   given column type
	 */
	public static <T, M> Collection<ColumnConstraint<T>> getColumnConstraints(
			ColumnTypeMapper<T, M> mapper) {

		Class<M> destinationType = mapper.getDestinationType();
		Collection<ColumnConstraint<M>> unmapped = getColumnConstraints(destinationType);
		Collection<ColumnConstraint<T>> mapped = mapConstraints(mapper, unmapped);
		return mapped;
	}

	/**
	 * Returns a list of all the {@link ColumnConstraint} that are capable of filtering the
	 * given column type.
	 *
	 * @param columnType the class of the data that is return by the table model for specific column.
	 * @return  a list of all the {@link ColumnConstraint} that are capable of filtering the
	 * given column type.
	 */
	// safe because we are creating an EnumColumnConstraint using the type that was just checked to be an enum
	@SuppressWarnings({ "rawtypes", "unchecked" })
	public static <T> Collection<ColumnConstraint<T>> getColumnConstraints(Class<T> columnType) {
		List<ColumnConstraint<T>> list = new ArrayList<>();

		if (columnType.isEnum()) {
			list.add(new EnumColumnConstraint(columnType, Collections.emptySet()));
			return list;
		}

		initializeColumnConstraints();

		for (ColumnConstraint<?> constraint : columnConstraints) {
			if (constraint.getColumnType().isAssignableFrom(columnType)) {
				list.add((ColumnConstraint<T>) constraint);
			}
		}

		if (list.isEmpty() && hasGoodStringConversion(columnType)) {
			list.addAll(wrapToStringConstraints(columnType, getColumnConstraints(String.class)));
		}

		Collections.sort(list);
		return list;
	}

	private static void initializeColumnConstraints() {

		if (columnConstraints != null) {
			return;
		}

		List<ColumnConstraint<?>> foundConstraints = findColumnConstraints();
		List<ColumnConstraint<?>> mappedConstraints = new ArrayList<>();

		@SuppressWarnings("rawtypes")
		List<ColumnTypeMapper> mappers = ClassSearcher.getInstances(ColumnTypeMapper.class);

		for (ColumnTypeMapper<?, ?> mapper : mappers) {
			mappedConstraints.addAll(generateMappedConstraints(mapper, foundConstraints));
		}
		foundConstraints.addAll(mappedConstraints);
		columnConstraints = foundConstraints;
	}

	private static <T, M> Collection<ColumnConstraint<?>> generateMappedConstraints(
			ColumnTypeMapper<T, M> mapper, List<ColumnConstraint<?>> foundConstraints) {
		List<ColumnConstraint<?>> mappedConstraints = new ArrayList<>();

		Class<M> destinationType = mapper.getDestinationType();
		List<ColumnConstraint<M>> list = getMatchingConstraints(foundConstraints, destinationType);
		for (ColumnConstraint<M> columnConstraint : list) {
			MappedColumnConstraint<T, M> mappedConstraint =
				new MappedColumnConstraint<>(mapper, columnConstraint);
			mappedConstraints.add(mappedConstraint);
		}
		return mappedConstraints;
	}

	private static <T, M> Collection<ColumnConstraint<T>> mapConstraints(
			ColumnTypeMapper<T, M> mapper, Collection<ColumnConstraint<M>> constraints) {

		List<ColumnConstraint<T>> mappedConstraints = new ArrayList<>();
		for (ColumnConstraint<M> columnConstraint : constraints) {
			MappedColumnConstraint<T, M> mappedConstraint =
				new MappedColumnConstraint<>(mapper, columnConstraint);
			mappedConstraints.add(mappedConstraint);
		}
		return mappedConstraints;
	}

	@SuppressWarnings("unchecked") // if the type matches, it is safe to cast
	private static <T> List<ColumnConstraint<T>> getMatchingConstraints(
			List<ColumnConstraint<?>> constraints, Class<T> destinationType) {

		List<ColumnConstraint<T>> list = new ArrayList<>();
		for (ColumnConstraint<?> columnConstraint : constraints) {
			if (columnConstraint.getColumnType().equals(destinationType)) {
				list.add((ColumnConstraint<T>) columnConstraint);
			}
		}
		return list;
	}

	private static boolean hasGoodStringConversion(Class<?> columnType) {
		if (DisplayStringProvider.class.isAssignableFrom(columnType)) {
			return true;
		}
		try {
			Method method = columnType.getMethod("toString");
			// if toString is not overridden then don't bother
			if (method.getDeclaringClass().equals(Object.class)) {
				return false;
			}
		}
		catch (NoSuchMethodException | SecurityException e) {
			return false;
		}
		return true;
	}

	private static <T> List<ColumnConstraint<T>> wrapToStringConstraints(Class<T> type,
			Collection<ColumnConstraint<String>> stringConstraints) {

		List<ColumnConstraint<T>> list = new ArrayList<>();
		for (ColumnConstraint<String> constraint : stringConstraints) {
			list.add(new MappedColumnConstraint<>(new ObjectToStringMapper<>(type), constraint));
		}
		return list;
	}

	private static List<ColumnConstraint<?>> findColumnConstraints() {
		List<ColumnConstraint<?>> constraints = new ArrayList<>();

		List<ColumnConstraintProvider> constraintProviders =
			ClassSearcher.getInstances(ColumnConstraintProvider.class);

		for (ColumnConstraintProvider provider : constraintProviders) {
			constraints.addAll(provider.getColumnConstraints());
		}

		return constraints;
	}

}
