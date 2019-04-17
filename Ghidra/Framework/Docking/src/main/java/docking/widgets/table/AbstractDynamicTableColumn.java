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

import java.util.*;

import ghidra.docking.settings.*;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.util.NumericUtilities;
import ghidra.util.table.column.GColumnRenderer;
import utilities.util.reflection.ReflectionUtilities;

/**
 * An Table Column is an interface that should be implemented by each class that provides
 * a field (column) of an object based table (each row relates to a particular type of object).
 * It determines the appropriate cell object for use by the table column this field represents.
 * It can then return the appropriate object to display in the table cell for the indicated
 * row object.
 *
 * Implementations of this interface must provide a public default constructor.
 * 
 * @param <ROW_TYPE> The row object class supported by this column
 * @param <COLUMN_TYPE> The column object class supported by this column
 * @param <DATA_SOURCE> The object class type that will be passed to 
 * 						see <code>getValue(ROW_TYPE, Settings, DATA_SOURCE, ServiceProvider)</code>
 */
public abstract class AbstractDynamicTableColumn<ROW_TYPE, COLUMN_TYPE, DATA_SOURCE>
		implements DynamicTableColumn<ROW_TYPE, COLUMN_TYPE, DATA_SOURCE> {

	public static SettingsDefinition[] NO_SETTINGS_DEFINITIONS = new SettingsDefinition[0];

	protected static final FormatSettingsDefinition INTEGER_RADIX_SETTING =
		FormatSettingsDefinition.DEF_DECIMAL;

	protected static final IntegerSignednessFormattingModeSettingsDefinition INTEGER_SIGNEDNESS_MODE_SETTING =
		IntegerSignednessFormattingModeSettingsDefinition.DEF;

	protected static final FloatingPointPrecisionSettingsDefinition FLOATING_POINT_PRECISION_SETTING =
		FloatingPointPrecisionSettingsDefinition.DEF;

	protected static SettingsDefinition[] INTEGER_SETTINGS_DEFINITIONS =
		new SettingsDefinition[] { INTEGER_RADIX_SETTING, INTEGER_SIGNEDNESS_MODE_SETTING };

	protected static SettingsDefinition[] FLOATING_POINT_SETTINGS_DEFINITIONS =
		new SettingsDefinition[] { FLOATING_POINT_PRECISION_SETTING };

	private boolean hasConfiguredDefaultSettings = false;
	private SettingsDefinition[] defaultSettingsDefinitions = NO_SETTINGS_DEFINITIONS;

	// lazy-loaded; do not access directly
	private String identifier;

	public AbstractDynamicTableColumn() {
		// default constructor
	}

	/* Only for special purposes (if you're not sure if you're special, then you aren't) */
	protected AbstractDynamicTableColumn(String identifier) {
		this.identifier = Objects.requireNonNull(identifier);
	}

	@Override
	public abstract String getColumnName();

	@Override
	public int getColumnPreferredWidth() {
		return -1;
	}

	@Override
	public Comparator<COLUMN_TYPE> getComparator() {
		return null;
	}

	@Override
	@SuppressWarnings("unchecked")
	// enforced by the compiler
	public Class<COLUMN_TYPE> getColumnClass() {
		@SuppressWarnings("rawtypes")
		Class<? extends AbstractDynamicTableColumn> implementationClass = getClass();
		List<Class<?>> typeArguments = ReflectionUtilities.getTypeArguments(
			AbstractDynamicTableColumn.class, implementationClass);
		return (Class<COLUMN_TYPE>) typeArguments.get(1);
	}

	@Override
	@SuppressWarnings("unchecked")
	// enforced by the compiler
	public Class<ROW_TYPE> getSupportedRowType() {
		@SuppressWarnings("rawtypes")
		Class<? extends AbstractDynamicTableColumn> implementationClass = getClass();
		List<Class<?>> typeArguments = ReflectionUtilities.getTypeArguments(
			AbstractDynamicTableColumn.class, implementationClass);
		return (Class<ROW_TYPE>) typeArguments.get(0);
	}

	@Override
	public abstract COLUMN_TYPE getValue(ROW_TYPE rowObject, Settings settings, DATA_SOURCE data,
			ServiceProvider serviceProvider) throws IllegalArgumentException;

	@Override
	public GColumnRenderer<COLUMN_TYPE> getColumnRenderer() {
		return null;
	}

	private void configureDefaultSettings() {
		defaultSettingsDefinitions = NO_SETTINGS_DEFINITIONS;
		Class<COLUMN_TYPE> columnClass = getColumnClass();
		if (NumericUtilities.isIntegerType(columnClass)) {
			defaultSettingsDefinitions = INTEGER_SETTINGS_DEFINITIONS;
		}
		else if (NumericUtilities.isFloatingPointType(columnClass)) {
			defaultSettingsDefinitions = FLOATING_POINT_SETTINGS_DEFINITIONS;
		}
		hasConfiguredDefaultSettings = true;
	}

	@Override
	public SettingsDefinition[] getSettingsDefinitions() {
		if (!hasConfiguredDefaultSettings) {
			configureDefaultSettings();
		}
		return defaultSettingsDefinitions;
	}

	/* (non-Javadoc)
	 * @see ghidra.util.table.field.DynamicTableColumn#getMaxLines(ghidra.util.settings.Settings)
	 */
	@Override
	public int getMaxLines(Settings settings) {
		return 1;
	}

	@Override
	public String getColumnDisplayName(Settings settings) {
		return getColumnName();
	}

	@Override
	public String getColumnDescription() {
		Class<ROW_TYPE> type = getSupportedRowType();
		if (type == null) {
			// this can happen for dynamically created columns
			return null;
		}
		String rowClassName = type.getSimpleName();
		return getColumnName() + " (for row type: " + rowClassName + ")";
	}

	@Override
	public final boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}

		if (obj == null) {
			return false;
		}

		if (!(obj instanceof AbstractDynamicTableColumn)) {
			return false;
		}

		@SuppressWarnings("rawtypes")
		AbstractDynamicTableColumn dynamicTableColumn = (AbstractDynamicTableColumn) obj;
		return getUniqueIdentifier().equals(dynamicTableColumn.getUniqueIdentifier());
	}

	@Override
	public final int hashCode() {
		return getIdentifier().hashCode();
	}

	// Note: this method is here because the default 'identifier' must be lazy loaded, as 
	//       at construction time not all the variables needed are available.
	private String getIdentifier() {
		/*
			We need this method to return a value that is unique for every column.  We have a
		 	few issues that we need to work around:
		 		-The case where 2 different column classes share the same column header value
		 		-The case where a single column class is used repeatedly, with a different
		 		 column header value each time
		
		 	Thus, to be unique, we need to combine both the class name and the column header
		 	value.  The only time this may be an issue is if the column header value changes
		 	dynamically--not sure if this actually happens anywhere in our system.  If it did,
		 	then the saved settings would not get reloaded correctly.
		 */

		if (identifier == null) {
			// the combination of the class name and the column name should be unique
			identifier = getClass().getName() + '.' + getColumnName();
		}
		return identifier;
	}

	@Override
	public final String getUniqueIdentifier() {
		// Note: this method is final, as changing it can break how table settings are saved
		//       and reloaded
		return getIdentifier();
	}

	@Override
	public String toString() {
		return getColumnName();
	}
}
