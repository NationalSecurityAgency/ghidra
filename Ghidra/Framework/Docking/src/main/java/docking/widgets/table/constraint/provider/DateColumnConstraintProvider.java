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
package docking.widgets.table.constraint.provider;

import java.time.LocalDate;
import java.time.ZoneId;
import java.util.*;

import docking.widgets.table.constraint.*;
import docking.widgets.table.constrainteditor.*;

/**
 * Provides Date related column constraints.
 */
public class DateColumnConstraintProvider implements ColumnConstraintProvider {

	/**
	 * Date object representing an invalid date.
	 */

	// Akin to Address.NO_ADDRESS
	public static final LocalDate DEFAULT_DATE =
		new Date(Long.MAX_VALUE).toInstant().atZone(ZoneId.systemDefault()).toLocalDate();

	@Override
	public Collection<ColumnConstraint<?>> getColumnConstraints() {
		List<ColumnConstraint<?>> list = new ArrayList<>();

		// @formatter:off
		list.add(new AtLeastDateColumnConstraint(DEFAULT_DATE, new LocalDateEditorProvider()));
		list.add(new AtMostDateColumnConstraint(DEFAULT_DATE, new LocalDateEditorProvider()));
		list.add(new InDateRangeColumnConstraint(DEFAULT_DATE, DEFAULT_DATE, new LocalDateRangeEditorProvider()));
		list.add(new NotInDateRangeColumnConstraint(DEFAULT_DATE, DEFAULT_DATE, new LocalDateRangeEditorProvider()));

		// @formatter:on

		return list;
	}

	/**
	 * class for providing a date editor
	 */
	static class LocalDateEditorProvider implements EditorProvider<LocalDate> {
		@Override
		public ColumnConstraintEditor<LocalDate> getEditor(
				ColumnConstraint<LocalDate> columnConstraint,
				ColumnData<LocalDate> columnDataSource) {
			return new DateValueConstraintEditor(columnConstraint);
		}

		@Override
		public LocalDate parseValue(String value, Object dataSource) {
			return LocalDate.parse(value, DateValueConstraintEditor.LOCAL_DATE_FORMAT);
		}

		@Override
		public String toString(LocalDate value) {
			return value.format(DateValueConstraintEditor.LOCAL_DATE_FORMAT);
		}

	}

	/**
	 * class for providing a date range editor.
	 */
	static class LocalDateRangeEditorProvider extends LocalDateEditorProvider {
		@Override
		public ColumnConstraintEditor<LocalDate> getEditor(
				ColumnConstraint<LocalDate> columnConstraint,
				ColumnData<LocalDate> columnDataSource) {
			return new DateRangeConstraintEditor(columnConstraint);
		}
	}
}
