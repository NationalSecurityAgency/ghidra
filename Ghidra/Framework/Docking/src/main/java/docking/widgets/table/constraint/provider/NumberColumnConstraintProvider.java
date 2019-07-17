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

import java.text.DecimalFormat;
import java.util.*;

import docking.widgets.table.constraint.*;
import docking.widgets.table.constrainteditor.*;

/**
 * Provides number related column constraints.
 */
public class NumberColumnConstraintProvider implements ColumnConstraintProvider {

	@Override
	public Collection<ColumnConstraint<?>> getColumnConstraints() {

		List<ColumnConstraint<?>> list = new ArrayList<>();

		// @formatter:off
		list.add(new AtLeastColumnConstraint<>((byte)0, new ByteEditorProvider()));
		list.add(new AtLeastColumnConstraint<>((short)0, new ShortEditorProvider()));
		list.add(new AtLeastColumnConstraint<>(0, new IntEditorProvider()));
		list.add(new AtLeastColumnConstraint<>(0l, new LongEditorProvider()));
		list.add(new AtLeastColumnConstraint<>(0d, new FloatingEditorProvider()));

		list.add(new AtMostColumnConstraint<>((byte)0, new ByteEditorProvider()));
		list.add(new AtMostColumnConstraint<>((short)0, new ShortEditorProvider()));
		list.add(new AtMostColumnConstraint<>(0, new IntEditorProvider()));
		list.add(new AtMostColumnConstraint<>(0l, new LongEditorProvider()));
		list.add(new AtMostColumnConstraint<>(0d, new FloatingEditorProvider()));

		list.add(new InRangeColumnConstraint<>((byte)0, (byte)0, new ByteRangeEditorProvider()));
		list.add(new InRangeColumnConstraint<>((short)0, (short)0, new ShortRangeEditorProvider()));
		list.add(new InRangeColumnConstraint<>(0, 0, new IntRangeEditorProvider()));
		list.add(new InRangeColumnConstraint<>(0l, 0l, new LongRangeEditorProvider()));
		list.add(new InRangeColumnConstraint<>(0d, 0d, new FloatingRangeEditorProvider()));

		list.add(new NotInRangeColumnConstraint<>((byte)0, (byte)0, new ByteRangeEditorProvider()));
		list.add(new NotInRangeColumnConstraint<>((short)0, (short)0, new ShortRangeEditorProvider()));
		list.add(new NotInRangeColumnConstraint<>(0, 0, new IntRangeEditorProvider()));
		list.add(new NotInRangeColumnConstraint<>(0l, 0l, new LongRangeEditorProvider()));
		list.add(new NotInRangeColumnConstraint<>(0d, 0d, new FloatingRangeEditorProvider()));

		// @formatter:on
		return list;
	}

	/**
	 * Class for providing editor for byte columns.
	 */
	static class ByteEditorProvider extends IntegerEditorProvider<Byte> {
		ByteEditorProvider() {
			super(v -> (byte) v);
		}

	}

	/**
	 * Class for providing editor for short columns.
	 */
	static class ShortEditorProvider extends IntegerEditorProvider<Short> {
		public ShortEditorProvider() {
			super(v -> (short) v);
		}
	}

	/**
	 * Class for providing editor for int columns.
	 */
	static class IntEditorProvider extends IntegerEditorProvider<Integer> {
		public IntEditorProvider() {
			super(v -> (int) v);
		}
	}

	/**
	 * Class for providing range editor for byte columns.
	 */
	static class ByteRangeEditorProvider extends IntegerRangeEditorProvider<Byte> {
		public ByteRangeEditorProvider() {
			super(v -> (byte) v);
		}
	}

	/**
	 * Class for providing range editor for short columns.
	 */
	static class ShortRangeEditorProvider extends IntegerRangeEditorProvider<Short> {
		public ShortRangeEditorProvider() {
			super(v -> (short) v);
		}
	}

	/**
	 * Class for providing range editor for int columns.
	 */
	static class IntRangeEditorProvider extends IntegerRangeEditorProvider<Integer> {
		public IntRangeEditorProvider() {
			super(v -> (int) v);
		}
	}

	/**
	 * Base class for providing single floating point value editors.
	 */
	static class FloatingEditorProvider implements EditorProvider<Double> {

		@Override
		public ColumnConstraintEditor<Double> getEditor(ColumnConstraint<Double> columnConstraint,
				ColumnData<Double> columnDataSource) {
			return new DoubleValueConstraintEditor(columnConstraint);
		}

		@Override
		public Double parseValue(String value, Object dataSource) {
			return Double.parseDouble(value);
		}

		@Override
		public String toString(Double value) {
			return new DecimalFormat(DoubleValueConstraintEditor.FLOATING_POINT_FORMAT).format(
				value);
		}
	}

	/**
	 * Base class for providing floating point range editors.
	 */
	static class FloatingRangeEditorProvider implements EditorProvider<Double> {

		@Override
		public ColumnConstraintEditor<Double> getEditor(ColumnConstraint<Double> columnConstraint,
				ColumnData<Double> columnDataSource) {
			return new DoubleRangeConstraintEditor(columnConstraint);
		}

		@Override
		public Double parseValue(String value, Object dataSource) {
			return Double.parseDouble(value);
		}

		@Override
		public String toString(Double value) {
			return new DecimalFormat(DoubleValueConstraintEditor.FLOATING_POINT_FORMAT).format(
				value);
		}
	}
}
