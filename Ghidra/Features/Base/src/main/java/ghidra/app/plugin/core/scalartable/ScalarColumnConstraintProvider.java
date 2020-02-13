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
package ghidra.app.plugin.core.scalartable;

import java.util.*;

import docking.widgets.table.constraint.*;
import docking.widgets.table.constraint.provider.LongEditorProvider;
import docking.widgets.table.constraint.provider.LongRangeEditorProvider;
import ghidra.program.model.scalar.Scalar;

/**
 * Provides Scalar-related column constraints.
 */
public class ScalarColumnConstraintProvider implements ColumnConstraintProvider {

	@Override
	public Collection<ColumnConstraint<?>> getColumnConstraints() {

		List<ColumnConstraint<?>> list = new ArrayList<>();

		/*
		 *  Since we're converting Scalar to Long, we'll also get the extant Long constraints; 
		 *  they'll operate on the scalars value, independent of signedness.
		 */

		// @formatter:off
		list.add(makeSignedConstraint(new AtLeastColumnConstraint<>("At Least (signed)", 0l, new LongEditorProvider(), "scalar")));
		list.add(makeSignedConstraint(new AtMostColumnConstraint<>("At Most (signed)", 0l, new LongEditorProvider(), "scalar")));
		list.add(makeSignedConstraint(new InRangeColumnConstraint<>("In Range (signed)", 0l, 0l, new LongRangeEditorProvider(), "scalar")));
		list.add(makeSignedConstraint(new NotInRangeColumnConstraint<>("Not In Range (signed)", 0l, 0l, new LongRangeEditorProvider(), "scalar")));

		list.add(makeUnsignedConstraint(new AtLeastColumnConstraint<>("At Least (unsigned)", 0l, new LongEditorProvider(), "scalar-unsigned")));
		list.add(makeUnsignedConstraint(new AtMostColumnConstraint<>("At Most (unsigned)", 0l, new LongEditorProvider(), "scalar-unsigned")));
		list.add(makeUnsignedConstraint(new InRangeColumnConstraint<>("In Range (unsigned)", 0l, 0l, new LongRangeEditorProvider(), "scalar-unsigned")));
		list.add(makeUnsignedConstraint(new NotInRangeColumnConstraint<>("Not In Range (unsigned)", 0l, 0l, new LongRangeEditorProvider(), "scalar-unsigned")));
		// @formatter:on

		return list;
	}

	private static ColumnConstraint<?> makeSignedConstraint(ColumnConstraint<Long> delegate) {
		return new ScalarMappedColumnConstraint(new ScalarToSignedLongColumnTypeMapper(), delegate);
	}

	private static ColumnConstraint<?> makeUnsignedConstraint(ColumnConstraint<Long> delegate) {
		return new ScalarMappedColumnConstraint(new ScalarToUnsignedLongColumnTypeMapper(),
			delegate);
	}

	/**
	 * Class that converts a Scalar to a signed Long value
	 */
	static class ScalarToSignedLongColumnTypeMapper extends ColumnTypeMapper<Scalar, Long> {

		@Override
		public Long convert(Scalar value) {
			return value.getSignedValue();
		}
	}

	/**
	 * Class that converts a Scalar to an unsigned Long value
	 */
	static class ScalarToUnsignedLongColumnTypeMapper extends ColumnTypeMapper<Scalar, Long> {

		@Override
		public Long convert(Scalar value) {
			return value.getUnsignedValue();
		}
	}

	/**
	 * Class to adapt Long-type constraints to Scalar-type columns.
	 */
	static class ScalarMappedColumnConstraint extends MappedColumnConstraint<Scalar, Long> {

		public ScalarMappedColumnConstraint(ColumnTypeMapper<Scalar, Long> mapper,
				ColumnConstraint<Long> delegate) {
			super(mapper, delegate);
		}

	}

}
