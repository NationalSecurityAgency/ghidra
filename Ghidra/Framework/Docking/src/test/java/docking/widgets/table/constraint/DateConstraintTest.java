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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.time.LocalDate;
import java.util.*;

import org.junit.Before;
import org.junit.Test;

import docking.widgets.table.constraint.provider.DateColumnConstraintProvider;
import docking.widgets.table.constraint.provider.DateColumnTypeMapper;

public class DateConstraintTest {

	private ColumnConstraint<Date> greaterThan;
	private ColumnConstraint<Date> lessThan;
	private ColumnConstraint<Date> inRange;
	private ColumnConstraint<Date> notInRange;

	private static final long SECOND = 1000;
	private static final long MINUTE = 60 * SECOND;
	private static final long HOUR = 60 * MINUTE;
	private static final long DAY = 24 * HOUR;

	@Before
	public void setup() {
		DateColumnConstraintProvider provider = new DateColumnConstraintProvider();
		Collection<ColumnConstraint<?>> columnConstraints = provider.getColumnConstraints();

		greaterThan = getConstraint(columnConstraints, "On or After Date");
		lessThan = getConstraint(columnConstraints, "On or Before Date");
		inRange = getConstraint(columnConstraints, "Between Dates");
		notInRange = getConstraint(columnConstraints, "Not Between Dates");

	}

	private ColumnConstraint<Date> getConstraint(Collection<ColumnConstraint<?>> columnConstraints,
			String string) {
		// @formatter:off
		Optional<ColumnConstraint<?>> first = columnConstraints.stream()
				.filter(v -> v.getColumnType().equals(LocalDate.class) && v.getName().equals(string))
				.findFirst();
		// @formatter:on
		@SuppressWarnings("unchecked")
		ColumnConstraint<LocalDate> constraint = (ColumnConstraint<LocalDate>) first.orElse(null);
		if (constraint != null) {
			return new MappedColumnConstraint<>(new DateColumnTypeMapper(), constraint);
		}
		fail("Could not find constraint: " + string);
		return null;
	}

	@Test
	public void testGetColumnType() {
		assertEquals(Date.class, greaterThan.getColumnType());
	}

	@Test
	public void testRoundTripParseForSingleValueDateConstraint() {

		String valueString = lessThan.getConstraintValueString();
		ColumnConstraint<Date> parsed = lessThan.parseConstraintValue(valueString, null);
		String parsedValueString = parsed.getConstraintValueString();
		assertEquals(lessThan, parsed);

	}

	@Test
	public void testRoundTripParseForRangeDateConstraint() {
		String valueString = inRange.getConstraintValueString();
		ColumnConstraint<Date> parsed = inRange.parseConstraintValue(valueString, null);
		assertEquals(inRange, parsed);

	}
}
