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
package ghidra.base.widgets.table.constraint.provider;

import java.math.BigInteger;
import java.util.*;

import docking.widgets.table.constraint.*;
import docking.widgets.table.constrainteditor.*;
import ghidra.program.model.address.Address;
import ghidra.util.NumericUtilities;

/**
 * Class for providing Program related column type constraints.  Addresses get converted to
 * UnsignedLong (via BigInteger) and many others get converted to Strings.  For example, some
 * tables have a column whose type is "Symbol", but the column just displays the symbol's name.
 * So we created a number of "Symbol" constraints, but they are just adapters to the
 * various String constraints.
 */
public class ProgramColumnConstraintProvider implements ColumnConstraintProvider {

	@Override
	public Collection<ColumnConstraint<?>> getColumnConstraints() {
		List<ColumnConstraint<?>> list = new ArrayList<>();

		// @formatter:off

		list.add(new AddressColumnConstraint(new AtMostColumnConstraint<>(UnsignedLongConstraintEditor.MAX_VALUE, new UnsignedLongConstraintEditorProvider())));
		list.add(new AddressColumnConstraint(new AtLeastColumnConstraint<>(BigInteger.ZERO, new UnsignedLongConstraintEditorProvider())));
		list.add(new AddressColumnConstraint(new InRangeColumnConstraint<>(BigInteger.ZERO, UnsignedLongConstraintEditor.MAX_VALUE, new UnsignedLongRangeEditorProvider())));
		list.add(new AddressColumnConstraint(new NotInRangeColumnConstraint<>(BigInteger.ZERO, UnsignedLongConstraintEditor.MAX_VALUE, new UnsignedLongRangeEditorProvider())));

		// @formatter:on

		return list;

	}

	/**
	 * This is a special non-discoverable mapper to be used by the special AddressColumnConstraint
	 * class below.  This is special because we don't want to use any old BigInteger editor, but
	 * rather an unsigned editor that makes more sense for addresses.
	 */
	private static class AddressToBigIntegerMapper extends ColumnTypeMapper<Address, BigInteger> {

		@Override
		public BigInteger convert(Address value) {
			return NumericUtilities.unsignedLongToBigInteger(value.getOffset());
		}

	}

	/**
	 * This is a special mapped constraint because we don't wan't a default BigInteger editor,
	 * but rather an unsigned editor that is more appropriate for addresses.
	 */
	private static class AddressColumnConstraint
			extends MappedColumnConstraint<Address, BigInteger> {

		public AddressColumnConstraint(ColumnConstraint<BigInteger> delegate) {
			super(new AddressToBigIntegerMapper(), delegate);
		}

		@Override
		public ColumnConstraint<Address> copy(ColumnConstraint<BigInteger> value) {
			return new AddressColumnConstraint(value);
		}

	}

}
