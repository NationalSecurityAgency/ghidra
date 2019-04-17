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
package docking.widgets.table.constrainteditor;

import java.math.BigInteger;

import docking.widgets.table.constraint.ColumnConstraint;
import docking.widgets.table.constraint.ColumnData;
import docking.widgets.table.constraint.provider.EditorProvider;

/**
 * {@link EditorProvider} for the {@link UnsignedLongRangeConstraintEditor}.
 */
public class UnsignedLongRangeEditorProvider implements EditorProvider<BigInteger> {

	@Override
	public ColumnConstraintEditor<BigInteger> getEditor(
			ColumnConstraint<BigInteger> columnConstraint, ColumnData<BigInteger> columnData) {
		return new UnsignedLongRangeConstraintEditor(columnConstraint);
	}

	@Override
	public BigInteger parseValue(String value, Object dataSource) {
		return new BigInteger(value, 16);
	}

	@Override
	public String toString(BigInteger value) {
		return value.toString(16);
	}

}
