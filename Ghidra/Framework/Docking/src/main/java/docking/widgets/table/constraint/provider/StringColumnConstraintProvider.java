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

import java.util.*;

import docking.widgets.table.constraint.*;

/**
 * Provides String related column constraints.
 */
public class StringColumnConstraintProvider implements ColumnConstraintProvider {

	@Override
	public Collection<ColumnConstraint<?>> getColumnConstraints() {
		List<ColumnConstraint<?>> list = new ArrayList<>();

		list.add(new StringContainsColumnConstraint(""));
		list.add(new StringStartsWithColumnConstraint(""));

		list.add(new StringMatcherColumnConstraint(""));
		list.add(new StringNotContainsColumnConstraint(""));
		list.add(new StringNotStartsWithColumnConstraint(""));

		list.add(new StringEndsWithColumnConstraint(""));
		list.add(new StringNotEndsWithColumnConstraint(""));

		list.add(new StringIsEmptyColumnConstraint());
		list.add(new StringIsNotEmptyColumnConstraint());
		return list;

	}
}
