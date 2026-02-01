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
package ghidra.program.model.data;

import java.util.Arrays;

import org.junit.Test;

import generic.test.AbstractGTest;

public class DataTypeNameComparatorTest extends AbstractGTest {

	@Test
	public void testDataTypeNameSort() {

		String[] names = new String[] {
			//@formatter:off
			"int",
			"INT",
			"int *",
			"INT *",
			"int [2]",
			"int * *",
			"INT_PTR",
			"s1 *",
			"S1 *",
			"S1.conflict",
			"s1",
			"S1",
			"S1.conflict1",
			"S1.conflict10",
			"S1.conflict2",
			"s1.conflict *",
			"s1.conflict2 *",
			"s1.conflict10"
			//@formatter:on
		};

		String[] sortedNames = new String[] {
			//@formatter:off
			"INT",
			"INT *",
			"int",
			"int *",
			"int * *",
			"int [2]",
			"INT_PTR",
			"S1",
			"S1 *",
			"S1.conflict",
			"S1.conflict1",
			"S1.conflict2",
			"S1.conflict10",
			"s1",
			"s1 *",
			"s1.conflict *",
			"s1.conflict2 *",
			"s1.conflict10"
			//@formatter:on
		};

		Arrays.sort(names, DataTypeNameComparator.INSTANCE);

		assertArraysEqualOrdered("Incorrect datatype name sort order", sortedNames, names);
	}

}
