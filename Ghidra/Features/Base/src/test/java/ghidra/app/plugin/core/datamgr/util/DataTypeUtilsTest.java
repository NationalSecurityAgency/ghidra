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
package ghidra.app.plugin.core.datamgr.util;

import java.util.*;

import org.junit.Before;
import org.junit.Test;

import generic.test.AbstractGTest;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComparator;
import ghidra.program.model.data.TestDoubleDataType;
import ghidra.util.UniversalIdGenerator;

public class DataTypeUtilsTest {

	@Before
	public void setUp() {
		UniversalIdGenerator.initialize();
	}

	@Test
	public void testDataSearch() throws Exception {

		String[] TEST_DATA =
			{ "10th", "1st", "2nd", "3rd", "4th", "5th", "6th", "7th", "8th", "9th", "a", "AAA",
				"AAAS", "Aarhus", "azure", "b", "babbitt", "babble", "Babcock", "bromide",
				"bromine", "Bromley", "Yves", "Yvette", "YWCA", "z", "Zachary", "zag", "zagging" };

		final List<DataType> data = new ArrayList<>();

		for (String element : TEST_DATA) {
			data.add(new FakeDataType(element));
		}

		// sort them how our data will be sorted
		Collections.sort(data, new DataTypeComparator());
		List<DataType> finalData = Collections.unmodifiableList(data);

		// a
		runDataSearchForString("a", data, finalData.subList(10, 15));

		// aa
		runDataSearchForString("AA", data, finalData.subList(11, 14));

		// aaa
		runDataSearchForString("aaa", data, finalData.subList(11, 13));

		// 1
		runDataSearchForString("1", data, finalData.subList(0, 2));

		// 1s
		runDataSearchForString("1s", data, finalData.subList(1, 2));

		// 8
		runDataSearchForString("8", data, finalData.subList(8, 9));

		// 8th
		runDataSearchForString("8th", data, finalData.subList(8, 9));

		// no match
		List<DataType> emptyList = Collections.emptyList();
		runDataSearchForString("8thz", data, emptyList);

		// b
		runDataSearchForString("b", data, finalData.subList(15, 22));

		// ba
		runDataSearchForString("ba", data, finalData.subList(16, 19));

		// bab (same as ba)    
		runDataSearchForString("bab", data, finalData.subList(16, 19));

		// br
		runDataSearchForString("br", data, finalData.subList(19, 22));

		// Y        
		runDataSearchForString("Y", data, finalData.subList(22, 25));

		// yv
		runDataSearchForString("Yv", data, finalData.subList(22, 24));

		// z
		runDataSearchForString("Z", data, finalData.subList(25, 29));

		// za
		runDataSearchForString("zA", data, finalData.subList(26, 29));

		// zag
		runDataSearchForString("zag", data, finalData.subList(27, 29));
	}

	private void runDataSearchForString(String text, List<DataType> sourceData,
			List<DataType> expectedMatches) {

		char endChar = '\uffff';
		List<DataType> actualMatches =
			DataTypeUtils.getMatchingSubList(text, text + endChar, sourceData);

		AbstractGTest.assertListEqualUnordered(null, expectedMatches, actualMatches);
	}

	private class FakeDataType extends TestDoubleDataType {

		FakeDataType(String name) {
			super(name);
		}

		@Override
		public String getPathName() {
			return "/" + getName();
		}
	}
}
