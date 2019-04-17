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
package docking.widgets;

import static org.junit.Assert.assertEquals;

import java.util.ArrayList;
import java.util.List;

import org.junit.Before;
import org.junit.Test;

import generic.test.AbstractGenericTest;

public class DefaultDropDownSelectionDataModelTest extends AbstractGenericTest {

	private DefaultDropDownSelectionDataModel<TestType> model;

	public DefaultDropDownSelectionDataModelTest() {
		super();
	}

	@Before
	public void setUp() throws Exception {
		List<TestType> data = new ArrayList<>();
		data.add(new TestType("abc"));
		data.add(new TestType("baa"));
		data.add(new TestType("bac"));
		data.add(new TestType("bace"));
		data.add(new TestType("bad"));
		data.add(new TestType("cat"));
		data.add(new TestType("zzz"));
		model = new DefaultDropDownSelectionDataModel<>(data, t -> t.getName());
	}

	@Test
	public void testGetMatchingData() {
		List<TestType> matchingData = model.getMatchingData("a");
		assertEquals(1, matchingData.size());
		assertEquals("abc", matchingData.get(0).getName());

		matchingData = model.getMatchingData("bac");
		assertEquals(2, matchingData.size());
		assertEquals("bac", matchingData.get(0).getName());
		assertEquals("bace", matchingData.get(1).getName());
	}

	private class TestType {
		private String name;

		TestType(String name) {
			this.name = name;
		}

		String getName() {
			return name;
		}
	}
}
