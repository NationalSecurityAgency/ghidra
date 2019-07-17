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
package docking.widgets.table;

import static org.junit.Assert.assertEquals;

import java.sql.Date;
import java.util.Arrays;

import org.junit.Assert;
import org.junit.Test;

public class AnyObjectTableModelTest {

	private AnyObjectTableModel<TestClass> model;

	@Test
	public void testColumnsForPublicString() {
		model = new AnyObjectTableModel<>("Test", TestClass.class, "getName");
		assertColumns("Name");
	}

	@Test
	public void testColumnsForMultipleWordMethodNames() {
		model = new AnyObjectTableModel<>("Test", TestClass.class, "getNameThatIsAwesome");
		assertColumns("Name That Is Awesome");
	}

	@Test
	public void testColumnsForPublicInt() {
		model = new AnyObjectTableModel<>("Test", TestClass.class, "getA");
		assertColumns("A");
	}

	@Test
	public void testColumnsForPackageString() {
		model = new AnyObjectTableModel<>("Test", TestClass.class, "getPackageName");
		// verify that a non-public method is not found
		assertColumns("No method: getPackageName");
	}

	public void testMultipleColumns() {
		model = new AnyObjectTableModel<>("Test", TestClass.class, "getName", "getA");
		assertColumns("Name", "A");
	}

	public void testStringValue() {
		model = new AnyObjectTableModel<>("Test", TestClass.class, "getName");
		model.setModelData(Arrays.asList(new TestClass("Bob", 12, new Date(0))));
		Object valueAt = model.getValueAt(0, 0);
		assertEquals("Bob", valueAt);
	}

	public void testPrimitiveValue() {
		model = new AnyObjectTableModel<>("Test", TestClass.class, "getA");
		model.setModelData(Arrays.asList(new TestClass("Bob", 12, new Date(0))));
		Object valueAt = model.getValueAt(0, 0);
		assertEquals(12, valueAt);
	}

	public void testDateObject() {
		model = new AnyObjectTableModel<>("Test", TestClass.class, "getDate");
		model.setModelData(Arrays.asList(new TestClass("Bob", 12, new Date(0))));
		Object valueAt = model.getValueAt(0, 0);
		assertEquals(new Date(0), valueAt);
	}

	public void testValueClass() {
		model = new AnyObjectTableModel<>("Test", TestClass.class, "getDate");
		model.setModelData(Arrays.asList(new TestClass("Bob", 12, new Date(0))));
		Class<?> columnClass = model.getColumnClass(0);
		assertEquals(Date.class, columnClass);

	}

	private void assertColumns(String... columnNames) {
		Assert.assertEquals(columnNames.length, model.getColumnCount());
		for (int i = 0; i < columnNames.length; i++) {
			assertEquals(columnNames[i], model.getColumnName(i));
		}
	}

	static class TestClass {
		private Date date;
		private String name;
		private int a;

		TestClass(String name, int a, Date date) {
			this.name = name;
			this.a = a;
			this.date = date;
		}

		String getPackageName() {
			return getName() + "_package";
		}

		public String getNameThatIsAwesome() {
			return name;
		}

		public String getName() {
			return name;
		}

		public int getA() {
			return a;
		}

		public Date getDate() {
			return date;
		}
	}
}
