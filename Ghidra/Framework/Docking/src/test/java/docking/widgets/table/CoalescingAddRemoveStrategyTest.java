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

import static docking.widgets.table.AddRemoveListItem.Type.*;
import static org.junit.Assert.*;

import java.util.*;

import org.junit.Before;
import org.junit.Test;

import docking.widgets.table.threaded.TestTableData;
import ghidra.util.task.TaskMonitor;

public class CoalescingAddRemoveStrategyTest {

	private CoalescingAddRemoveStrategy<TestRowObject> strategy;
	private SpyTableData spyTableData;
	private List<TestRowObject> modelData;

	@Before
	public void setUp() throws Exception {
		strategy = new CoalescingAddRemoveStrategy<>();
		modelData = createModelData();
		spyTableData = createTableData();
	}

	private SpyTableData createTableData() {
		Comparator<TestRowObject> comparator = (s1, s2) -> {
			return s1.getName().compareTo(s2.getName());
		};
		TableSortState sortState = TableSortState.createDefaultSortState(0);
		TableSortingContext<TestRowObject> sortContext =
			new TableSortingContext<>(sortState, comparator);

		modelData.sort(comparator);

		return new SpyTableData(modelData, sortContext);
	}

	private List<TestRowObject> createModelData() {
		List<TestRowObject> data = new ArrayList<>();
		data.add(new TestRowObject(1));
		data.add(new TestRowObject(2));
		data.add(new TestRowObject(3));
		data.add(new TestRowObject(4));
		return data;
	}

	@Test
	public void testRemove_DifferentInstance_SameId() throws Exception {

		List<AddRemoveListItem<TestRowObject>> addRemoves = new ArrayList<>();

		TestRowObject ro = new TestRowObject(1);
		addRemoves.add(new AddRemoveListItem<>(REMOVE, ro));

		strategy.process(addRemoves, spyTableData, TaskMonitor.DUMMY);

		assertEquals(1, spyTableData.getRemoveCount());
		assertEquals(0, spyTableData.getInsertCount());
	}

	@Test
	public void testInsert_NewSymbol() throws Exception {

		List<AddRemoveListItem<TestRowObject>> addRemoves = new ArrayList<>();

		TestRowObject newSymbol = new TestRowObject(10);
		addRemoves.add(new AddRemoveListItem<>(ADD, newSymbol));

		strategy.process(addRemoves, spyTableData, TaskMonitor.DUMMY);
		assertEquals(0, spyTableData.getRemoveCount());
		assertEquals(1, spyTableData.getInsertCount());
	}

	@Test
	public void testInsertAndRemove_NewSymbol() throws Exception {

		List<AddRemoveListItem<TestRowObject>> addRemoves = new ArrayList<>();

		TestRowObject newSymbol = new TestRowObject(10);
		addRemoves.add(new AddRemoveListItem<>(ADD, newSymbol));
		addRemoves.add(new AddRemoveListItem<>(REMOVE, newSymbol));

		strategy.process(addRemoves, spyTableData, TaskMonitor.DUMMY);

		// no work was done, since the insert was followed by a remove
		assertEquals(0, spyTableData.getRemoveCount());
		assertEquals(0, spyTableData.getInsertCount());
	}

	@Test
	public void testChange_NewSymbol() throws Exception {
		List<AddRemoveListItem<TestRowObject>> addRemoves = new ArrayList<>();

		TestRowObject newSymbol = new TestRowObject(10);
		addRemoves.add(new AddRemoveListItem<>(CHANGE, newSymbol));

		strategy.process(addRemoves, spyTableData, TaskMonitor.DUMMY);

		// no remove, since the symbol was not in the table
		assertEquals(0, spyTableData.getRemoveCount());
		assertEquals(1, spyTableData.getInsertCount());
	}

	@Test
	public void testChange_ExisingSymbol() throws Exception {
		List<AddRemoveListItem<TestRowObject>> addRemoves = new ArrayList<>();

		TestRowObject ro = modelData.get(0);
		addRemoves.add(new AddRemoveListItem<>(CHANGE, ro));

		strategy.process(addRemoves, spyTableData, TaskMonitor.DUMMY);

		// no remove, since the symbol was not in the table
		assertEquals(1, spyTableData.getRemoveCount());
		assertEquals(1, spyTableData.getInsertCount());
	}

	@Test
	public void testRemoveAndInsert_NewSymbol() throws Exception {

		List<AddRemoveListItem<TestRowObject>> addRemoves = new ArrayList<>();

		TestRowObject newSymbol = new TestRowObject(10);
		addRemoves.add(new AddRemoveListItem<>(REMOVE, newSymbol));
		addRemoves.add(new AddRemoveListItem<>(ADD, newSymbol));

		strategy.process(addRemoves, spyTableData, TaskMonitor.DUMMY);

		// the remove does not happen, since the time was not in the table
		assertEquals(0, spyTableData.getRemoveCount());
		assertEquals(1, spyTableData.getInsertCount());
	}

	@Test
	public void testRemoveAndInsert_ExistingSymbol() throws Exception {

		List<AddRemoveListItem<TestRowObject>> addRemoves = new ArrayList<>();

		TestRowObject ro = modelData.get(0);
		addRemoves.add(new AddRemoveListItem<>(REMOVE, ro));
		addRemoves.add(new AddRemoveListItem<>(ADD, ro));

		strategy.process(addRemoves, spyTableData, TaskMonitor.DUMMY);

		// the remove does not happen, since the time was not in the table
		assertEquals(1, spyTableData.getRemoveCount());
		assertEquals(1, spyTableData.getInsertCount());
	}

	@Test
	public void testChangeAndInsert_ExistingSymbol() throws Exception {

		List<AddRemoveListItem<TestRowObject>> addRemoves = new ArrayList<>();

		TestRowObject ro = modelData.get(0);
		addRemoves.add(new AddRemoveListItem<>(CHANGE, ro));
		addRemoves.add(new AddRemoveListItem<>(ADD, ro));

		strategy.process(addRemoves, spyTableData, TaskMonitor.DUMMY);

		// the insert portions get coalesced
		assertEquals(1, spyTableData.getRemoveCount());
		assertEquals(1, spyTableData.getInsertCount());
	}

	@Test
	public void testChangeAndRemove_ExistingSymbol() throws Exception {

		List<AddRemoveListItem<TestRowObject>> addRemoves = new ArrayList<>();

		TestRowObject ro = modelData.get(0);
		addRemoves.add(new AddRemoveListItem<>(CHANGE, ro));
		addRemoves.add(new AddRemoveListItem<>(REMOVE, ro));

		strategy.process(addRemoves, spyTableData, TaskMonitor.DUMMY);

		// the remove portions get coalesced; no insert takes place
		assertEquals(1, spyTableData.getRemoveCount());
		assertEquals(0, spyTableData.getInsertCount());
	}

	@Test
	public void testChangeAndChange_ExistingSymbol() throws Exception {

		List<AddRemoveListItem<TestRowObject>> addRemoves = new ArrayList<>();

		TestRowObject ro = modelData.get(0);
		addRemoves.add(new AddRemoveListItem<>(CHANGE, ro));
		addRemoves.add(new AddRemoveListItem<>(CHANGE, ro));

		strategy.process(addRemoves, spyTableData, TaskMonitor.DUMMY);

		// the changes get coalesced
		assertEquals(1, spyTableData.getRemoveCount());
		assertEquals(1, spyTableData.getInsertCount());
	}

	@Test
	public void testRemoveAndRemove_ExistingSymbol() throws Exception {

		List<AddRemoveListItem<TestRowObject>> addRemoves = new ArrayList<>();

		TestRowObject ro = modelData.get(0);
		addRemoves.add(new AddRemoveListItem<>(REMOVE, ro));
		addRemoves.add(new AddRemoveListItem<>(REMOVE, ro));

		strategy.process(addRemoves, spyTableData, TaskMonitor.DUMMY);

		// the removes get coalesced
		assertEquals(1, spyTableData.getRemoveCount());
		assertEquals(0, spyTableData.getInsertCount());
	}

	@Test
	public void testInsertAndInsert_ExistingSymbol() throws Exception {

		List<AddRemoveListItem<TestRowObject>> addRemoves = new ArrayList<>();

		TestRowObject ro = modelData.get(0);
		addRemoves.add(new AddRemoveListItem<>(ADD, ro));
		addRemoves.add(new AddRemoveListItem<>(ADD, ro));

		strategy.process(addRemoves, spyTableData, TaskMonitor.DUMMY);

		// the inserts get coalesced
		assertEquals(0, spyTableData.getRemoveCount());
		assertEquals(1, spyTableData.getInsertCount());
	}

	@Test
	public void testInsertAndChange_ExistingSymbol() throws Exception {

		List<AddRemoveListItem<TestRowObject>> addRemoves = new ArrayList<>();

		TestRowObject ro = modelData.get(0);
		addRemoves.add(new AddRemoveListItem<>(ADD, ro));
		addRemoves.add(new AddRemoveListItem<>(CHANGE, ro));

		strategy.process(addRemoves, spyTableData, TaskMonitor.DUMMY);

		// the insert portions get coalesced
		assertEquals(1, spyTableData.getRemoveCount());
		assertEquals(1, spyTableData.getInsertCount());
	}

	@Test
	public void testRemoveAndChange_ExistingSymbol() throws Exception {

		List<AddRemoveListItem<TestRowObject>> addRemoves = new ArrayList<>();

		TestRowObject ro = modelData.get(0);
		addRemoves.add(new AddRemoveListItem<>(REMOVE, ro));
		addRemoves.add(new AddRemoveListItem<>(CHANGE, ro));

		strategy.process(addRemoves, spyTableData, TaskMonitor.DUMMY);

		// the remove portions get coalesced
		assertEquals(1, spyTableData.getRemoveCount());
		assertEquals(1, spyTableData.getInsertCount());
	}

	@Test
	public void testLostItems_Remove() throws Exception {

		// 
		// Test that symbols get removed when the data up on which they are sorted changes before
		// the removal takes place
		//
		List<AddRemoveListItem<TestRowObject>> addRemoves = new ArrayList<>();

		TestRowObject symbol = modelData.get(0);
		symbol.setName("UpdatedName");
		addRemoves.add(new AddRemoveListItem<>(REMOVE, symbol));

		strategy.process(addRemoves, spyTableData, TaskMonitor.DUMMY);

		// the insert portions get coalesced
		assertEquals(1, spyTableData.getRemoveCount());
		assertEquals(0, spyTableData.getInsertCount());
	}

	@Test
	public void testLostItems_Change() throws Exception {

		// 
		// Test that symbols get removed when the data up on which they are sorted changes before
		// the removal takes place
		//
		List<AddRemoveListItem<TestRowObject>> addRemoves = new ArrayList<>();

		TestRowObject symbol = modelData.get(0);
		symbol.setName("UpdatedName");
		addRemoves.add(new AddRemoveListItem<>(CHANGE, symbol));

		strategy.process(addRemoves, spyTableData, TaskMonitor.DUMMY);

		// the insert portions get coalesced
		assertEquals(1, spyTableData.getRemoveCount());
		assertEquals(1, spyTableData.getInsertCount());
	}

//==================================================================================================
// Inner Classes
//==================================================================================================	

	private class SpyTableData extends TestTableData<TestRowObject> {

		private int removeCount;
		private int insertCount;

		SpyTableData(List<TestRowObject> data, TableSortingContext<TestRowObject> sortContext) {
			super(data, sortContext);
		}

		@Override
		public boolean remove(TestRowObject t) {
			removeCount++;
			return super.remove(t);
		}

		@Override
		public void insert(TestRowObject value) {
			insertCount++;
			super.insert(value);
		}

		int getRemoveCount() {
			return removeCount;
		}

		int getInsertCount() {
			return insertCount;
		}
	}

	private class TestRowObject {

		private String name;
		private long id;

		TestRowObject(long id) {
			this.id = id;
			this.name = Long.toString(id);
		}

		String getName() {
			return name;
		}

		void setName(String newName) {
			this.name = newName;
		}

		@Override
		public int hashCode() {
			return (int) id;
		}

		@Override
		public boolean equals(Object obj) {
			if (this == obj) {
				return true;
			}
			if (obj == null) {
				return false;
			}
			if (getClass() != obj.getClass()) {
				return false;
			}

			TestRowObject other = (TestRowObject) obj;
			if (id != other.id) {
				return false;
			}
			return true;
		}

	}
}
