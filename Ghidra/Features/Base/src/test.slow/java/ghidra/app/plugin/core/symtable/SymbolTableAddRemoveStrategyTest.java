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
package ghidra.app.plugin.core.symtable;

import static docking.widgets.table.AddRemoveListItem.Type.*;
import static org.junit.Assert.*;

import java.util.*;

import org.junit.Before;
import org.junit.Test;

import docking.widgets.table.*;
import docking.widgets.table.threaded.TestTableData;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.TestAddress;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.task.TaskMonitor;

public class SymbolTableAddRemoveStrategyTest {

	private SymbolTableAddRemoveStrategy strategy;
	private SpyTableData spyTableData;
	private List<Symbol> modelData;

	@Before
	public void setUp() throws Exception {
		strategy = new SymbolTableAddRemoveStrategy();
		modelData = createModelData();
		spyTableData = createTableData();
	}

	private SpyTableData createTableData() {
		Comparator<Symbol> comparator = (s1, s2) -> {
			return s1.getName().compareTo(s2.getName());
		};
		TableSortState sortState = TableSortState.createDefaultSortState(0);
		TableSortingContext<Symbol> sortContext =
			new TableSortingContext<>(sortState, comparator);

		modelData.sort(comparator);

		return new SpyTableData(modelData, sortContext);
	}

	private List<Symbol> createModelData() {
		List<Symbol> data = new ArrayList<>();
		data.add(new TestSymbol(1, new TestAddress(101)));
		data.add(new TestSymbol(2, new TestAddress(102)));
		data.add(new TestSymbol(3, new TestAddress(103)));
		data.add(new TestSymbol(4, new TestAddress(104)));
		return data;
	}

	@Test
	public void testRemove_DifferentInstance_SameId() throws Exception {

		List<AddRemoveListItem<Symbol>> addRemoves = new ArrayList<>();

		TestSymbol s = new TestSymbol(1, new TestAddress(101));
		addRemoves.add(new AddRemoveListItem<>(REMOVE, s));

		strategy.process(addRemoves, spyTableData, TaskMonitor.DUMMY);

		assertEquals(1, spyTableData.getRemoveCount());
		assertEquals(0, spyTableData.getInsertCount());
	}

	@Test
	public void testInsert_NewSymbol() throws Exception {

		List<AddRemoveListItem<Symbol>> addRemoves = new ArrayList<>();

		TestSymbol newSymbol = new TestSymbol(10, new TestAddress(1010));
		addRemoves.add(new AddRemoveListItem<>(ADD, newSymbol));

		strategy.process(addRemoves, spyTableData, TaskMonitor.DUMMY);
		assertEquals(0, spyTableData.getRemoveCount());
		assertEquals(1, spyTableData.getInsertCount());
	}

	@Test
	public void testInsertAndRemove_NewSymbol() throws Exception {

		List<AddRemoveListItem<Symbol>> addRemoves = new ArrayList<>();

		TestSymbol newSymbol = new TestSymbol(10, new TestAddress(1010));
		addRemoves.add(new AddRemoveListItem<>(ADD, newSymbol));
		addRemoves.add(new AddRemoveListItem<>(REMOVE, newSymbol));

		strategy.process(addRemoves, spyTableData, TaskMonitor.DUMMY);

		// no work was done, since the insert was followed by a remove
		assertEquals(0, spyTableData.getRemoveCount());
		assertEquals(0, spyTableData.getInsertCount());
	}

	@Test
	public void testChange_NewSymbol() throws Exception {
		List<AddRemoveListItem<Symbol>> addRemoves = new ArrayList<>();

		TestSymbol newSymbol = new TestSymbol(10, new TestAddress(1010));
		addRemoves.add(new AddRemoveListItem<>(CHANGE, newSymbol));

		strategy.process(addRemoves, spyTableData, TaskMonitor.DUMMY);

		// no remove, since the symbol was not in the table
		assertEquals(0, spyTableData.getRemoveCount());
		assertEquals(1, spyTableData.getInsertCount());
	}

	@Test
	public void testChange_ExisingSymbol() throws Exception {
		List<AddRemoveListItem<Symbol>> addRemoves = new ArrayList<>();

		Symbol s = modelData.get(0);
		addRemoves.add(new AddRemoveListItem<>(CHANGE, s));

		strategy.process(addRemoves, spyTableData, TaskMonitor.DUMMY);

		// no remove, since the symbol was not in the table
		assertEquals(1, spyTableData.getRemoveCount());
		assertEquals(1, spyTableData.getInsertCount());
	}

	@Test
	public void testRemoveAndInsert_NewSymbol() throws Exception {

		List<AddRemoveListItem<Symbol>> addRemoves = new ArrayList<>();

		TestSymbol newSymbol = new TestSymbol(10, new TestAddress(1010));
		addRemoves.add(new AddRemoveListItem<>(REMOVE, newSymbol));
		addRemoves.add(new AddRemoveListItem<>(ADD, newSymbol));

		strategy.process(addRemoves, spyTableData, TaskMonitor.DUMMY);

		// the remove does not happen, since the time was not in the table
		assertEquals(0, spyTableData.getRemoveCount());
		assertEquals(1, spyTableData.getInsertCount());
	}

	@Test
	public void testRemoveAndInsert_ExistingSymbol() throws Exception {

		List<AddRemoveListItem<Symbol>> addRemoves = new ArrayList<>();

		Symbol s = modelData.get(0);
		addRemoves.add(new AddRemoveListItem<>(REMOVE, s));
		addRemoves.add(new AddRemoveListItem<>(ADD, s));

		strategy.process(addRemoves, spyTableData, TaskMonitor.DUMMY);

		// the remove does not happen, since the time was not in the table
		assertEquals(1, spyTableData.getRemoveCount());
		assertEquals(1, spyTableData.getInsertCount());
	}

	@Test
	public void testChangeAndInsert_ExistingSymbol() throws Exception {

		List<AddRemoveListItem<Symbol>> addRemoves = new ArrayList<>();

		Symbol s = modelData.get(0);
		addRemoves.add(new AddRemoveListItem<>(CHANGE, s));
		addRemoves.add(new AddRemoveListItem<>(ADD, s));

		strategy.process(addRemoves, spyTableData, TaskMonitor.DUMMY);

		// the insert portions get coalesced
		assertEquals(1, spyTableData.getRemoveCount());
		assertEquals(1, spyTableData.getInsertCount());
	}

	@Test
	public void testChangeAndRemove_ExistingSymbol() throws Exception {

		List<AddRemoveListItem<Symbol>> addRemoves = new ArrayList<>();

		Symbol s = modelData.get(0);
		addRemoves.add(new AddRemoveListItem<>(CHANGE, s));
		addRemoves.add(new AddRemoveListItem<>(REMOVE, s));

		strategy.process(addRemoves, spyTableData, TaskMonitor.DUMMY);

		// the remove portions get coalesced; no insert takes place
		assertEquals(1, spyTableData.getRemoveCount());
		assertEquals(0, spyTableData.getInsertCount());
	}

	@Test
	public void testChangeAndChange_ExistingSymbol() throws Exception {

		List<AddRemoveListItem<Symbol>> addRemoves = new ArrayList<>();

		Symbol s = modelData.get(0);
		addRemoves.add(new AddRemoveListItem<>(CHANGE, s));
		addRemoves.add(new AddRemoveListItem<>(CHANGE, s));

		strategy.process(addRemoves, spyTableData, TaskMonitor.DUMMY);

		// the changes get coalesced
		assertEquals(1, spyTableData.getRemoveCount());
		assertEquals(1, spyTableData.getInsertCount());
	}

	@Test
	public void testRemoveAndRemove_ExistingSymbol() throws Exception {

		List<AddRemoveListItem<Symbol>> addRemoves = new ArrayList<>();

		Symbol s = modelData.get(0);
		addRemoves.add(new AddRemoveListItem<>(REMOVE, s));
		addRemoves.add(new AddRemoveListItem<>(REMOVE, s));

		strategy.process(addRemoves, spyTableData, TaskMonitor.DUMMY);

		// the removes get coalesced
		assertEquals(1, spyTableData.getRemoveCount());
		assertEquals(0, spyTableData.getInsertCount());
	}

	@Test
	public void testInsertAndInsert_ExistingSymbol() throws Exception {

		List<AddRemoveListItem<Symbol>> addRemoves = new ArrayList<>();

		Symbol s = modelData.get(0);
		addRemoves.add(new AddRemoveListItem<>(ADD, s));
		addRemoves.add(new AddRemoveListItem<>(ADD, s));

		strategy.process(addRemoves, spyTableData, TaskMonitor.DUMMY);

		// the inserts get coalesced
		assertEquals(0, spyTableData.getRemoveCount());
		assertEquals(1, spyTableData.getInsertCount());
	}

	@Test
	public void testInsertAndChange_ExistingSymbol() throws Exception {

		List<AddRemoveListItem<Symbol>> addRemoves = new ArrayList<>();

		Symbol s = modelData.get(0);
		addRemoves.add(new AddRemoveListItem<>(ADD, s));
		addRemoves.add(new AddRemoveListItem<>(CHANGE, s));

		strategy.process(addRemoves, spyTableData, TaskMonitor.DUMMY);

		// the insert portions get coalesced
		assertEquals(1, spyTableData.getRemoveCount());
		assertEquals(1, spyTableData.getInsertCount());
	}

	@Test
	public void testRemoveAndChange_ExistingSymbol() throws Exception {

		List<AddRemoveListItem<Symbol>> addRemoves = new ArrayList<>();

		Symbol s = modelData.get(0);
		addRemoves.add(new AddRemoveListItem<>(REMOVE, s));
		addRemoves.add(new AddRemoveListItem<>(CHANGE, s));

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
		List<AddRemoveListItem<Symbol>> addRemoves = new ArrayList<>();

		TestSymbol symbol = (TestSymbol) modelData.get(0);
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
		List<AddRemoveListItem<Symbol>> addRemoves = new ArrayList<>();

		TestSymbol symbol = (TestSymbol) modelData.get(0);
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

	private class SpyTableData extends TestTableData<Symbol> {

		private int removeCount;
		private int insertCount;

		SpyTableData(List<Symbol> data, TableSortingContext<Symbol> sortContext) {
			super(data, sortContext);
		}

		@Override
		public boolean remove(Symbol t) {
			removeCount++;
			return super.remove(t);
		}

		@Override
		public void insert(Symbol value) {
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

	private class TestSymbol extends ProxySymbol {

		private String name;

		TestSymbol(long id, Address address) {
			super(id, address);
			name = id + "@" + address;
		}

		void setName(String name) {
			this.name = name;
		}

		@Override
		public String getName() {
			return name;
		}
	}
}
