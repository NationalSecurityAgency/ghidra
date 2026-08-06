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
package ghidra.program.database.symbol;

import static ghidra.program.database.symbol.SymbolDatabaseAdapter.*;
import static ghidra.program.model.symbol.Namespace.*;
import static ghidra.program.model.symbol.SymbolType.*;
import static org.junit.Assert.*;

import java.io.IOException;
import java.util.*;

import javax.help.UnsupportedOperationException;

import org.junit.Before;
import org.junit.Test;

import db.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class LibraryUpdaterTest {
	private TestSymbolDatabaseAdapter adapter;
	private Schema schema;
	private Map<String, DBRecord> symbolMap;

	private long nextId = 1;

	@Before
	public void setUp() {
		adapter = new TestSymbolDatabaseAdapter();
		schema = SymbolDatabaseAdapter.SYMBOL_SCHEMA;
		symbolMap = new HashMap<>();
	}

	@Test
	public void testUpgradeEternalLabel() throws Exception {
		/*  
		 	upgrade from / to
		
		 		user32.dll::bar
		
		 		global::bar (in library: user32.dll)
		 */

		library("user32.dll");
		label("foo");
		label("user32.dll::bar");
		assertRecordCount(3);

		performUpgrade();

		assertRecordCount(3);
		assertLibrary("user32.dll");
		assertLabel("foo");
		assertLabel("bar");

		assertHasLibrary("bar", "user32.dll");
		assertHasNoLibrary("foo");
	}

	@Test
	public void testUpgradeEternalFunction() throws Exception {
		/*  
		 	upgrade from / to
		
		 		user32.dll::bar
		
		 		global::bar (in library: user32.dll)
		 */

		library("user32.dll");
		function("foo");
		function("user32.dll::bar");
		assertRecordCount(3);

		performUpgrade();

		assertRecordCount(3);
		assertLibrary("user32.dll");
		assertFunction("foo");
		assertFunction("bar");

		assertHasLibrary("bar", "user32.dll");
		assertHasNoLibrary("foo");
	}

	@Test
	public void testUpgradeExternaSymbolInSubNamespace() throws Exception {
		/*  
			upgrade from / to
		
			 	user32.dll::namespace::foo
		
		 		namespace::foo (in library user32.dll)
		 */

		library("user32.dll");
		namespace("user32.dll::fooNs");
		label("user32.dll::fooNs::foo");

		assertRecordCount(3);
		performUpgrade();
		assertRecordCount(3);

		assertLibrary("user32.dll");
		assertNamespace("fooNs");
		assertLabel("fooNs::foo");

		assertHasLibrary("fooNs::foo", "user32.dll");
		assertHasNoLibrary("fooNs");
	}

	@Test
	public void testUpgradeExternalSymbolMergedNamesapce() throws Exception {
		/*  
			upgrade from / to
		
				testNs::foo
		 		user32.dll::testNs::bar
		
				testNs::foo
				testNs::bar (in library user32.dll)  
				(Note: instead of promoting the testNs inside the library, it was deleted and the
					   existing testNs was used)
		 */

		library("user32.dll");
		namespace("testNs");
		namespace("user32.dll::testNs");
		label("testNs::foo");
		label("user32.dll::testNs::bar");

		assertRecordCount(5);
		performUpgrade();
		assertRecordCount(4);

		assertLibrary("user32.dll");
		assertNamespace("testNs");
		assertLabel("testNs::foo");
		assertLabel("testNs::bar");

		assertHasLibrary("testNs::bar", "user32.dll");
		assertHasNoLibrary("testNs::foo");

		assertMissing("user32.dll::testNs");
	}

	@Test
	public void testUpgradeExternalSymbolMergedSubNamesapce() throws Exception {
		/*  
			upgrade from / to
		
				testNs::subNs::foo
		 		user32.dll::testNs::subNs::bar
		
				testNs::subNs::foo
				testNs::subNs::bar (in library user32.dll)  
				(Note: instead of promoting the testNs::subNs inside the library, it was deleted and the
					   existing testNs::subNs was used)
		 */

		library("user32.dll");
		namespace("testNs");
		namespace("testNs::subNs");
		namespace("user32.dll::testNs");
		namespace("user32.dll::testNs::subNs");
		label("testNs::subNs::foo");
		label("user32.dll::testNs::subNs::bar");

		assertRecordCount(7);
		performUpgrade();
		assertRecordCount(5);

		assertLibrary("user32.dll");
		assertNamespace("testNs");
		assertNamespace("testNs::subNs");
		assertLabel("testNs::subNs::foo");
		assertLabel("testNs::subNs::bar");

		assertHasLibrary("testNs::subNs::bar", "user32.dll");
		assertHasNoLibrary("testNs::subNs::foo");

		assertMissing("user32.dll::testNs");
	}

	@Test
	public void testUpgradeExternalLabelInSubNamespaceOfMergedNamespace() throws Exception {
		/*  
			upgrade from / to
		
				testNs::foo
				user32.dll::testNs::subNs::bar
		
				testNs::foo
				testNs::subNs::bar (in library user32.dll)  
				(Note: instead of promoting the testNs inside the library, it was deleted and the
				   existing testNs was used, then the subNs was parented to the existing testNs)
		 */
		library("user32.dll");
		namespace("user32.dll::testNs");
		namespace("testNs");
		namespace("user32.dll::testNs::subNs");
		label("testNs::foo");
		label("user32.dll::testNs::subNs::bar");

		assertRecordCount(6);
		performUpgrade();
		assertRecordCount(5);

		assertLibrary("user32.dll");
		assertNamespace("testNs");
		assertNamespace("testNs::subNs");
		assertLabel("testNs::foo");
		assertLabel("testNs::subNs::bar");

		assertHasNoLibrary("testNs::foo");
		assertHasLibrary("testNs::subNs::bar", "user32.dll");

		assertMissing("user32.dll::testNs");
		assertMissing("user32.dll::testNs::subNs");
	}

	@Test
	public void testUpgradeExternalLabelInNamespaceMergedWithNonClassNamespace() throws Exception {
		/*  
			upgrade from / to
		
				testNs::foo	(testNs is a plain namespace)
				user32.dll::testNs::bar	(testNs is a class namespace)
		
				testNs::foo
				testNs::bar (in library user32.dll)  
				(Note: the testNs is now a class namespace)
		 */
		library("user32.dll");
		namespace("user32.dll::testNs");
		classNamespace("testNs");
		label("testNs::foo");
		label("user32.dll::testNs::bar");

		assertRecordCount(5);
		performUpgrade();
		assertRecordCount(4);

		assertLibrary("user32.dll");
		assertClass("testNs");
		assertLabel("testNs::foo");
		assertLabel("testNs::bar");

		assertHasNoLibrary("testNs::foo");
		assertHasLibrary("testNs::bar", "user32.dll");

		assertMissing("user32.dll::testNs");
		assertMissing("user32.dll::testNs::subNs");
	}

	@Test
	public void testUpgradeExternalLabelInClasMergedWithNonClassNamespace() throws Exception {
		/*  
			upgrade from / to
		
				testNs::foo	(testNs is a plain namespace)
				user32.dll::testNs::bar	(testNs is a class namespace)
		
				testNs::foo
				testNs::bar (in library user32.dll)  
				(Note: the testNs is now a class namespace)
		 */
		library("user32.dll");
		classNamespace("user32.dll::testNs");
		namespace("testNs");
		label("testNs::foo");
		label("user32.dll::testNs::bar");

		assertRecordCount(5);
		performUpgrade();
		assertRecordCount(4);

		assertLibrary("user32.dll");
		assertClass("testNs");
		assertLabel("testNs::foo");
		assertLabel("testNs::bar");

		assertHasNoLibrary("testNs::foo");
		assertHasLibrary("testNs::bar", "user32.dll");

		assertMissing("user32.dll::testNs");
		assertMissing("user32.dll::testNs::subNs");
	}

	private void assertRecordCount(int expectedCount) {
		assertEquals("Record Count: ", expectedCount, adapter.getSymbolCount());

	}

	private void assertMissing(String path) {
		DBRecord dbRecord = symbolMap.get(path);
		if (dbRecord != null) {
			fail("Expected no symbol for " + path + ", but found " +
				dbRecord.getString(SYMBOL_NAME_COL));
		}
	}

	private void assertHasLibrary(String path, String libraryName) {
		DBRecord library = getRecord(libraryName, LIBRARY);
		DBRecord record = getRecord(path, null);
		Field value = record.getFieldValue(SymbolDatabaseAdapter.SYMBOL_LIBRARY_ID_COL);
		if (value.isNull()) {
			fail(path + " does not have a library value");
		}
		if (value.getLongValue() != library.getKey()) {
			DBRecord actual = adapter.getSymbolRecord(value.getLongValue());
			String actualName = actual.getString(SYMBOL_NAME_COL);
			fail("Expected library " + libraryName + ", but has library " + actualName);
		}
	}

	private void assertHasNoLibrary(String path) {
		DBRecord record = getRecord(path, null);
		Field value = record.getFieldValue(SymbolDatabaseAdapter.SYMBOL_LIBRARY_ID_COL);
		if (!value.isNull()) {
			DBRecord actual = adapter.getSymbolRecord(value.getLongValue());
			String actualName = actual.getString(SYMBOL_NAME_COL);
			fail("Expected no library, but has library: " + actualName);
		}
	}

	private void assertLibrary(String libraryPath) {
		getRecord(libraryPath, LIBRARY);
	}

	private void assertLabel(String labelPath) {
		getRecord(labelPath, LABEL);
	}

	private void assertFunction(String labelPath) {
		getRecord(labelPath, FUNCTION);
	}

	private void assertNamespace(String namespacePath) {
		getRecord(namespacePath, NAMESPACE);
	}

	private void assertClass(String classPath) {
		getRecord(classPath, CLASS);
	}

	private DBRecord getRecord(String libraryPath, SymbolType expectedType) {
		DBRecord dbRecord = symbolMap.get(libraryPath);
		if (dbRecord == null) {
			fail("No record found for " + libraryPath);
		}
		if (expectedType != null) {
			SymbolType type = getType(dbRecord);
			assertEquals("Unexpected symbol type for " + libraryPath, expectedType, type);
		}
		return dbRecord;
	}

	private SymbolType getType(DBRecord dbRecord) {
		byte typeValue = dbRecord.getByteValue(SymbolDatabaseAdapter.SYMBOL_TYPE_COL);
		return SymbolType.getSymbolType(typeValue);
	}

	private void performUpgrade() throws Exception {
		LibraryUpgrader updater = new LibraryUpgrader(adapter, TaskMonitor.DUMMY);
		updater.update();
		reloadSymbolMap();
	}

	private void reloadSymbolMap() throws IOException {
		symbolMap.clear();
		RecordIterator it = adapter.getSymbols();
		Map<Long, DBRecord> recordMap = new HashMap<>();
		while (it.hasNext()) {
			DBRecord next = it.next();
			recordMap.put(next.getKey(), next);
		}
		for (DBRecord record : recordMap.values()) {
			symbolMap.put(getPath(record, recordMap), record);
		}
	}

	private String getPath(DBRecord record, Map<Long, DBRecord> recordMap) {
		String name = record.getString(SYMBOL_NAME_COL);
		long parentId = record.getLongValue(SymbolDatabaseAdapter.SYMBOL_PARENT_ID_COL);
		if (parentId == GLOBAL_NAMESPACE_ID) {
			return name;
		}
		return getPath(recordMap.get(parentId), recordMap) + "::" + name;
	}

	private void label(String name) {
		int index = name.lastIndexOf("::");
		if (index < 0) {
			createSymbolRecord(name, LABEL, 0);
			return;
		}
		DBRecord parent = symbolMap.get(name.substring(0, index));
		createSymbolRecord(name.substring(index + 2), LABEL, parent.getKey());
	}

	private void function(String name) {
		int index = name.lastIndexOf("::");
		if (index < 0) {
			createSymbolRecord(name, FUNCTION, 0);
			return;
		}
		DBRecord parent = symbolMap.get(name.substring(0, index));
		createSymbolRecord(name.substring(index + 2), FUNCTION, parent.getKey());
	}

	private void library(String name) {
		DBRecord record = createSymbolRecord(name, LIBRARY, 0);
		symbolMap.put(name, record);

	}

	private void namespace(String name) {
		int index = name.lastIndexOf("::");
		if (index < 0) {
			DBRecord record = createSymbolRecord(name, NAMESPACE, GLOBAL_NAMESPACE_ID);
			symbolMap.put(name, record);
			return;
		}
		DBRecord parent = symbolMap.get(name.substring(0, index));
		DBRecord record = createSymbolRecord(name.substring(index + 2), NAMESPACE, parent.getKey());
		symbolMap.put(name, record);
	}

	private void classNamespace(String name) {
		int index = name.lastIndexOf("::");
		if (index < 0) {
			DBRecord record = createSymbolRecord(name, CLASS, GLOBAL_NAMESPACE_ID);
			symbolMap.put(name, record);
			return;
		}
		DBRecord parent = symbolMap.get(name.substring(0, index));
		DBRecord record = createSymbolRecord(name.substring(index + 2), CLASS, parent.getKey());
		symbolMap.put(name, record);
	}

	private DBRecord createSymbolRecord(String name, SymbolType type, long namespaceId) {
		DBRecord record = schema.createRecord(nextId++);
		record.setString(SYMBOL_NAME_COL, name);
		record.setByteValue(SymbolDatabaseAdapter.SYMBOL_TYPE_COL, type.getID());
		record.setLongValue(SymbolDatabaseAdapter.SYMBOL_PARENT_ID_COL, namespaceId);
		adapter.updateSymbolRecord(record);
		return record;
	}

	private class TestSymbolDatabaseAdapter extends SymbolDatabaseAdapter {
		private Map<Long, DBRecord> records = new HashMap<>();

		@Override
		protected int getVersion() {
			return 0;
		}

		@Override
		DBRecord createSymbolRecord(String name, long namespaceID, Address address,
				SymbolType symbolType, boolean isPrimary, SourceType source) {
			throw new UnsupportedOperationException();
		}

		@Override
		DBRecord getSymbolRecord(long symbolId) {
			return records.get(symbolId);
		}

		@Override
		void removeSymbol(long symbolId) throws IOException {
			records.remove(symbolId);
		}

		@Override
		boolean hasSymbol(Address addr) throws IOException {
			throw new UnsupportedOperationException();
		}

		@Override
		Field[] getSymbolIDs(Address addr) throws IOException {
			throw new UnsupportedOperationException();
		}

		@Override
		int getSymbolCount() {
			return records.size();
		}

		@Override
		RecordIterator getSymbolsByAddress(boolean forward) throws IOException {
			throw new UnsupportedOperationException();
		}

		@Override
		RecordIterator getSymbolsByAddress(Address startAddr, boolean forward) throws IOException {
			throw new UnsupportedOperationException();
		}

		@Override
		void updateSymbolRecord(DBRecord record) {
			records.put(record.getKey(), record);
		}

		@Override
		RecordIterator getSymbols() throws IOException {
			return new TestRecordIterator(records.values());
		}

		@Override
		RecordIterator getSymbols(Address start, Address end, boolean forward) throws IOException {
			throw new UnsupportedOperationException();
		}

		@Override
		RecordIterator getSymbols(AddressSetView set, boolean forward) throws IOException {
			return null;
		}

		@Override
		RecordIterator getPrimarySymbols(AddressSetView set, boolean forward) throws IOException {
			throw new UnsupportedOperationException();
		}

		@Override
		DBRecord getPrimarySymbol(Address address) throws IOException {
			throw new UnsupportedOperationException();
		}

		@Override
		void moveAddress(Address oldAddr, Address newAddr) throws IOException {
			throw new UnsupportedOperationException();
		}

		@Override
		Set<Address> deleteAddressRange(Address startAddr, Address endAddr, TaskMonitor monitor)
				throws CancelledException, IOException {
			throw new UnsupportedOperationException();
		}

		@Override
		RecordIterator getSymbolsByNamespace(long id) throws IOException {
			throw new UnsupportedOperationException();
		}

		@Override
		RecordIterator getSymbolsByName(String name) throws IOException {
			throw new UnsupportedOperationException();
		}

		@Override
		RecordIterator getSymbolsByLibrary(long libraryID) throws IOException {
			throw new UnsupportedOperationException();
		}

		@Override
		RecordIterator scanSymbolsByName(String startName) throws IOException {
			throw new UnsupportedOperationException();
		}

		@Override
		RecordIterator getExternalSymbolsByOriginalImportName(String extLabel) throws IOException {
			throw new UnsupportedOperationException();
		}

		@Override
		RecordIterator getExternalSymbolsByMemoryAddress(Address extProgAddr) throws IOException {
			throw new UnsupportedOperationException();
		}

		@Override
		RecordIterator getSymbolsByNameAndNamespace(String name, long id) throws IOException {
			throw new UnsupportedOperationException();
		}

		@Override
		DBRecord getSymbolRecord(Address address, String name, long namespaceId)
				throws IOException {
			throw new UnsupportedOperationException();
		}

		@Override
		Address getMaxSymbolAddress(AddressSpace space) throws IOException {
			throw new UnsupportedOperationException();
		}

		@Override
		Table getTable() {
			throw new UnsupportedOperationException();
		}

	}

	private class TestRecordIterator implements RecordIterator {
		private Iterator<DBRecord> it;

		TestRecordIterator(Collection<DBRecord> records) {
			it = records.iterator();
		}

		@Override
		public boolean hasNext() throws IOException {
			return it.hasNext();
		}

		@Override
		public boolean hasPrevious() throws IOException {
			return false;
		}

		@Override
		public DBRecord next() throws IOException {
			return it.next();
		}

		@Override
		public DBRecord previous() throws IOException {
			return null;
		}

		@Override
		public boolean delete() throws IOException {
			return false;
		}

	}
}
