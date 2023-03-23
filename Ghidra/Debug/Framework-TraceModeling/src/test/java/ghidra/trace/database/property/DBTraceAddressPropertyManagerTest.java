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
package ghidra.trace.database.property;

import static org.junit.Assert.*;

import java.io.File;
import java.util.Map.Entry;
import java.util.Objects;

import org.junit.*;

import db.Transaction;
import ghidra.program.model.address.Address;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.trace.database.ToyDBTraceBuilder;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.TraceAddressSnapRange;
import ghidra.trace.model.property.*;
import ghidra.util.ObjectStorage;
import ghidra.util.Saveable;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.map.TypeMismatchException;

public class DBTraceAddressPropertyManagerTest extends AbstractGhidraHeadlessIntegrationTest {
	protected static class MySaveable implements Saveable {
		protected int i;
		protected String str;

		public MySaveable() {
		}

		public MySaveable(int i, String str) {
			this.i = i;
			this.str = str;
		}

		@Override
		public boolean equals(Object obj) {
			if (obj == this) {
				return true;
			}
			if (!(obj instanceof MySaveable)) {
				return false;
			}
			MySaveable that = (MySaveable) obj;
			return this.i == that.i && Objects.equals(this.str, that.str);
		}

		@Override
		public int hashCode() {
			return Objects.hash(i, str);
		}

		@Override
		public Class<?>[] getObjectStorageFields() {
			return new Class[] { Integer.class, String.class };
		}

		@Override
		public void save(ObjectStorage objStorage) {
			objStorage.putInt(i);
			objStorage.putString(str);
		}

		@Override
		public void restore(ObjectStorage objStorage) {
			i = objStorage.getInt();
			str = objStorage.getString();
		}

		@Override
		public int getSchemaVersion() {
			return 0;
		}

		@Override
		public boolean isUpgradeable(int oldSchemaVersion) {
			return false;
		}

		@Override
		public boolean upgrade(ObjectStorage oldObjStorage, int oldSchemaVersion,
				ObjectStorage currentObjStorage) {
			return false;
		}

		@Override
		public boolean isPrivate() {
			return false;
		}
	}

	protected static class ExtMySaveable extends MySaveable {
		private float f;

		public ExtMySaveable() {
		}

		public ExtMySaveable(int i, String str, float f) {
			super(i, str);
			this.f = f;
		}

		@Override
		public boolean equals(Object obj) {
			if (obj == this) {
				return true;
			}
			if (!(obj instanceof ExtMySaveable)) {
				return false;
			}
			ExtMySaveable that = (ExtMySaveable) obj;
			return super.equals(that) && this.f == that.f;
		}

		@Override
		public int hashCode() {
			return Objects.hash(this.i, this.str, this.f);
		}

		@Override
		public Class<?>[] getObjectStorageFields() {
			return new Class[] { Integer.class, String.class, Float.class };
		}

		@Override
		public void save(ObjectStorage objStorage) {
			super.save(objStorage);
			objStorage.putFloat(f);
		}

		@Override
		public void restore(ObjectStorage objStorage) {
			super.restore(objStorage);
			f = objStorage.getFloat();
		}
	}

	protected static class Unsupported {
	}

	ToyDBTraceBuilder tb;
	TraceAddressPropertyManager propertyManager;

	@Before
	public void setUpPropertyManagerTest() throws Exception {
		tb = new ToyDBTraceBuilder("Testing", "Toy:BE:64:default");
		propertyManager = tb.trace.getAddressPropertyManager();
	}

	@After
	public void tearDownPropertyManagerTest() throws Exception {
		tb.close();
	}

	protected void doTestCreatePropertyMap(Class<?> valueClass) throws Exception {
		try (Transaction tx = tb.startTransaction()) {
			propertyManager.createPropertyMap("MyProp", valueClass);
		}
		try (Transaction tx = tb.startTransaction()) {
			propertyManager.createPropertyMap("MyProp", valueClass);
			fail();
		}
		catch (DuplicateNameException e) {
			// pass
		}
	}

	@Test
	public void testCreateIntegerPropertyMap() throws Exception {
		doTestCreatePropertyMap(Integer.class);
	}

	@Test
	public void testCreateLongPropertyMap() throws Exception {
		doTestCreatePropertyMap(Long.class);
	}

	@Test
	public void testCreateStringPropertyMap() throws Exception {
		doTestCreatePropertyMap(String.class);
	}

	@Test
	public void testCreateVoidPropertyMap() throws Exception {
		doTestCreatePropertyMap(Void.class);
	}

	@Test
	public void testCreateSaveablePropertyMap() throws Exception {
		doTestCreatePropertyMap(MySaveable.class);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testCreateUnsupportedPropertyMap() throws Exception {
		try (Transaction tx = tb.startTransaction()) {
			propertyManager.createPropertyMap("MyProp", Unsupported.class);
		}
	}

	@Test
	public void testGetPropertyMap() throws Exception {
		assertNull(propertyManager.getPropertyMap("MyProp"));
		TracePropertyMapOperations<String> map;
		try (Transaction tx = tb.startTransaction()) {
			map = propertyManager.createPropertyMap("MyProp", String.class);
		}
		assertNotNull(map);
		assertSame(map, propertyManager.getPropertyMap("MyProp"));
		assertSame(map, propertyManager.getPropertyMap("MyProp", String.class));

		try {
			propertyManager.getPropertyMap("MyProp", Integer.class);
			fail();
		}
		catch (TypeMismatchException e) {
			// pass
		}
	}

	@Test
	public void testGetOrCreatePropertyMap() throws Exception {
		assertNull(propertyManager.getPropertyMap("MyProp"));
		TracePropertyMapOperations<String> map;
		try (Transaction tx = tb.startTransaction()) {
			map = propertyManager.getOrCreatePropertyMap("MyProp", String.class);
		}
		assertNotNull(map);
		assertSame(map, propertyManager.getOrCreatePropertyMap("MyProp", String.class));

		try {
			propertyManager.getOrCreatePropertyMap("MyProp", Integer.class);
			fail();
		}
		catch (TypeMismatchException e) {
			// pass
		}
	}

	@Test
	public void testGetAllProperties() throws Exception {
		assertEquals(0, propertyManager.getAllProperties().size());
		TracePropertyMapOperations<String> map;
		try (Transaction tx = tb.startTransaction()) {
			map = propertyManager.createPropertyMap("MyProp", String.class);
		}
		assertNotNull(map);
		assertEquals(1, propertyManager.getAllProperties().size());
		assertSame(map, propertyManager.getAllProperties().get("MyProp"));
	}

	@Test
	public void testMapGetValueClass() throws Exception {
		TracePropertyMapOperations<String> map;
		try (Transaction tx = tb.startTransaction()) {
			map = propertyManager.createPropertyMap("MyProp", String.class);
		}
		assertSame(String.class, map.getValueClass());
	}

	protected <T> void doTestMap(Class<T> valueClass, T value) throws Exception {
		try (Transaction tx = tb.startTransaction()) {
			TracePropertyMapOperations<T> map =
				propertyManager.createPropertyMap("MyProp", valueClass);
			assertSame(valueClass, map.getValueClass());

			map.set(Lifespan.nowOn(0), tb.range(0x00400000, 0x00400003), value);
			assertEquals(value, map.get(4, tb.addr(0x00400001)));

			assertEquals(tb.set(tb.range(0x00400000, 0x00400003)),
				map.getAddressSetView(Lifespan.at(0)));

			Entry<TraceAddressSnapRange, T> entry = map.getEntry(4, tb.addr(0x00400001));
			assertEquals(value, entry.getValue());
			assertEquals(Lifespan.nowOn(0), entry.getKey().getLifespan());
			assertEquals(tb.range(0x00400000, 0x00400003), entry.getKey().getRange());

			map.clear(Lifespan.nowOn(11), tb.range(0x00400000));

			assertEquals(value, map.get(4, tb.addr(0x00400001)));
			assertNull(map.get(11, tb.addr(0x00400001)));
		}
		File file = tb.save();

		try (ToyDBTraceBuilder tb = new ToyDBTraceBuilder(file)) {
			TraceAddressPropertyManager propertyManager = tb.trace.getAddressPropertyManager();
			TracePropertyMapOperations<T> map =
				propertyManager.getPropertyMap("MyProp", valueClass);
			assertNotNull(map);

			Entry<TraceAddressSnapRange, T> entry = map.getEntry(4, tb.addr(0x00400001));
			assertEquals(value, entry.getValue());
			assertEquals(Lifespan.span(0, 10), entry.getKey().getLifespan());
			assertEquals(tb.range(0x00400000, 0x00400003), entry.getKey().getRange());
		}
	}

	@Test
	public void testIntegerMap() throws Exception {
		doTestMap(Integer.class, 6);
	}

	@Test
	public void testLongMap() throws Exception {
		doTestMap(Long.class, 6L);
	}

	@Test
	public void testStringMap() throws Exception {
		doTestMap(String.class, "MyString");
	}

	@Test
	public void testVoidMap() throws Exception {
		doTestMap(Void.class, null);
	}

	@Test
	public void testSaveableMap() throws Exception {
		doTestMap(MySaveable.class, new MySaveable(6, "MyString"));
	}

	@Test
	public void testStringMapAtNoAdress() throws Exception {
		TracePropertyMap<String> map;
		try (Transaction tx = tb.startTransaction()) {
			map = propertyManager.createPropertyMap("MyProp", String.class);

			map.set(Lifespan.nowOn(0), Address.NO_ADDRESS, "Value");
		}

		assertEquals("Value", map.get(4, Address.NO_ADDRESS));

		File file = tb.save();

		try (ToyDBTraceBuilder tb = new ToyDBTraceBuilder(file)) {
			TracePropertyMap<String> map2 =
				tb.trace.getAddressPropertyManager().getPropertyMap("MyProp", String.class);
			assertEquals("Value", map2.get(4, Address.NO_ADDRESS));
		}
	}
}
