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
package ghidra.util.database;

import static org.junit.Assert.*;

import java.io.IOException;

import org.junit.Ignore;
import org.junit.Test;

import db.DBHandle;
import db.DBRecord;
import ghidra.util.UniversalIdGenerator;
import ghidra.util.database.annot.*;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

public class DBCachedObjectStoreFactoryTest {
	static {
		UniversalIdGenerator.initialize();
	}

	public static class MyDomainObject extends DBCachedDomainObjectAdapter {
		protected MyDomainObject(DBHandle dbh, String name, Object consumer) {
			super(dbh, DBOpenMode.CREATE, TaskMonitor.DUMMY, name, 500, 1000, consumer);
		}

		@Override
		public boolean isChangeable() {
			return true;
		}

		@Override
		public String getDescription() {
			return "Dummy Domain Object";
		}
	}

	@DBAnnotatedObjectInfo(version = 0)
	public static class MyObject extends DBAnnotatedObject {
		public static final String TABLE_NAME = "OBJECTS";

		public static final String A_COLUMN_NAME = "A";
		public static final String C_COLUMN_NAME = "C";

		@DBAnnotatedColumn(A_COLUMN_NAME)
		static DBObjectColumn A_COLUMN;
		@DBAnnotatedColumn(C_COLUMN_NAME)
		static DBObjectColumn C_COLUMN;

		@DBAnnotatedField(column = "A")
		int a;

		@DBAnnotatedField(column = "C")
		int c;

		public MyObject(DBCachedObjectStore<? extends MyObject> store, DBRecord record) {
			super(store, record);
		}
	}

	@DBAnnotatedObjectInfo(version = 0)
	public static class MyExtObject extends MyObject {
		@SuppressWarnings("hiding")
		public static final String TABLE_NAME = "EXTENDED_OBJECTS";

		public static final String B_COLUMN_NAME = "B";

		@SuppressWarnings("hiding")
		@DBAnnotatedColumn(A_COLUMN_NAME)
		static DBObjectColumn A_COLUMN;
		@SuppressWarnings("hiding")
		@DBAnnotatedColumn(C_COLUMN_NAME)
		static DBObjectColumn C_COLUMN;
		@DBAnnotatedColumn(B_COLUMN_NAME)
		static DBObjectColumn B_COLUMN;

		@DBAnnotatedField(column = "B")
		int b;

		public MyExtObject(DBCachedObjectStore<? extends MyExtObject> store, DBRecord record) {
			super(store, record);
		}
	}

	public enum MyEnum {
		VAL0,
		VAL1,
		VAL2,
		VAL3,
		VAL4,
		VAL5,
		VAL6,
		VAL7,
		VAL8,
		VAL9,
		VAL10,
		VAL11,
		VAL12,
		VAL13,
		VAL14,
		VAL15,
		VAL16,
		VAL17,
		VAL18,
		VAL19,
		VAL20,
		VAL21,
		VAL22,
		VAL23,
		VAL24,
		VAL25,
		VAL26,
		VAL27,
		VAL28,
		VAL29,
		VAL30,
		VAL31,
		VAL32,
		VAL33,
		VAL34,
		VAL35,
		VAL36,
		VAL37,
		VAL38,
		VAL39,
		VAL40,
		VAL41,
		VAL42,
		VAL43,
		VAL44,
		VAL45,
		VAL46,
		VAL47,
		VAL48,
		VAL49,
		VAL50,
		VAL51,
		VAL52,
		VAL53,
		VAL54,
		VAL55,
		VAL56,
		VAL57,
		VAL58,
		VAL59,
		VAL60,
		VAL61,
		VAL62,
		VAL63,
		VAL64,
		VAL65,
		VAL66,
		VAL67,
		VAL68,
		VAL69,
		VAL70,
		VAL71,
		VAL72,
		VAL73,
		VAL74,
		VAL75,
		VAL76,
		VAL77,
		VAL78,
		VAL79,
		VAL80,
		VAL81,
		VAL82,
		VAL83,
		VAL84,
		VAL85,
		VAL86,
		VAL87,
		VAL88,
		VAL89,
		VAL90,
		VAL91,
		VAL92,
		VAL93,
		VAL94,
		VAL95,
		VAL96,
		VAL97,
		VAL98,
		VAL99,
		VAL100,
		VAL101,
		VAL102,
		VAL103,
		VAL104,
		VAL105,
		VAL106,
		VAL107,
		VAL108,
		VAL109,
		VAL110,
		VAL111,
		VAL112,
		VAL113,
		VAL114,
		VAL115,
		VAL116,
		VAL117,
		VAL118,
		VAL119,
		VAL120,
		VAL121,
		VAL122,
		VAL123,
		VAL124,
		VAL125,
		VAL126,
		VAL127,
		VAL128,
		VAL129,
		VAL130,
		VAL131,
		VAL132,
		VAL133,
		VAL134,
		VAL135,
		VAL136,
		VAL137,
		VAL138,
		VAL139,
		VAL140,
		VAL141,
		VAL142,
		VAL143,
		VAL144,
		VAL145,
		VAL146,
		VAL147,
		VAL148,
		VAL149,
		VAL150,
		VAL151,
		VAL152,
		VAL153,
		VAL154,
		VAL155,
		VAL156,
		VAL157,
		VAL158,
		VAL159,
		VAL160,
		VAL161,
		VAL162,
		VAL163,
		VAL164,
		VAL165,
		VAL166,
		VAL167,
		VAL168,
		VAL169,
		VAL170,
		VAL171,
		VAL172,
		VAL173,
		VAL174,
		VAL175,
		VAL176,
		VAL177,
		VAL178,
		VAL179,
		VAL180,
		VAL181,
		VAL182,
		VAL183,
		VAL184,
		VAL185,
		VAL186,
		VAL187,
		VAL188,
		VAL189,
		VAL190,
		VAL191,
		VAL192,
		VAL193,
		VAL194,
		VAL195,
		VAL196,
		VAL197,
		VAL198,
		VAL199,
		VAL200,
		VAL201,
		VAL202,
		VAL203,
		VAL204,
		VAL205,
		VAL206,
		VAL207,
		VAL208,
		VAL209,
		VAL210,
		VAL211,
		VAL212,
		VAL213,
		VAL214,
		VAL215,
		VAL216,
		VAL217,
		VAL218,
		VAL219,
		VAL220,
		VAL221,
		VAL222,
		VAL223,
		VAL224,
		VAL225,
		VAL226,
		VAL227,
		VAL228,
		VAL229,
		VAL230,
		VAL231,
		VAL232,
		VAL233,
		VAL234,
		VAL235,
		VAL236,
		VAL237,
		VAL238,
		VAL239,
		VAL240,
		VAL241,
		VAL242,
		VAL243,
		VAL244,
		VAL245,
		VAL246,
		VAL247,
		VAL248,
		VAL249,
		VAL250,
		VAL251,
		VAL252,
		VAL253,
		VAL254,
	}

	public enum MyEnumTooBig {
		VAL0,
		VAL1,
		VAL2,
		VAL3,
		VAL4,
		VAL5,
		VAL6,
		VAL7,
		VAL8,
		VAL9,
		VAL10,
		VAL11,
		VAL12,
		VAL13,
		VAL14,
		VAL15,
		VAL16,
		VAL17,
		VAL18,
		VAL19,
		VAL20,
		VAL21,
		VAL22,
		VAL23,
		VAL24,
		VAL25,
		VAL26,
		VAL27,
		VAL28,
		VAL29,
		VAL30,
		VAL31,
		VAL32,
		VAL33,
		VAL34,
		VAL35,
		VAL36,
		VAL37,
		VAL38,
		VAL39,
		VAL40,
		VAL41,
		VAL42,
		VAL43,
		VAL44,
		VAL45,
		VAL46,
		VAL47,
		VAL48,
		VAL49,
		VAL50,
		VAL51,
		VAL52,
		VAL53,
		VAL54,
		VAL55,
		VAL56,
		VAL57,
		VAL58,
		VAL59,
		VAL60,
		VAL61,
		VAL62,
		VAL63,
		VAL64,
		VAL65,
		VAL66,
		VAL67,
		VAL68,
		VAL69,
		VAL70,
		VAL71,
		VAL72,
		VAL73,
		VAL74,
		VAL75,
		VAL76,
		VAL77,
		VAL78,
		VAL79,
		VAL80,
		VAL81,
		VAL82,
		VAL83,
		VAL84,
		VAL85,
		VAL86,
		VAL87,
		VAL88,
		VAL89,
		VAL90,
		VAL91,
		VAL92,
		VAL93,
		VAL94,
		VAL95,
		VAL96,
		VAL97,
		VAL98,
		VAL99,
		VAL100,
		VAL101,
		VAL102,
		VAL103,
		VAL104,
		VAL105,
		VAL106,
		VAL107,
		VAL108,
		VAL109,
		VAL110,
		VAL111,
		VAL112,
		VAL113,
		VAL114,
		VAL115,
		VAL116,
		VAL117,
		VAL118,
		VAL119,
		VAL120,
		VAL121,
		VAL122,
		VAL123,
		VAL124,
		VAL125,
		VAL126,
		VAL127,
		VAL128,
		VAL129,
		VAL130,
		VAL131,
		VAL132,
		VAL133,
		VAL134,
		VAL135,
		VAL136,
		VAL137,
		VAL138,
		VAL139,
		VAL140,
		VAL141,
		VAL142,
		VAL143,
		VAL144,
		VAL145,
		VAL146,
		VAL147,
		VAL148,
		VAL149,
		VAL150,
		VAL151,
		VAL152,
		VAL153,
		VAL154,
		VAL155,
		VAL156,
		VAL157,
		VAL158,
		VAL159,
		VAL160,
		VAL161,
		VAL162,
		VAL163,
		VAL164,
		VAL165,
		VAL166,
		VAL167,
		VAL168,
		VAL169,
		VAL170,
		VAL171,
		VAL172,
		VAL173,
		VAL174,
		VAL175,
		VAL176,
		VAL177,
		VAL178,
		VAL179,
		VAL180,
		VAL181,
		VAL182,
		VAL183,
		VAL184,
		VAL185,
		VAL186,
		VAL187,
		VAL188,
		VAL189,
		VAL190,
		VAL191,
		VAL192,
		VAL193,
		VAL194,
		VAL195,
		VAL196,
		VAL197,
		VAL198,
		VAL199,
		VAL200,
		VAL201,
		VAL202,
		VAL203,
		VAL204,
		VAL205,
		VAL206,
		VAL207,
		VAL208,
		VAL209,
		VAL210,
		VAL211,
		VAL212,
		VAL213,
		VAL214,
		VAL215,
		VAL216,
		VAL217,
		VAL218,
		VAL219,
		VAL220,
		VAL221,
		VAL222,
		VAL223,
		VAL224,
		VAL225,
		VAL226,
		VAL227,
		VAL228,
		VAL229,
		VAL230,
		VAL231,
		VAL232,
		VAL233,
		VAL234,
		VAL235,
		VAL236,
		VAL237,
		VAL238,
		VAL239,
		VAL240,
		VAL241,
		VAL242,
		VAL243,
		VAL244,
		VAL245,
		VAL246,
		VAL247,
		VAL248,
		VAL249,
		VAL250,
		VAL251,
		VAL252,
		VAL253,
		VAL254,
		VAL255,
	}

	@DBAnnotatedObjectInfo(version = 0)
	public static class MyKitchenSink extends DBAnnotatedObject {
		public static final String TABLE_NAME = "SINK";

		public static final String BOOLEAN_COLUMN_NAME = "Boolean";
		public static final String BYTE_COLUMN_NAME = "Byte";
		public static final String ENUM_COLUMN_NAME = "Enum";
		public static final String SHORT_COLUMN_NAME = "Short";
		public static final String INT_COLUMN_NAME = "Int";
		public static final String LONG_COLUMN_NAME = "Long";
		public static final String STRING_COLUMN_NAME = "String";
		public static final String BINARY_COLUMN_NAME = "Binary";

		@DBAnnotatedColumn(BOOLEAN_COLUMN_NAME)
		static DBObjectColumn BOOLEAN_COLUMN;
		@DBAnnotatedColumn(BYTE_COLUMN_NAME)
		static DBObjectColumn BYTE_COLUMN;
		@DBAnnotatedColumn(ENUM_COLUMN_NAME)
		static DBObjectColumn ENUM_COLUMN;
		@DBAnnotatedColumn(SHORT_COLUMN_NAME)
		static DBObjectColumn SHORT_COLUMN;
		@DBAnnotatedColumn(INT_COLUMN_NAME)
		static DBObjectColumn INT_COLUMN;
		@DBAnnotatedColumn(LONG_COLUMN_NAME)
		static DBObjectColumn LONG_COLUMN;
		@DBAnnotatedColumn(STRING_COLUMN_NAME)
		static DBObjectColumn STRING_COLUMN;
		@DBAnnotatedColumn(BINARY_COLUMN_NAME)
		static DBObjectColumn BINARY_COLUMN;

		@DBAnnotatedField(column = BOOLEAN_COLUMN_NAME)
		boolean booleanField;
		@DBAnnotatedField(column = BYTE_COLUMN_NAME)
		byte byteField;
		@DBAnnotatedField(column = ENUM_COLUMN_NAME)
		MyEnum enumField;
		@DBAnnotatedField(column = SHORT_COLUMN_NAME)
		short shortField;
		@DBAnnotatedField(column = INT_COLUMN_NAME)
		int intField;
		@DBAnnotatedField(column = LONG_COLUMN_NAME)
		long longField;
		@DBAnnotatedField(column = STRING_COLUMN_NAME)
		String stringField;
		@DBAnnotatedField(column = BINARY_COLUMN_NAME)
		byte[] binaryField;

		public MyKitchenSink(DBCachedObjectStore<?> store, DBRecord record) {
			super(store, record);
		}
	}

	@Test
	public void testColumnNumbers() throws IOException, VersionException {
		DBHandle handle = new DBHandle();
		MyDomainObject myDO = new MyDomainObject(handle, "Testing", this);
		DBCachedObjectStoreFactory factory = new DBCachedObjectStoreFactory(myDO);
		try (UndoableTransaction trans = UndoableTransaction.start(myDO, "Create Tables", true)) {
			factory.getOrCreateCachedStore(MyObject.TABLE_NAME, MyObject.class, MyObject::new,
				false);
			factory.getOrCreateCachedStore(MyExtObject.TABLE_NAME, MyExtObject.class,
				MyExtObject::new, false);
		}

		assertEquals(0, MyObject.A_COLUMN.columnNumber);
		assertEquals(1, MyObject.C_COLUMN.columnNumber);

		// NOTE: Fields are numbered in declaration order, starting with the superclasses
		assertEquals(0, MyExtObject.A_COLUMN.columnNumber);
		assertEquals(1, MyExtObject.C_COLUMN.columnNumber);
		assertEquals(2, MyExtObject.B_COLUMN.columnNumber);

		myDO.release(this);
	}

	public static abstract class AbstractObject extends DBAnnotatedObject {
		final static String FIELD_COLUMN_NAME = "MyField";

		@DBAnnotatedColumn(FIELD_COLUMN_NAME)
		static DBObjectColumn FIELD_COLUMN;

		public AbstractObject(DBCachedObjectStore<?> store, DBRecord record) {
			super(store, record);
		}
	}

	@DBAnnotatedObjectInfo(version = 0)
	public static class MyFromAbstract extends AbstractObject {
		@DBAnnotatedField(column = FIELD_COLUMN_NAME)
		int myField;

		public MyFromAbstract(DBCachedObjectStore<?> store, DBRecord record) {
			super(store, record);
		}
	}

	@Test
	public void testAbstractColumns() throws IOException, VersionException {
		DBHandle handle = new DBHandle();
		MyDomainObject myDO = new MyDomainObject(handle, "Testing", this);
		DBCachedObjectStoreFactory factory = new DBCachedObjectStoreFactory(myDO);
		try (UndoableTransaction trans = UndoableTransaction.start(myDO, "Create Tables", true)) {
			factory.getOrCreateCachedStore("MyTable", MyFromAbstract.class, MyFromAbstract::new,
				false);
		}
		finally {
			myDO.release(this);
		}

		assertNotNull(AbstractObject.FIELD_COLUMN);
	}

	@Test
	@Ignore("I'm no longer sure this test is correct. See the TODO within.")
	public void testCodecs() throws IOException, VersionException {

		DBHandle handle = new DBHandle();
		MyDomainObject myDO = new MyDomainObject(handle, "Testing", this);
		DBCachedObjectStoreFactory factory = new DBCachedObjectStoreFactory(myDO);
		DBCachedObjectStore<MyKitchenSink> store;
		try (UndoableTransaction trans = UndoableTransaction.start(myDO, "Create Tables", true)) {
			store = factory.getOrCreateCachedStore(MyKitchenSink.TABLE_NAME, MyKitchenSink.class,
				MyKitchenSink::new, false);

			MyKitchenSink objA = store.create(0);
			store.cache.invalidate();
			MyKitchenSink objB = store.getObjectAt(0);

			// TODO: I think this is actually wrong
			assertNotEquals(System.identityHashCode(objA), System.identityHashCode(objB));

			assertEquals(objA.booleanField, objA.booleanField);
			assertEquals(objA.byteField, objB.byteField);
			assertEquals(objA.enumField, objB.enumField);
			assertEquals(objA.shortField, objB.shortField);
			assertEquals(objA.intField, objB.intField);
			assertEquals(objA.longField, objB.longField);
			assertEquals(objA.stringField, objB.stringField);
			assertEquals(objA.binaryField, objB.binaryField);
		}
		myDO.release(this);
	}

	@DBAnnotatedObjectInfo(version = 0)
	public static class MyUsesMyEnumTooBig extends DBAnnotatedObject {
		public static final String TABLE_NAME = "OOPS";

		public static final String ENUM_COLUMN_NAME = "Enum";

		@DBAnnotatedColumn(ENUM_COLUMN_NAME)
		static DBObjectColumn ENUM_COLUMN;

		@DBAnnotatedField(column = ENUM_COLUMN_NAME)
		MyEnumTooBig enumField;

		public MyUsesMyEnumTooBig(DBCachedObjectStore<?> store, DBRecord record) {
			super(store, record);
		}
	}

	@Test
	public void testEnumCodecTooBig() throws IOException, VersionException {
		DBHandle handle = new DBHandle();
		MyDomainObject myDO = new MyDomainObject(handle, "Testing", this);
		DBCachedObjectStoreFactory factory = new DBCachedObjectStoreFactory(myDO);
		try (UndoableTransaction trans = UndoableTransaction.start(myDO, "Create Tables", true)) {
			factory.getOrCreateCachedStore(MyUsesMyEnumTooBig.TABLE_NAME, MyUsesMyEnumTooBig.class,
				MyUsesMyEnumTooBig::new, false);
			fail();
		}
		catch (IllegalArgumentException e) {
			// pass
		}
	}
}
