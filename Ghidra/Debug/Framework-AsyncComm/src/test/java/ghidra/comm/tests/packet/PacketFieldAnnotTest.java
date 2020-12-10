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
package ghidra.comm.tests.packet;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.lang.reflect.Field;
import java.util.*;

import org.junit.Test;

import ghidra.comm.packet.Packet;
import ghidra.comm.packet.annot.*;
import ghidra.comm.packet.annot.TypedByField.TypeSelect;
import ghidra.comm.packet.binary.BinaryPacketCodec;
import ghidra.comm.packet.err.*;
import ghidra.comm.packet.fields.PacketField;

public class PacketFieldAnnotTest {
	protected void expectOrder(Class<? extends Packet> cls, String... names)
			throws NoSuchFieldException, SecurityException, FieldOrderingException {
		List<Field> expected = new ArrayList<>();

		for (String name : names) {
			expected.add(cls.getField(name));
		}
		assertEquals(expected, Packet.getFields(cls));
	}

	public static class TestMessageBase extends Packet {
		@PacketField
		public int field1;

		@PacketField
		public int field2;

		public int notAField;
	}

	public static class TestMessageBase2 extends Packet {
		@PacketField
		public int field2;

		@PacketField
		public int field1;
	}

	public static class TestMessageExtM extends TestMessageBase {
		@PacketField(after = "field1", before = "field2")
		public String field1dot5;
	}

	@Test
	public void testGoodFieldOrders()
			throws NoSuchFieldException, SecurityException, FieldOrderingException {
		expectOrder(TestMessageBase.class, "field1", "field2");
		expectOrder(TestMessageBase2.class, "field2", "field1");
		expectOrder(TestMessageExtM.class, "field1", "field1dot5", "field2");
	}

	public static class TestMessageOrderCirc extends TestMessageBase {
		@PacketField(after = "field2", before = "field1")
		public String fieldCirc;
	}

	@Test
	public void testCircularOrder() throws NoSuchFieldException, SecurityException {
		try {
			expectOrder(TestMessageOrderCirc.class);
			fail();
		}
		catch (FieldOrderingException e) {
			if (!e.getCause().getMessage().contains("cyclic")) {
				fail(e.getMessage());
			}
			// pass
		}
	}

	public static class TestMessageExtU extends TestMessageBase {
		@PacketField
		public String fieldUnordered;
	}

	@Test
	public void testNotTotalOrder() throws NoSuchFieldException, SecurityException {
		try {
			expectOrder(TestMessageExtU.class);
			fail();
		}
		catch (FieldOrderingException e) {
			if (!e.getCause().getMessage().contains("total")) {
				fail(e.getMessage());
			}
			// pass
		}
	}

	public static class TestMessageExtAdvA extends TestMessageBase {
		@PacketField(after = "field2")
		public int field3;

		@PacketField
		public int field4;
	}

	public static class TestMessageExtAdvM extends TestMessageBase {
		@PacketField(after = "field1", before = "field2")
		public int field1dot3;

		@PacketField
		public int field1dot6;
	}

	@Test
	public void testAdvancedOrdering()
			throws NoSuchFieldException, SecurityException, FieldOrderingException {
		expectOrder(TestMessageExtAdvA.class, "field1", "field2", "field3", "field4");
		expectOrder(TestMessageExtAdvM.class, "field1", "field1dot3", "field1dot6", "field2");
	}

	public static class TestMessageAccessDefault extends Packet {
		@PacketField
		int forgotPublic;
	}

	public static class TestMessageStaticNotFinal extends Packet {
		@PacketField
		public static int forgotFinal;
	}

	@Test
	public void testForgotMods() throws FieldOrderingException {
		try {
			BinaryPacketCodec.getInstance().registerPacketType(TestMessageAccessDefault.class);
			fail();
		}
		catch (InvalidFieldModifiersException e) {
			// pass
		}

		try {
			BinaryPacketCodec.getInstance().registerPacketType(TestMessageStaticNotFinal.class);
			fail();
		}
		catch (InvalidFieldModifiersException e) {
			// pass
		}
	}

	public static class TestMessageNoSuchField extends Packet {
		@PacketField
		@SizedByField("nosuch")
		public byte[] data;
	}

	public static class TestMessageNotPacketField extends Packet {
		public int notfield;

		@PacketField
		@SizedByField("notfield")
		public byte[] data;
	}

	@Test
	public void testNoSuchField() throws FieldOrderingException {
		try {
			BinaryPacketCodec.getInstance().registerPacketType(TestMessageNoSuchField.class);
			fail();
		}
		catch (InvalidFieldNameException e) {
			// pass
		}
	}

	@Test
	public void testNotPacketField() throws FieldOrderingException {
		try {
			BinaryPacketCodec.getInstance().registerPacketType(TestMessageNotPacketField.class);
			fail();
		}
		catch (InvalidFieldNameException e) {
			// pass
		}
	}

	public static class TestMessageTypeNotExtension extends Packet {
		@PacketField
		public int type;

		@PacketField
		@TypedByField(by = "type", types = { // 
			@TypeSelect(key = 1, type = String.class),//
			@TypeSelect(key = 2, type = Integer.class) })
		public Number num;
	}

	@Test
	public void testTypeNotExtension() throws FieldOrderingException {
		try {
			BinaryPacketCodec.getInstance().registerPacketType(TestMessageTypeNotExtension.class);
			fail();
		}
		catch (PacketAnnotationException e) {
			// pass
		}
	}

	public static class TestMessageCountProceedsField extends Packet {
		@PacketField
		@CountedByField("count")
		public byte[] data;

		@PacketField
		public int count;
	}

	@Test
	public void testCountProceedsField() {
		try {
			BinaryPacketCodec.getInstance().registerPacketType(TestMessageCountProceedsField.class);
			fail();
		}
		catch (AnnotatedFieldOrderingException e) {
			// pass
		}
	}

	public static class TestMessageSizeProceedsField extends Packet {
		@PacketField
		@SizedByField("size")
		public byte[] data;

		@PacketField
		public int size;
	}

	@Test
	public void testSizeProceedsField() {
		try {
			BinaryPacketCodec.getInstance().registerPacketType(TestMessageSizeProceedsField.class);
			fail();
		}
		catch (AnnotatedFieldOrderingException e) {
			// pass
		}
	}

	public static class TestMessageTypeProceedsField extends Packet {
		@PacketField
		@TypedByField(by = "type", types = { //
			@TypeSelect(key = 1, type = String.class) })
		public Object data;

		@PacketField
		public int type;
	}

	@Test
	public void testTypeProceedsField() {
		try {
			BinaryPacketCodec.getInstance().registerPacketType(TestMessageTypeProceedsField.class);
			fail();
		}
		catch (AnnotatedFieldOrderingException e) {
			// pass
		}
	}

	public static class TestMessageTypeNoMap extends Packet {
		@PacketField
		public int type;

		@PacketField
		@TypedByField(by = "type", types = {})
		public Object[] data;
	}

	@Test
	public void testTypeNoMap() throws FieldOrderingException {
		try {
			BinaryPacketCodec.getInstance().registerPacketType(TestMessageTypeNoMap.class);
			fail();
		}
		catch (PacketAnnotationException e) {
			if (!(e.getAnnotation().annotationType() == TypedByField.class)) {
				fail();
			}
			// pass
		}
	}

	public static class TestMessageColNoRepAnnot extends Packet {
		@PacketField
		public Collection<Object> col;
	}

	@Test
	public void testColNoRepAnnot() {
		try {
			BinaryPacketCodec.getInstance().registerPacketType(TestMessageColNoRepAnnot.class);
			fail();
		}
		catch (PacketDeclarationException e) {
			// pass
		}
	}

	public static class TestMessageStaticFinalInherit extends Packet {
		public TestMessageStaticFinalInherit() {
		}

		@PacketField
		public static final String A = "A";
	}

	public static class TestSubMessageStaticFinalInherit extends TestMessageStaticFinalInherit {
		@PacketField(after = "A")
		public String f2;
	}

	@Test
	public void testStaticFinalInherit() {
		List<Field> fields = Packet.getFields(TestSubMessageStaticFinalInherit.class);
		assertEquals(2, fields.size());
		assertEquals("A", fields.get(0).getName());
		assertEquals("f2", fields.get(1).getName());
	}
}
