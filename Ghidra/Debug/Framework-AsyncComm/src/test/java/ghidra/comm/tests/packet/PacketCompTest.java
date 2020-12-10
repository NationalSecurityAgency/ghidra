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

import static org.junit.Assert.*;

import java.util.ArrayList;
import java.util.List;

import org.junit.Test;

import ghidra.comm.packet.Packet;
import ghidra.comm.packet.fields.PacketField;

public class PacketCompTest {
	public static class TestMessage extends Packet {
		@PacketField
		public int f1;

		@PacketField
		public TestSubMessage f2;

		@PacketField
		public TestSubMessage[] f3;

		@PacketField
		public short[] f4;

		@PacketField
		public List<TestSubMessage> f5;

		public int notafield;
	}

	public static class TestSubMessage extends Packet {
		@PacketField
		public float fA;

		@PacketField
		public String fB;

		@PacketField
		public String fC;

		public int alsonotfield;
	}

	protected TestMessage getExpPacket() {
		TestMessage msg = new TestMessage();
		msg.f1 = 5;
		msg.f2 = new TestSubMessage();
		msg.f2.fA = 7.0f;
		msg.f2.fB = "Copy";
		msg.f3 = new TestSubMessage[] { new TestSubMessage(), null };
		msg.f3[0].fB = "Elem0";
		msg.f4 = new short[] { (short) 3, (short) 4 };
		msg.f5 = new ArrayList<>();
		msg.f5.add(new TestSubMessage());
		msg.f5.add(null);
		msg.f5.get(0).fC = "ListElem0";
		msg.notafield = 1;
		msg.f2.alsonotfield = 2;

		return msg;
	}

	@Test
	public void testCopy() {
		TestMessage msg = getExpPacket();
		TestMessage cpy = msg.copy();

		assertEquals(5, cpy.f1);
		assertEquals(7.0f, cpy.f2.fA, 0.0);
		assertEquals("Copy", cpy.f2.fB);
		assertEquals(null, cpy.f2.fC);
		assertEquals("Elem0", cpy.f3[0].fB);
		assertEquals(null, cpy.f3[1]);
		assertEquals((short) 3, cpy.f4[0]);
		assertEquals((short) 4, cpy.f4[1]);
		assertEquals("ListElem0", cpy.f5.get(0).fC);
		assertEquals(null, cpy.f5.get(1));
		assertEquals(0, cpy.notafield);
		assertEquals(0, cpy.f2.alsonotfield);

		// Verify a deep copy
		cpy.f3[0].fB = "Clobber";
		assertEquals("Elem0", msg.f3[0].fB);
		cpy.f5.get(0).fC = "Clobber";
		assertEquals("ListElem0", msg.f5.get(0).fC);
	}

	@Test
	public void testToString() {
		TestMessage msg = getExpPacket();
		TestMessage cpy = getExpPacket();

		assertEquals(msg.toString(), cpy.toString());

		cpy.f3[0].fB = "Clobber";
		assertFalse(msg.toString().equals(cpy.toString()));
	}

	@Test
	public void testHashCode() {
		TestMessage msg = getExpPacket();
		TestMessage cpy = getExpPacket();
		int msgHash = msg.hashCode();

		assertEquals(msgHash, cpy.hashCode());

		cpy.f3[0].fB = "Clobber";
		assertFalse(msgHash == cpy.hashCode());
	}

	@Test
	public void testEquality() {
		TestMessage msg = getExpPacket();
		TestMessage cpy = getExpPacket();

		assertEquals(msg, cpy);

		cpy.f3[0].fB = "Clobber";
		assertFalse(msg.equals(cpy));
	}

	@Test
	public void testCompare() {
		TestMessage msg = getExpPacket();
		TestMessage cpy = getExpPacket();

		assertEquals(0, msg.compareTo(cpy));

		cpy.f2 = null;
		assertTrue(msg.compareTo(cpy) > 0);
		cpy = getExpPacket();

		cpy.f3[0].fB = "Clobber";
		assertTrue(msg.compareTo(cpy) > 0);

		cpy.f3[0].fB = "FollowsElem0";
		assertTrue(msg.compareTo(cpy) < 0);

		cpy.f3[0].fB = "Elem0";
		assertEquals(0, msg.compareTo(cpy));
	}
}
