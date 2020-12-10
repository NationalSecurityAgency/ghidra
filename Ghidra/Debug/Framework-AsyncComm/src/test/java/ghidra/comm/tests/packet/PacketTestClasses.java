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

import java.lang.reflect.InvocationTargetException;
import java.util.*;

import ghidra.comm.packet.*;
import ghidra.comm.packet.annot.*;
import ghidra.comm.packet.annot.TypedByField.TypeSelect;
import ghidra.comm.packet.annot.WithFlag.Mode;
import ghidra.comm.packet.binary.NullTerminated;
import ghidra.comm.packet.binary.ReverseByteOrder;
import ghidra.comm.packet.fields.PacketField;
import ghidra.comm.packet.string.*;
import ghidra.comm.packet.string.SizeRestricted.PadDirection;
import ghidra.comm.util.BitmaskSet;
import ghidra.comm.util.BitmaskUniverse;

public interface PacketTestClasses {
	public static class TestMessageFlatTypes extends Packet {
		public TestMessageFlatTypes() {
		}

		public TestMessageFlatTypes(boolean f1, byte f2, char f3, short f4, int f5, long f6,
				String f7, float f8, double f9) {
			this.f1 = f1;
			this.f2 = f2;
			this.f3 = f3;
			this.f4 = f4;
			this.f5 = f5;
			this.f6 = f6;
			this.f7 = f7;
			this.f8 = f8;
			this.f9 = f9;
		}

		@PacketField
		@RegexTerminated(exp = ",", tok = ",")
		public boolean f1;

		@PacketField
		@RegexTerminated(exp = ",", tok = ",")
		public byte f2;

		@PacketField
		@RegexTerminated(exp = ",", tok = ",")
		public char f3;

		@PacketField
		@RegexTerminated(exp = ",", tok = ",")
		public short f4;

		@PacketField
		@RegexTerminated(exp = ",", tok = ",")
		@WithRadix(10)
		public int f5;

		@PacketField
		@RegexTerminated(exp = ",", tok = ",")
		public long f6;

		@PacketField
		@NullTerminated
		@RegexTerminated(exp = ",", tok = ",")
		public String f7;

		@PacketField
		@RegexTerminated(exp = ",", tok = ",")
		public float f8;

		@PacketField
		@WithRadix(16)
		public double f9;
	}

	public static class TestMessageFlatMixedEndian extends Packet {
		public TestMessageFlatMixedEndian() {
		}

		public TestMessageFlatMixedEndian(char f1, char f2, int f3, int f4, String f5, String f6,
				long f7, long f8, float f9, float f10, double f11, double f12) {
			this.f1 = f1;
			this.f2 = f2;
			this.f3 = f3;
			this.f4 = f4;
			this.f5 = f5;
			this.f6 = f6;
			this.f7 = f7;
			this.f8 = f8;
			this.f9 = f9;
			this.f10 = f10;
			this.f11 = f11;
			this.f12 = f12;
		}

		@PacketField
		@RegexTerminated(exp = ",", tok = ",")
		public char f1;

		@PacketField
		@ReverseByteOrder
		@RegexTerminated(exp = ",", tok = ",")
		public char f2;

		@PacketField
		@RegexTerminated(exp = ",", tok = ",")
		public int f3;

		@PacketField
		@ReverseByteOrder
		@RegexTerminated(exp = ",", tok = ",")
		public int f4;

		@PacketField
		@NullTerminated
		@RegexTerminated(exp = ",", tok = ",")
		public String f5;

		@PacketField
		@NullTerminated(2)
		@RegexTerminated(exp = "\\s+", tok = " ")
		public String f6;

		@PacketField
		@RegexTerminated(exp = ",", tok = ",")
		public long f7;

		@PacketField
		@ReverseByteOrder
		@RegexTerminated(exp = ",", tok = ",")
		public long f8;

		@PacketField
		@RegexTerminated(exp = ",", tok = ",")
		@WithRadix(10)
		public float f9;

		@PacketField
		@ReverseByteOrder
		@RegexTerminated(exp = ",", tok = ",")
		@WithRadix(10)
		public float f10;

		@PacketField
		@RegexTerminated(exp = ",", tok = ",")
		@WithRadix(10)
		public double f11;

		@PacketField
		@ReverseByteOrder
		@WithRadix(10)
		public double f12;
	}

	public static class TestMessageSizedString extends Packet {
		public TestMessageSizedString() {
		}

		public TestMessageSizedString(String str, int more) {
			this.str = str;
			this.more = more;
		}

		@PacketField
		@RegexTerminated(exp = ",", tok = ",")
		public int len;

		@PacketField
		@SizedByField("len")
		public String str;

		@PacketField
		public int more;
	}

	public static class TestMessageMethodSizedString extends Packet {
		public TestMessageMethodSizedString() {
		}

		public TestMessageMethodSizedString(String str) {
			this.str = str;
		}

		@PacketField
		@RegexTerminated(exp = ",", tok = ",")
		public int len;

		public int getLen() {
			return len - 4;
		}

		public void setLen(int len) {
			this.len = len + 4;
		}

		@PacketField
		@SizedByMethods(getter = "getLen", setter = "setLen", modifies = "len")
		public String str;
	}

	public static class TestMessageCountedShortArray extends Packet {
		public TestMessageCountedShortArray() {
		}

		public TestMessageCountedShortArray(int more, short... arr) {
			this.arr = arr;
			this.more = more;
		}

		@PacketField
		@RegexTerminated(exp = ",", tok = ",")
		public int count;

		@PacketField
		@ReverseByteOrder
		@RepeatedField
		@RegexSeparated(exp = ",", tok = ",")
		@CountedByField(value = "count")
		@RegexTerminated(exp = ";", tok = ";")
		public short[] arr;

		@PacketField
		@WithRadix(16)
		public int more;
	}

	public static class TestMessageDynamicTypedSubs extends Packet {
		public static abstract class SubTestMessageType extends Packet {
			// Placeholder
		}

		public TestMessageDynamicTypedSubs() {
		}

		public TestMessageDynamicTypedSubs(SubTestMessageType sub) {
			this.sub = sub;
		}

		public static class IntTestMessage extends SubTestMessageType {
			public IntTestMessage() {
			}

			public IntTestMessage(int val) {
				this.val = val;
			}

			@PacketField
			public int val;
		}

		public static class LongTestMessage extends SubTestMessageType {
			public LongTestMessage() {
			}

			public LongTestMessage(long val) {
				this.val = val;
			}

			@PacketField
			public long val;
		}

		@PacketField
		@RegexTerminated(exp = ",", tok = ",")
		public int type;

		@PacketField
		@TypedByField(by = "type", types = { //
			@TypeSelect(key = 1, type = IntTestMessage.class), //
			@TypeSelect(key = 2, type = LongTestMessage.class) })
		public SubTestMessageType sub;
	}

	public static class TestMessageDynamicTyped extends Packet {
		public TestMessageDynamicTyped() {
		}

		public TestMessageDynamicTyped(Number num) {
			this.num = num;
		}

		@PacketField
		@RegexTerminated(exp = ",", tok = ",")
		public int type;

		@PacketField
		@TypedByField(by = "type", types = { //
			@TypeSelect(key = 1, type = Integer.class), //
			@TypeSelect(key = 2, type = Long.class) })
		public Number num;
	}

	public static class TestMessageUnmeasuredCollection extends Packet {
		public static class TestElement extends Packet {
			public TestElement() {
			}

			public TestElement(Object val) {
				this.val = val;
			}

			@PacketField
			@RegexTerminated(exp = ",", tok = ",")
			public byte type;

			@PacketField
			@RegexTerminated(exp = ",", tok = ",")
			public short len;

			@PacketField
			@SizedByField("len")
			@TypedByField(by = "type", types = { //
				@TypeSelect(key = 1, type = Integer.class), //
				@TypeSelect(key = 2, type = String.class) })
			public Object val;
		}

		public TestMessageUnmeasuredCollection() {
		}

		public TestMessageUnmeasuredCollection(Object... items) {
			this.col = new ArrayList<>();
			for (Object o : items) {
				this.col.add(new TestElement(o));
			}
		}

		@PacketField
		@RepeatedField(container = ArrayList.class, elements = TestMessageUnmeasuredCollection.TestElement.class)
		public Collection<TestMessageUnmeasuredCollection.TestElement> col;
	}

	public static class TestMessageFullSpecColField extends Packet {
		public static class IntList extends ArrayList<Integer> {
			// Placeholder
		}

		public TestMessageFullSpecColField() {
		}

		public TestMessageFullSpecColField(int... nums) {
			col = new IntList();
			for (int n : nums) {
				col.add(n);
			}
		}

		@PacketField
		@RepeatedField
		@RegexSeparated(exp = ",", tok = ",")
		public IntList col;
	}

	public static class TestMessageLookahead extends Packet {
		public static abstract class SubTestMessageLookahead extends Packet {
			// Placeholder
		}

		public static class IntTestMessage extends SubTestMessageLookahead {
			public IntTestMessage() {
			}

			public IntTestMessage(int val) {
				this.val = val;
			}

			@PacketField
			public static final String INT = "Int";

			@PacketField
			public int val;
		}

		public static class LongTestMessage extends SubTestMessageLookahead {
			public LongTestMessage() {
			}

			public LongTestMessage(long val) {
				this.val = val;
			}

			@PacketField
			public static final String LONG = "Long";

			@PacketField
			public long val;
		}

		public TestMessageLookahead() {
		}

		public TestMessageLookahead(int val) {
			this.dyn = new IntTestMessage(val);
		}

		public TestMessageLookahead(long val) {
			this.dyn = new LongTestMessage(val);
		}

		@PacketField
		@TypedByLookahead({ IntTestMessage.class, LongTestMessage.class })
		public SubTestMessageLookahead dyn;
	}

	public static class TestMessageDoubleTermed extends Packet {
		public TestMessageDoubleTermed() {
		}

		public TestMessageDoubleTermed(String str) {
			this.str = str;
		}

		@PacketField
		@RegexTerminated(exp = ",", tok = ",")
		public int len;

		@PacketField
		@NullTerminated
		@RegexTerminated(exp = ",", tok = ",")
		@SizedByField(value = "len", adjust = 1)
		public String str;
	}

	public static class TestMessageFixedSize extends Packet {
		public TestMessageFixedSize() {
		}

		public TestMessageFixedSize(int... vals) {
			this.vals = vals;
		}

		@PacketField
		@SizeRestricted(direction = PadDirection.LEFT, pad = '0', value = 8)
		@WithRadix(16)
		@RepeatedField
		public int[] vals;
	}

	public static class TestMessageOptional extends Packet {
		public TestMessageOptional() {
		}

		public TestMessageOptional(String f1) {
			this.f1 = f1;
		}

		public TestMessageOptional(String f1, int opt) {
			this.f1 = f1;
			this.opt = opt;
		}

		@PacketField
		@RegexTerminated(exp = ";", tok = ";", cond = "opt")
		@NullTerminated(cond = "opt")
		public String f1;

		@PacketField
		@OptionalField
		public Integer opt;
	}

	public static class TestMessageEnum extends Packet {
		public static enum TestEnum {
			OFF, ON, ONE, TWO, THREE;
		}

		public TestMessageEnum() {
		}

		public TestMessageEnum(TestEnum mode, int val) {
			this.mode = mode;
			this.val = val;
		}

		@PacketField
		public TestEnum mode;

		@PacketField
		public int val;
	}

	public static class TestMessageHexString extends Packet {
		public TestMessageHexString() {
		}

		public TestMessageHexString(String encstr) {
			this.encstr = encstr;
		}

		@PacketField
		@SizeRestricted(direction = PadDirection.LEFT, pad = '0', value = 2)
		@WithRadix(16)
		@RepeatedField
		@EncodeChars("UTF-8")
		public String encstr;
	}

	public static class TestMessageEmpty extends Packet {
		// Intentionally empty
	}

	public static abstract class AbstractTestNumber extends Packet {
		public abstract long getLongValue();

		public abstract void setLongValue(long val);
	}

	public static class LongTestNumber extends AbstractTestNumber {
		@PacketField
		public long val;

		public LongTestNumber() {
		}

		public LongTestNumber(long val) {
			this.val = val;
		}

		@Override
		public long getLongValue() {
			return val;
		}

		@Override
		public void setLongValue(long val) {
			this.val = val;
		}
	}

	public static class IntTestNumber extends AbstractTestNumber {
		@PacketField
		public int val;

		public IntTestNumber() {
		}

		public IntTestNumber(int val) {
			this.val = val;
		}

		@Override
		public long getLongValue() {
			return val;
		}

		@Override
		public void setLongValue(long val) {
			this.val = (int) val;
		}
	}

	static final PacketFactory LONG_TEST_NUMBER_FACTORY = new AbstractPacketFactory() {
		@SuppressWarnings("unchecked")
		@Override
		public <P extends Packet> P newPacket(Class<P> pktType)
				throws InstantiationException, IllegalAccessException, IllegalArgumentException,
				InvocationTargetException, NoSuchMethodException, SecurityException {
			if (pktType == AbstractTestNumber.class) {
				return (P) new LongTestNumber();
			}
			return super.newPacket(pktType);
		}

		@Override
		public void registerTypes(PacketCodec<?> codec) {
			codec.registerPacketType(LongTestNumber.class);
		}
	};

	static final PacketFactory INT_TEST_NUMBER_FACTORY = new AbstractPacketFactory() {
		@SuppressWarnings("unchecked")
		@Override
		public <P extends Packet> P newPacket(Class<P> pktType)
				throws InstantiationException, IllegalAccessException, IllegalArgumentException,
				InvocationTargetException, NoSuchMethodException, SecurityException {
			if (pktType == AbstractTestNumber.class) {
				return (P) new IntTestNumber();
			}
			return super.newPacket(pktType);
		}

		@Override
		public void registerTypes(PacketCodec<?> codec) {
			codec.registerPacketType(IntTestNumber.class);
		}
	};

	public static class TestMessageAbstractTestNumber extends Packet {
		public TestMessageAbstractTestNumber() {
		}

		@SafeVarargs
		public TestMessageAbstractTestNumber(int follows, AbstractTestNumber... numbers) {
			this.numbers = Arrays.asList(numbers);
			this.follows = follows;
		}

		@PacketField
		public int count;

		@PacketField
		@RepeatedField
		@CountedByField("count")
		public List<AbstractTestNumber> numbers;

		@PacketField
		public int follows;
	}

	public static class TestMessageTypedByMap extends Packet {
		public enum TestEnum {
			A, B;
		}

		public static final Map<TestEnum, Class<? extends TestSubByMap>> ENUM_MAP =
			typeMap(TestEnum.class, TestSubByMap.class) //
					.put(TestEnum.A, TestASubByMap.class) //
					.put(TestEnum.B, TestBSubByMap.class) //
					.build();

		public abstract static class TestSubByMap extends Packet {
			// Placeholder
		}

		public static class TestASubByMap extends TestSubByMap {
			public TestASubByMap() {
			}

			public TestASubByMap(int val) {
				this.val = val;
			}

			@PacketField
			public int val;
		}

		public static class TestBSubByMap extends TestSubByMap {
			public TestBSubByMap() {
			}

			public TestBSubByMap(long val) {
				this.val = val;
			}

			@PacketField
			public long val;
		}

		public TestMessageTypedByMap() {
		}

		public TestMessageTypedByMap(TestSubByMap sub) {
			this.sub = sub;
		}

		@PacketField
		public TestEnum type;

		@PacketField
		@TypedByField(by = "type", map = "ENUM_MAP")
		public TestSubByMap sub;
	}

	public static class TestMessageFlags extends Packet {
		public enum TestFlags implements BitmaskUniverse {
			FIRST(1 << 0), SECOND(1 << 1);

			private final long mask;

			TestFlags(long mask) {
				this.mask = mask;
			}

			@Override
			public long getMask() {
				return mask;
			}
		}

		public TestMessageFlags() {
			this(null, null);
		}

		public TestMessageFlags(Long first) {
			this(first, null);
		}

		public TestMessageFlags(Integer second) {
			this(null, second);
		}

		public TestMessageFlags(Long first, Integer second) {
			this.first = first;
			this.second = second;
		}

		@PacketField
		@BitmaskEncoded(universe = TestFlags.class, type = Byte.class)
		public BitmaskSet<TestFlags> flags;

		@PacketField
		@WithFlag(by = "flags", flag = "FIRST")
		public Long first;

		@PacketField
		@WithFlag(by = "flags", flag = "SECOND", mode = Mode.ABSENT)
		public Integer second;
	}
}
