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
package ghidra.pcode.emu.jit.analysis;

import java.util.*;

import org.objectweb.asm.Opcodes;

import ghidra.lifecycle.Unfinished;
import ghidra.pcode.emu.jit.gen.opnd.Opnd;
import ghidra.pcode.emu.jit.gen.opnd.SimpleOpnd;
import ghidra.pcode.emu.jit.gen.util.Types;
import ghidra.pcode.emu.jit.gen.util.Types.*;

/**
 * The p-code type of an operand.
 * 
 * <p>
 * A type is an integer of floating-point value of a specific size in bytes. All values and
 * variables in p-code are just bit vectors. The operators interpret those vectors according to a
 * {@link JitTypeBehavior}. While types only technically belong to the operands, we also talk about
 * values, variables, and varnodes being assigned types, so that we can allocate suitable JVM
 * locals.
 */
public interface JitType {

	/**
	 * Get the smallest type to which both of the given types can be converted without loss.
	 * <p>
	 * When the given types are a mix of integral and floating-point, this chooses an integral type
	 * whose size is the greater of the two.
	 * 
	 * @param a the first type
	 * @param b the second type
	 * @return the uniform type
	 */
	static JitType unify(JitType a, JitType b) {
		if (a == b) {
			return a;
		}
		int size = Math.max(a.size(), b.size());
		return JitTypeBehavior.INTEGER.type(size);
	}

	/**
	 * Similar to {@link #unify(JitType, JitType)}, except that it takes the lesser size.
	 * <p>
	 * This is used when culling of unnecessary loads is desired and loss of precision is
	 * acceptable.
	 * 
	 * @param a the first type
	 * @param b the second type
	 * @return the uniform type
	 */
	static JitType unifyLeast(JitType a, JitType b) {
		if (a == b) {
			return a;
		}
		int size = Math.min(a.size(), b.size());
		return JitTypeBehavior.INTEGER.type(size);
	}

	/**
	 * Compare two types by preference. The type with the more preferred behavior then smaller size
	 * is preferred.
	 * 
	 * @param t1 the first type
	 * @param t2 the second type
	 * @return as in {@link Comparator#compare(Object, Object)}
	 */
	static int compare(JitType t1, JitType t2) {
		int c;
		c = Integer.compare(t1.pref(), t2.pref());
		if (c != 0) {
			return c;
		}
		c = Integer.compare(t1.size(), t2.size());
		if (c != 0) {
			return c;
		}
		return 0;
	}

	/**
	 * Identify the p-code type that is exactly represented by the given JVM type.
	 * 
	 * <p>
	 * This is used during Direct userop invocation to convert the arguments and return value.
	 * 
	 * @param cls the primitive class (not boxed)
	 * @return the p-code type
	 * @see JitDataFlowUseropLibrary
	 */
	public static JitType forJavaType(Class<?> cls) {
		return SimpleJitType.forJavaType(cls);
	}

	/**
	 * A type comprising of legs, each of simple type
	 * 
	 * @param <T> the JVM type of each leg
	 * @param <LT> the p-code type of each leg
	 */
	public interface LeggedJitType<T extends BPrim<?>, LT extends SimpleJitType<T, LT>>
			extends JitType {

		@Override
		List<? extends LT> legTypesBE();

		/**
		 * Cast the given operand's legs as having this type's leg type.
		 * <p>
		 * This is (sadly) necessary because of the loss of type information in {@link Opnd} when it
		 * has a legged type.
		 * 
		 * @param opnd the operand whose legs to cast
		 * @return the legs in little-endian order.
		 */
		@SuppressWarnings({ "rawtypes", "unchecked" })
		default List<SimpleOpnd<T, LT>> castLegsLE(Opnd<? extends LeggedJitType<?, ?>> opnd) {
			return (List) opnd.legsLE();
		}
	}

	/**
	 * A p-code type that can be represented in a single JVM variable.
	 * 
	 * @param <T> the JVM type for this JIT type
	 * @param <JT> this JIT type (recursive)
	 */
	public interface SimpleJitType<T extends BPrim<?>, JT extends SimpleJitType<T, JT>>
			extends LeggedJitType<T, JT> {

		/**
		 * Identify the p-code type that is exactly represented by the given JVM type.
		 * 
		 * <p>
		 * This is used during Direct userop invocation to convert the arguments and return value.
		 * 
		 * @param cls the primitive class (not boxed)
		 * @return the p-code type
		 * @see JitDataFlowUseropLibrary
		 */
		@SuppressWarnings("unchecked")
		public static <T extends BPrim<?>, JT extends SimpleJitType<T, JT>> JT forJavaType(
				Class<?> cls) {
			if (cls == boolean.class) {
				return (JT) IntJitType.I1;
			}
			if (cls == byte.class) {
				return (JT) IntJitType.I1;
			}
			if (cls == short.class) {
				return (JT) IntJitType.I2;
			}
			if (cls == int.class) {
				return (JT) IntJitType.I4;
			}
			if (cls == long.class) {
				return (JT) LongJitType.I8;
			}
			if (cls == float.class) {
				return (JT) FloatJitType.F4;
			}
			if (cls == double.class) {
				return (JT) DoubleJitType.F8;
			}
			throw new IllegalArgumentException();
		}

		/**
		 * The JVM type of the variable that can represent a p-code variable of this type
		 * 
		 * @return the primitive type (not boxed)
		 */
		T bType();

		/**
		 * Re-apply the {@link JitTypeBehavior#INTEGER integer} behavior to this type
		 * 
		 * <p>
		 * This may be slightly faster than {@code JitTypeBehavior.INTEGER.resolve(this)}, because
		 * each type can pick its int type directly, and integer types can just return {@code this}.
		 * 
		 * @return this type as an int
		 */
		SimpleJitType<?, ?> asInt();

		@Override
		SimpleJitType<T, JT> ext();
	}

	/**
	 * The p-code types for integers of size 1 through 4, i.e., that fit in a JVM int.
	 * 
	 * @param size the size in bytes
	 */
	public record IntJitType(int size) implements SimpleJitType<TInt, IntJitType> {
		/** {@code int1}: a 1-byte integer */
		public static final IntJitType I1 = new IntJitType(1);
		/** {@code int2}: a 2-byte integer */
		public static final IntJitType I2 = new IntJitType(2);
		/** {@code int3}: a 3-byte integer */
		public static final IntJitType I3 = new IntJitType(3);
		/** {@code int4}: a 4-byte integer */
		public static final IntJitType I4 = new IntJitType(4);

		/**
		 * Get the type for an integer of the given size 1 through 4
		 * 
		 * @param size the size in bytes
		 * @return the type
		 * @throws IllegalArgumentException for any size <em>not</em> 1 through 4
		 */
		public static IntJitType forSize(int size) {
			return switch (size) {
				case 1 -> I1;
				case 2 -> I2;
				case 3 -> I3;
				case 4 -> I4;
				default -> throw new IllegalArgumentException("size:" + size);
			};
		}

		/**
		 * Compact constructor to check the size
		 * 
		 * @param size the size in bytes
		 */
		public IntJitType {
			assert 0 < size && size <= Integer.BYTES;
		}

		@Override
		public int pref() {
			return 0;
		}

		@Override
		public String nm() {
			return "i";
		}

		@Override
		public TInt bType() {
			return Types.T_INT;
		}

		@Override
		public IntJitType ext() {
			return I4;
		}

		@Override
		public IntJitType asInt() {
			return this;
		}

		@Override
		public List<IntJitType> legTypesBE() {
			return List.of(this);
		}

		@Override
		public List<IntJitType> legTypesLE() {
			return List.of(this);
		}
	}

	/**
	 * The p-code types for integers of size 5 through 8, i.e., that fit in a JVM long.
	 * 
	 * @param size the size in bytes
	 */
	public record LongJitType(int size) implements SimpleJitType<TLong, LongJitType> {
		/** {@code int5}: a 5-byte integer */
		public static final LongJitType I5 = new LongJitType(5);
		/** {@code int6}: a 6-byte integer */
		public static final LongJitType I6 = new LongJitType(6);
		/** {@code int7}: a 7-byte integer */
		public static final LongJitType I7 = new LongJitType(7);
		/** {@code int8}: a 8-byte integer */
		public static final LongJitType I8 = new LongJitType(8);

		// These are needed only as intermediates during conversion
		public static final LongJitType I1 = new LongJitType(1);
		public static final LongJitType I2 = new LongJitType(2);
		public static final LongJitType I3 = new LongJitType(3);
		public static final LongJitType I4 = new LongJitType(4);

		/**
		 * Get the type for an integer of the given size 5 through 8
		 * 
		 * @param size the size in bytes
		 * @return the type
		 * @throws IllegalArgumentException for any size <em>not</em> 5 through 8
		 */
		public static LongJitType forSize(int size) {
			return switch (size) {
				case 5 -> I5;
				case 6 -> I6;
				case 7 -> I7;
				case 8 -> I8;
				// For intermediate conversion only
				case 1 -> I1;
				case 2 -> I2;
				case 3 -> I3;
				case 4 -> I4;
				default -> throw new IllegalArgumentException("size:" + size);
			};
		}

		/**
		 * Compact constructor to check the size
		 * 
		 * @param size the size in bytes
		 */
		public LongJitType {
			assert 0 < size && size <= Long.BYTES;
		}

		@Override
		public int pref() {
			return 1;
		}

		@Override
		public String nm() {
			return "l";
		}

		@Override
		public TLong bType() {
			return Types.T_LONG;
		}

		@Override
		public LongJitType ext() {
			return I8;
		}

		@Override
		public LongJitType asInt() {
			return this;
		}

		@Override
		public List<LongJitType> legTypesBE() {
			return List.of(this);
		}

		@Override
		public List<LongJitType> legTypesLE() {
			return List.of(this);
		}
	}

	/**
	 * The p-code type for floating-point of size 4, i.e., that fits in a JVM float.
	 */
	public enum FloatJitType implements SimpleJitType<TFloat, FloatJitType> {
		/** {@code float4}: a 4-byte float */
		F4;

		@Override
		public int pref() {
			return 2;
		}

		@Override
		public String nm() {
			return "f";
		}

		@Override
		public int size() {
			return Float.BYTES;
		}

		@Override
		public TFloat bType() {
			return Types.T_FLOAT;
		}

		@Override
		public FloatJitType ext() {
			return this;
		}

		@Override
		public IntJitType asInt() {
			return IntJitType.I4;
		}

		@Override
		public List<FloatJitType> legTypesBE() {
			return List.of(this);
		}

		@Override
		public List<FloatJitType> legTypesLE() {
			return List.of(this);
		}
	}

	/**
	 * The p-code type for floating-point of size 8, i.e., that fits in a JVM double.
	 */
	public enum DoubleJitType implements SimpleJitType<TDouble, DoubleJitType> {
		/** {@code float8}: a 8-byte float */
		F8;

		@Override
		public int pref() {
			return 3;
		}

		@Override
		public String nm() {
			return "d";
		}

		@Override
		public int size() {
			return Double.BYTES;
		}

		@Override
		public TDouble bType() {
			return Types.T_DOUBLE;
		}

		@Override
		public DoubleJitType ext() {
			return this;
		}

		@Override
		public LongJitType asInt() {
			return LongJitType.I8;
		}

		@Override
		public List<DoubleJitType> legTypesBE() {
			return List.of(this);
		}

		@Override
		public List<DoubleJitType> legTypesLE() {
			return List.of(this);
		}
	}

	/**
	 * The p-code types for integers of size 9 and greater.
	 * 
	 * <p>
	 * We take the strategy of inlined manipulation of int locals, composed to form the full
	 * variable. When stored on the stack, the least-significant portion is always toward the top,
	 * no matter the language endianness.
	 * 
	 * @param size the size in bytes
	 * @param legTypesBE the type of each leg, in big-endian order
	 * @param legTypesLE the type of each leg, in little-endian order
	 */
	public record MpIntJitType(int size, List<IntJitType> legTypesBE, List<IntJitType> legTypesLE)
			implements LeggedJitType<TInt, IntJitType> {
		private static final Map<Integer, MpIntJitType> FOR_SIZES = new HashMap<>();

		private static int legsAlloc(int size) {
			return (size + Integer.BYTES - 1) / Integer.BYTES;
		}

		private static int partialSize(int size) {
			return size % Integer.BYTES;
		}

		private static List<IntJitType> computeLegTypesBE(int size) {
			IntJitType[] types = new IntJitType[legsAlloc(size)];
			int i = 0;
			if (partialSize(size) != 0) {
				types[i++] = IntJitType.forSize(partialSize(size));
			}
			for (; i < types.length; i++) {
				types[i] = IntJitType.I4;
			}
			return Arrays.asList(types);
		}

		/**
		 * Get the type for an integer of the given size 9 or greater
		 * 
		 * @param size the size in bytes
		 * @return the type
		 * @throws IllegalArgumentException for any size 8 or less
		 */
		public static MpIntJitType forSize(int size) {
			return FOR_SIZES.computeIfAbsent(size, MpIntJitType::new);
		}

		private MpIntJitType(int size, List<IntJitType> legTypesBE) {
			this(size, legTypesBE, legTypesBE.reversed());
		}

		private MpIntJitType(int size) {
			this(size, computeLegTypesBE(size));
		}

		@Override
		public int pref() {
			return 4;
		}

		@Override
		public String nm() {
			return "I";
		}

		/**
		 * The total number of JVM int variables ("legs") required to store the int
		 * 
		 * @return the total number of legs
		 */
		public int legsAlloc() {
			return legsAlloc(size);
		}

		/**
		 * The number of legs that are filled
		 * 
		 * @return the number of whole legs
		 */
		public int legsWhole() {
			return size / Integer.BYTES;
		}

		/**
		 * The number of bytes filled in the last leg, if partial
		 * 
		 * @return the number of bytes in the partial leg, or 0 if all legs are whole
		 */
		public int partialSize() {
			return partialSize(size);
		}

		@Override
		public MpIntJitType ext() {
			return MpIntJitType.forSize(legsAlloc() * Integer.BYTES);
		}
	}

	/**
	 * <b>WIP</b>: The p-code types for floats of size other than 4 and 8
	 * 
	 * @param size the size in bytes
	 */
	public record MpFloatJitType(int size) implements LeggedJitType<TInt, IntJitType> {
		private static final Map<Integer, MpFloatJitType> FOR_SIZES = new HashMap<>();

		/**
		 * Get the type for a float of the given size other than 4 and 8
		 * 
		 * @param size the size in bytes
		 * @return the type
		 * @throws IllegalArgumentException for size 4 or 8
		 */
		public static MpFloatJitType forSize(int size) {
			return FOR_SIZES.computeIfAbsent(size, MpFloatJitType::new);
		}

		@Override
		public int pref() {
			return 5;
		}

		@Override
		public String nm() {
			return "F";
		}

		@Override
		public MpFloatJitType ext() {
			return this;
		}

		@Override
		public List<IntJitType> legTypesBE() {
			return Unfinished.TODO("MpFloat");
		}

		@Override
		public List<IntJitType> legTypesLE() {
			return Unfinished.TODO("MpFloat");
		}
	}

	/**
	 * The preference for this type. Smaller is more preferred.
	 * 
	 * @return the preference
	 */
	public int pref();

	/**
	 * Part of the name of a JVM local variable allocated for this type
	 * 
	 * @return the "type" part of a JVM local's name
	 */
	public String nm();

	/**
	 * The size of this type
	 * 
	 * @return the size in bytes
	 */
	public int size();

	/**
	 * Extend this p-code type to the p-code type that fills its entire host JVM type.
	 * 
	 * <p>
	 * This is useful, e.g., when multiplying two {@link IntJitType#I3 int3} values using
	 * {@link Opcodes#IMUL imul} that the result might be an {@link IntJitType#I4 int4} and so may
	 * need additional conversion.
	 * 
	 * @return the extended type
	 */
	JitType ext();

	/**
	 * Get the p-code type that describes the part of the variable in each leg
	 * 
	 * <p>
	 * Each whole leg will have the type {@link IntJitType#I4}, and the partial leg, if applicable,
	 * will have its appropriate smaller integer type.
	 * 
	 * @return the list of types, each fitting in a JVM int, in big-endian order.
	 */
	List<? extends SimpleJitType<?, ?>> legTypesBE();

	/**
	 * Get the p-code type that describes the part of the variable in each leg
	 * 
	 * <p>
	 * Each whole leg will have the type {@link IntJitType#I4}, and the partial leg, if applicable,
	 * will have its appropriate smaller integer type.
	 * 
	 * @return the list of types, each fitting in a JVM int, in little-endian order.
	 */
	List<? extends SimpleJitType<?, ?>> legTypesLE();
}
