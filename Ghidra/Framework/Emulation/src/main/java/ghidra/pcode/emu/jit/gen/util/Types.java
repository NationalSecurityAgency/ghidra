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
package ghidra.pcode.emu.jit.gen.util;

import java.lang.classfile.TypeKind;
import java.lang.constant.ClassDesc;
import java.lang.constant.ConstantDescs;

/**
 * A namespace for types describing Java types
 * <p>
 * Type descriptors are represented using {@link ClassDesc} from the {@code java.lang.constant}
 * package (the standard Class-File API), replacing the third-party ASM {@code Type} class.
 */
public interface Types {
	/** The {@code void} type */
	TVoid T_VOID = TVoid.INSTANCE;
	/** The {@code boolean} type */
	TBool T_BOOL = TBool.INSTANCE;
	/** The {@code byte} type */
	TByte T_BYTE = TByte.INSTANCE;
	/** The {@code char} type */
	TChar T_CHAR = TChar.INSTANCE;
	/** The {@code short} type */
	TShort T_SHORT = TShort.INSTANCE;
	/** The {@code int} type */
	TInt T_INT = TInt.INSTANCE;
	/** The {@code long} type */
	TLong T_LONG = TLong.INSTANCE;
	/** The {@code float} type */
	TFloat T_FLOAT = TFloat.INSTANCE;
	/** The {@code double} type */
	TDouble T_DOUBLE = TDouble.INSTANCE;

	/** The {@code boolean[]} type */
	TRef<boolean[]> T_BOOL_ARR = refOf(boolean[].class);
	/** The {@code byte[]} type */
	TRef<byte[]> T_BYTE_ARR = refOf(byte[].class);
	/** The {@code char[]} type */
	TRef<char[]> T_CHAR_ARR = refOf(char[].class);
	/** The {@code short[]} type */
	TRef<short[]> T_SHORT_ARR = refOf(short[].class);
	/** The {@code int[]} type */
	TRef<int[]> T_INT_ARR = refOf(int[].class);
	/** The {@code long[]} type */
	TRef<long[]> T_LONG_ARR = refOf(long[].class);
	/** The {@code float[]} type */
	TRef<float[]> T_FLOAT_ARR = refOf(float[].class);
	/** The {@code double[]} type */
	TRef<double[]> T_DOUBLE_ARR = refOf(double[].class);

	/**
	 * Create a type describing a reference of the given class (or interface) type
	 *
	 * @param <T> the type of the Java class
	 * @param cls the class
	 * @return the type
	 */
	static <T> TRef<T> refOf(Class<T> cls) {
		return TRef.of(cls);
	}

	/**
	 * Create a type describing an extension of the given class (or interface) type
	 * <p>
	 * This is used when the type is itself dynamically generated, but it is at least known to
	 * extend a type defined by compiled Java source. This is best used with a type variable on the
	 * class in the Java source that generates the type. Unfortunately, that variable may bleed into
	 * any number of classes and methods which support that generation, esp., since this is almost
	 * always required to describe the type of {@code this}, and {@code this} is frequently accessed
	 * in generated code. Conventionally, the type variable is called {@code THIS}:
	 *
	 * <pre>
	 * class MyGenerator&lt;THIS extends MyIf&gt; {
	 * 	private final TRef&lt;THIS&gt; typeThis = refExtends(MyIf.class, generateDesc());
	 * }
	 * </pre>
	 *
	 * @param <ST> the super type
	 * @param <T> the type variable used to refer to the extension
	 * @param cls the class of the super type
	 * @param desc the JVM type descriptor (e.g., {@code "Lmy/pkg/MyClass;"}) of the actual
	 *            generated extension type
	 * @return the type
	 */
	static <ST, T extends ST> TRef<T> refExtends(Class<ST> cls, String desc) {
		return TRef.ofExtends(cls, desc);
	}

	/**
	 * See {@link #refExtends(Class, String)}
	 *
	 * @param <ST> the super type
	 * @param <T> the type variable used to refer to the extension
	 * @param st the super type
	 * @param desc the JVM type descriptor of the actual generated extension type
	 * @return the type
	 */
	static <ST, T extends ST> TRef<T> refExtends(TRef<ST> st, String desc) {
		return TRef.ofExtends(st.cls, desc);
	}

	/**
	 * Create a type describing a reflected extension of a given class (or interface) type
	 * <p>
	 * This is used when the type is only known through reflection, but it is at least known to
	 * extend some other fixed type. This is best used with a type variable on the method that
	 * generates code wrt. the reflected class.
	 *
	 * @param <ST> the super type
	 * @param <T> the type variable used to refer to the extension
	 * @param st the super type
	 * @param reflected the reflected class
	 * @return the type
	 */
	static <ST, T extends ST> TRef<T> refExtends(TRef<ST> st, Class<?> reflected) {
		return TRef.ofExtends(st.cls,
			reflected.describeConstable().orElseThrow().descriptorString());
	}

	/**
	 * See {@link #refExtends(Class, String)}
	 *
	 * @param <ST> the super type
	 * @param <T> the type variable used to refer to the extension
	 * @param cls the super type
	 * @param desc the class descriptor of the actual generated extension type
	 * @return the type
	 */
	static <ST, T extends ST> TRef<T> refExtends(Class<ST> cls, ClassDesc desc) {
		return TRef.ofExtends(cls, desc.descriptorString());
	}

	/**
	 * See {@link #refExtends(Class, String)}
	 *
	 * @param <ST> the super type
	 * @param <T> the type variable used to refer to the extension
	 * @param st the super type
	 * @param desc the class descriptor of the actual generated extension type
	 * @return the type
	 */
	static <ST, T extends ST> TRef<T> refExtends(TRef<ST> st, ClassDesc desc) {
		return TRef.ofExtends(st.cls, desc.descriptorString());
	}

	/**
	 * Types that may be returned by a method in Java source
	 * <p>
	 * This is essentially "all types including {@code void}" as far as Java is concerned.
	 */
	public interface SType {
		/**
		 * Get the {@link ClassDesc} for this type
		 *
		 * @return the class descriptor
		 */
		ClassDesc classDesc();

		/**
		 * Get the Java class to describe this type
		 * <p>
		 * For generated types, this may instead be a suitable super type.
		 *
		 * @return the class
		 */
		Class<?> cls();
	}

	/**
	 * Types that may be ascribed to a variable in Java source
	 * <p>
	 * This is essentially "all types except {@code void}" as far as Java is concerned.
	 */
	public interface SNonVoid extends SType {
	}

	/**
	 * The primitive types that may be ascribed to a variable in Java source
	 * <p>
	 * This is essentially "all non-reference types" as far as Java is concerned.
	 *
	 * @param <A> the array type for which this primitive is the element type
	 */
	public interface SPrim<A> extends SNonVoid {
		/**
		 * The {@link TypeKind} for this primitive type, used with
		 * {@link java.lang.classfile.CodeBuilder#newarray(TypeKind)}.
		 *
		 * @return the type kind
		 */
		TypeKind typeKind();
	}

	/**
	 * The types that may be ascribed to local variables in JVM bytecode, and {@code void}
	 * <p>
	 * This includes {@code void}, all reference types, but only the primitive types {@code int},
	 * {@code float}, {@code long}, and {@code double}. The other primitive types are stored in
	 * {@code int} local variables.
	 */
	public interface BType extends SType {
		@Override
		ClassDesc classDesc();

		/**
		 * Get the internal name of the type (e.g., {@code java.lang.Object})
		 * <p>
		 * This is only meaningful for reference types. For primitive types, the descriptor string
		 * is returned as-is.
		 *
		 * @return the internal name
		 */
		default String internalName() {
			String d = classDesc().descriptorString();
			if (d.startsWith("L") && d.endsWith(";")) {
				return d.substring(1, d.length() - 1);
			}
			return d;
		}
	}

	/**
	 * The types that may be ascribed to local variables in JVM bytecode
	 */
	public interface BNonVoid extends BType, SNonVoid {
		/**
		 * {@return the number of slots (stack entries or local indices) taken by this type}
		 */
		int slots();
	}

	/**
	 * The primitive types that may be ascribed to local variables in JVM bytecode
	 * <p>
	 * This includes only {@code int}, {@code float}, {@code long}, and {@code double}.
	 *
	 * @param <A> the array type for which this primitive is the element type
	 */
	public interface BPrim<A> extends BNonVoid, SPrim<A> {
		@Override
		TypeKind typeKind();
	}

	/**
	 * The {@code void} type
	 */
	public enum TVoid implements BType {
		/** Singleton */
		INSTANCE;

		@Override
		public ClassDesc classDesc() {
			return ConstantDescs.CD_void;
		}

		@Override
		public Class<?> cls() {
			return void.class;
		}
	}

	/**
	 * Category 1 types as defined by the JVM specification
	 * <p>
	 * This includes reference types, {@code int}, and {@code float}.
	 */
	public interface TCat1 extends BNonVoid {
		@Override
		default int slots() {
			return 1;
		}
	}

	/**
	 * Reference types
	 *
	 * @param <T> the type
	 * @param cls the class for the type. For generated types, this may be a super type.
	 * @param classDesc the class descriptor
	 */
	public record TRef<T>(Class<? super T> cls, ClassDesc classDesc) implements TCat1 {

		static <T> TRef<T> of(Class<T> cls) {
			return new TRef<>(cls, cls.describeConstable().orElseThrow());
		}

		static <ST, T extends ST> TRef<T> ofExtends(Class<ST> cls, String desc) {
			return new TRef<T>(cls, ClassDesc.ofDescriptor(desc));
		}
	}

	/**
	 * The {@code boolean} type
	 */
	public enum TBool implements SPrim<boolean[]> {
		/** Singleton */
		INSTANCE;

		@Override
		public TypeKind typeKind() {
			return TypeKind.BOOLEAN;
		}

		@Override
		public ClassDesc classDesc() {
			return ConstantDescs.CD_boolean;
		}

		@Override
		public Class<?> cls() {
			return boolean.class;
		}
	}

	/**
	 * The {@code byte} type
	 */
	public enum TByte implements SPrim<byte[]> {
		/** Singleton */
		INSTANCE;

		@Override
		public TypeKind typeKind() {
			return TypeKind.BYTE;
		}

		@Override
		public ClassDesc classDesc() {
			return ConstantDescs.CD_byte;
		}

		@Override
		public Class<?> cls() {
			return byte.class;
		}
	}

	/**
	 * The {@code char} type
	 */
	public enum TChar implements SPrim<char[]> {
		/** Singleton */
		INSTANCE;

		@Override
		public TypeKind typeKind() {
			return TypeKind.CHAR;
		}

		@Override
		public ClassDesc classDesc() {
			return ConstantDescs.CD_char;
		}

		@Override
		public Class<?> cls() {
			return char.class;
		}
	}

	/**
	 * The {@code short} type
	 */
	public enum TShort implements SPrim<short[]> {
		/** Singleton */
		INSTANCE;

		@Override
		public TypeKind typeKind() {
			return TypeKind.SHORT;
		}

		@Override
		public ClassDesc classDesc() {
			return ConstantDescs.CD_short;
		}

		@Override
		public Class<?> cls() {
			return short.class;
		}
	}

	/**
	 * The {@code int} type
	 */
	public enum TInt implements TCat1, BPrim<int[]> {
		/** Singleton */
		INSTANCE;

		@Override
		public TypeKind typeKind() {
			return TypeKind.INT;
		}

		@Override
		public ClassDesc classDesc() {
			return ConstantDescs.CD_int;
		}

		@Override
		public Class<?> cls() {
			return int.class;
		}
	}

	/**
	 * The {@code float} type
	 */
	public enum TFloat implements TCat1, BPrim<float[]> {
		/** Singleton */
		INSTANCE;

		@Override
		public TypeKind typeKind() {
			return TypeKind.FLOAT;
		}

		@Override
		public ClassDesc classDesc() {
			return ConstantDescs.CD_float;
		}

		@Override
		public Class<?> cls() {
			return float.class;
		}
	}

	/**
	 * Category 2 types as defined by the JVM specification
	 * <p>
	 * This includes {@code long} and {@code double}.
	 */
	public interface TCat2 extends BNonVoid {
		@Override
		default int slots() {
			return 2;
		}
	}

	/**
	 * The {@code long} type
	 */
	public enum TLong implements TCat2, BPrim<long[]> {
		/** Singleton */
		INSTANCE;

		@Override
		public TypeKind typeKind() {
			return TypeKind.LONG;
		}

		@Override
		public ClassDesc classDesc() {
			return ConstantDescs.CD_long;
		}

		@Override
		public Class<?> cls() {
			return long.class;
		}
	}

	/**
	 * The {@code double} type
	 */
	public enum TDouble implements TCat2, BPrim<double[]> {
		/** Singleton */
		INSTANCE;

		@Override
		public TypeKind typeKind() {
			return TypeKind.DOUBLE;
		}

		@Override
		public ClassDesc classDesc() {
			return ConstantDescs.CD_double;
		}

		@Override
		public Class<?> cls() {
			return double.class;
		}
	}
}
