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

import java.util.Comparator;
import java.util.Objects;

import ghidra.pcode.emu.jit.analysis.JitType.*;
import ghidra.pcode.emu.jit.op.JitCopyOp;
import ghidra.pcode.emu.jit.op.JitPhiOp;

/**
 * The behavior/requirement for an operand's type.
 * 
 * @see JitTypeModel
 */
public enum JitTypeBehavior {
	/**
	 * No type requirement or interpretation.
	 */
	ANY {
		/**
		 * {@inheritDoc}
		 * 
		 * <p>
		 * If no type is specified, we default to ints.
		 */
		@Override
		public JitType type(int size) {
			return INTEGER.type(size);
		}

		@Override
		public JitType resolve(JitType varType) {
			return varType;
		}
	},
	/**
	 * The bits are interpreted as an integer.
	 */
	INTEGER {
		@Override
		public JitType type(int size) {
			assert size > 0;
			return switch (size) {
				case 1, 2, 3, 4 -> IntJitType.forSize(size);
				case 5, 6, 7, 8 -> LongJitType.forSize(size);
				default -> MpIntJitType.forSize(size);
			};
		}

		@Override
		public JitType resolve(JitType varType) {
			return type(varType.size());
		}
	},
	/**
	 * The bits are interpreted as a floating-point value.
	 */
	FLOAT {
		@Override
		public JitType type(int size) {
			return switch (size) {
				case Float.BYTES -> FloatJitType.F4;
				case Double.BYTES -> DoubleJitType.F8;
				default -> MpFloatJitType.forSize(size);
			};
		}

		@Override
		public JitType resolve(JitType varType) {
			return type(varType.size());
		}
	},
	/**
	 * For {@link JitCopyOp} and {@link JitPhiOp}: No type requirement or interpretation, but there
	 * is an implication that the output has the same interpretation as the inputs.
	 */
	COPY {
		@Override
		public JitType type(int size) {
			throw new AssertionError();
		}

		@Override
		public JitType resolve(JitType varType) {
			return ANY.resolve(varType);
		}
	},
	;

	/**
	 * Compare two behaviors by preference. The behavior with the smaller ordinal is preferred.
	 * 
	 * @param b1 the first behavior
	 * @param b2 the second behavior
	 * @return as in {@link Comparator#compare(Object, Object)}
	 */
	public static int compare(JitTypeBehavior b1, JitTypeBehavior b2) {
		return Objects.compare(b1, b2, JitTypeBehavior::compareTo);
	}

	/**
	 * Apply this behavior to a value of the given size to determine its type
	 * 
	 * @param size the size of the value in bytes
	 * @return the resulting type
	 * @throws AssertionError if the type is not applicable, and such an invocation was not expected
	 */
	public abstract JitType type(int size);

	/**
	 * Re-apply this behavior to an existing type
	 * 
	 * <p>
	 * For {@link #ANY} and {@link #COPY} the result is the given type.
	 * 
	 * @param varType the type
	 * @return the resulting type
	 */
	public abstract JitType resolve(JitType varType);

	/**
	 * Derive the type behavior from a Java language type.
	 * 
	 * <p>
	 * This is used on userops declared with Java primitives for parameters. To work with the
	 * {@link JitTypeModel}, we need to specify the type behavior of each operand. We aim to select
	 * behaviors such that the model allocates JVM locals whose JVM types match the userop method's
	 * parameters. This optimizes type conversions during Direct invocation.
	 * 
	 * @param cls the primitive class (not boxed)
	 * @return the p-code type behavior
	 * @see JitDataFlowUseropLibrary
	 */
	public static JitTypeBehavior forJavaType(Class<?> cls) {
		if (cls == byte.class) {
			return INTEGER;
		}
		if (cls == short.class) {
			return INTEGER;
		}
		if (cls == int.class) {
			return INTEGER;
		}
		if (cls == long.class) {
			return INTEGER;
		}
		if (cls == float.class) {
			return FLOAT;
		}
		if (cls == double.class) {
			return FLOAT;
		}
		if (cls == boolean.class) {
			return INTEGER;
		}
		if (cls == char.class) {
			return null;
		}
		if (cls == void.class) {
			return null;
		}
		if (cls.isPrimitive()) {
			throw new AssertionError();
		}
		return null;
	}
}
