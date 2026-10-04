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

import java.lang.classfile.ClassBuilder;
import java.lang.classfile.attribute.ConstantValueAttribute;
import java.lang.classfile.attribute.SignatureAttribute;

import org.apache.commons.lang3.reflect.TypeLiteral;

import ghidra.pcode.emu.jit.JitJvmTypeUtils;
import ghidra.pcode.emu.jit.gen.util.Types.*;

/**
 * Utilities for declaring fields in a {@link ClassBuilder}
 * <p>
 * LATER: We do not yet return a "field handle." Ideally, we would and that would be the required
 * argument for {@link Op#getfield(Emitter, TRef, String, BNonVoid)} and related ops.
 */
public interface Fld {
	/**
	 * Declare an initialized boolean field
	 *
	 * @param clb the class builder
	 * @param flags the access flags
	 * @param type the type
	 * @param name the name
	 * @param init the initial value
	 */
	static void decl(ClassBuilder clb, int flags, TBool type, String name, boolean init) {
		clb.withField(name, type.classDesc(), fb -> {
			fb.withFlags(flags);
			fb.with(ConstantValueAttribute.of(init ? 1 : 0));
		});
	}

	/**
	 * Declare an initialized byte field
	 *
	 * @param clb the class builder
	 * @param flags the access flags
	 * @param type the type
	 * @param name the name
	 * @param init the initial value
	 */
	static void decl(ClassBuilder clb, int flags, TByte type, String name, byte init) {
		clb.withField(name, type.classDesc(), fb -> {
			fb.withFlags(flags);
			fb.with(ConstantValueAttribute.of((int) init));
		});
	}

	/**
	 * Declare an initialized short field
	 *
	 * @param clb the class builder
	 * @param flags the access flags
	 * @param type the type
	 * @param name the name
	 * @param init the initial value
	 */
	static void decl(ClassBuilder clb, int flags, TShort type, String name, short init) {
		clb.withField(name, type.classDesc(), fb -> {
			fb.withFlags(flags);
			fb.with(ConstantValueAttribute.of((int) init));
		});
	}

	/**
	 * Declare an initialized int field
	 *
	 * @param clb the class builder
	 * @param flags the access flags
	 * @param type the type
	 * @param name the name
	 * @param init the initial value
	 */
	static void decl(ClassBuilder clb, int flags, TInt type, String name, int init) {
		clb.withField(name, type.classDesc(), fb -> {
			fb.withFlags(flags);
			fb.with(ConstantValueAttribute.of(init));
		});
	}

	/**
	 * Declare an initialized long field
	 *
	 * @param clb the class builder
	 * @param flags the access flags
	 * @param type the type
	 * @param name the name
	 * @param init the initial value
	 */
	static void decl(ClassBuilder clb, int flags, TLong type, String name, long init) {
		clb.withField(name, type.classDesc(), fb -> {
			fb.withFlags(flags);
			fb.with(ConstantValueAttribute.of(init));
		});
	}

	/**
	 * Declare an initialized float field
	 *
	 * @param clb the class builder
	 * @param flags the access flags
	 * @param type the type
	 * @param name the name
	 * @param init the initial value
	 */
	static void decl(ClassBuilder clb, int flags, TFloat type, String name, float init) {
		clb.withField(name, type.classDesc(), fb -> {
			fb.withFlags(flags);
			fb.with(ConstantValueAttribute.of(init));
		});
	}

	/**
	 * Declare an initialized double field
	 *
	 * @param clb the class builder
	 * @param flags the access flags
	 * @param type the type
	 * @param name the name
	 * @param init the initial value
	 */
	static void decl(ClassBuilder clb, int flags, TDouble type, String name, double init) {
		clb.withField(name, type.classDesc(), fb -> {
			fb.withFlags(flags);
			fb.with(ConstantValueAttribute.of(init));
		});
	}

	/**
	 * Declare an initialized reference field
	 * <p>
	 * Note that only certain types of fields can have initial values specified in this manner. A
	 * {@link String} is one such type. For other types, the initializer must be provided in a
	 * generated class initializer (for static fields) or constructor (for instance fields).
	 *
	 * @param clb the class builder
	 * @param flags the access flags
	 * @param type the type
	 * @param name the name
	 * @param init the initial value
	 */
	static <T> void decl(ClassBuilder clb, int flags, TRef<T> type, String name, T init) {
		clb.withField(name, type.classDesc(), fb -> {
			fb.withFlags(flags);
			if (init instanceof String s) {
				fb.with(ConstantValueAttribute.of(s));
			}
		});
	}

	/**
	 * Declare an uninitialized field of any type
	 *
	 * @param clb the class builder
	 * @param flags the access flags
	 * @param type the type
	 * @param name the name
	 */
	static <T> void decl(ClassBuilder clb, int flags, SNonVoid type, String name) {
		clb.withField(name, type.classDesc(), flags);
	}

	/**
	 * Declare an uninitialized field of any type with a type signature
	 *
	 * @param clb the class builder
	 * @param flags the access flags
	 * @param type the type with signature
	 * @param name the name
	 */
	static <T> void decl(ClassBuilder clb, int flags, TypeLiteral<T> type, String name) {
		Class<?> erased = JitJvmTypeUtils.erase(type.value);
		String signature = erased == type.value
				? null
				: JitJvmTypeUtils.typeToSignature(type.value);
		clb.withField(name, erased.describeConstable().orElseThrow(), fb -> {
			fb.withFlags(flags);
			if (signature != null) {
				fb.with(SignatureAttribute.of(
					fb.constantPool().utf8Entry(signature)));
			}
		});
	}
}
