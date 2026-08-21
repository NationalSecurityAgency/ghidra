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

import org.apache.commons.lang3.reflect.TypeLiteral;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.Type;

import ghidra.pcode.emu.jit.JitJvmTypeUtils;
import ghidra.pcode.emu.jit.gen.util.Types.*;

/**
 * Utilities for declaring fields in an ASM {@link ClassVisitor}
 * <p>
 * LATER: We do not yet return a "field handle." Ideally, we would and that would be the required
 * argument for {@link Op#getfield(Emitter, TRef, String, BNonVoid)} and related ops.
 */
public interface Fld {
	/**
	 * Declare an initialized boolean field
	 * 
	 * @param cv the class visitor
	 * @param flags the flags as in
	 *            {@link ClassVisitor#visitField(int, String, String, String, Object)}
	 * @param type the type
	 * @param name the name
	 * @param init the initial value
	 */
	static void decl(ClassVisitor cv, int flags, TBool type, String name, boolean init) {
		cv.visitField(flags, name, type.type().getDescriptor(), null, init);
	}

	/**
	 * Declare an initialized byte field
	 * 
	 * @param cv the class visitor
	 * @param flags the flags as in
	 *            {@link ClassVisitor#visitField(int, String, String, String, Object)}
	 * @param type the type
	 * @param name the name
	 * @param init the initial value
	 */
	static void decl(ClassVisitor cv, int flags, TByte type, String name, byte init) {
		cv.visitField(flags, name, type.type().getDescriptor(), null, init);
	}

	/**
	 * Declare an initialized short field
	 * 
	 * @param cv the class visitor
	 * @param flags the flags as in
	 *            {@link ClassVisitor#visitField(int, String, String, String, Object)}
	 * @param type the type
	 * @param name the name
	 * @param init the initial value
	 */
	static void decl(ClassVisitor cv, int flags, TShort type, String name, short init) {
		cv.visitField(flags, name, type.type().getDescriptor(), null, init);
	}

	/**
	 * Declare an initialized int field
	 * 
	 * @param cv the class visitor
	 * @param flags the flags as in
	 *            {@link ClassVisitor#visitField(int, String, String, String, Object)}
	 * @param type the type
	 * @param name the name
	 * @param init the initial value
	 */
	static void decl(ClassVisitor cv, int flags, TInt type, String name, int init) {
		cv.visitField(flags, name, type.type().getDescriptor(), null, init);
	}

	/**
	 * Declare an initialized long field
	 * 
	 * @param cv the class visitor
	 * @param flags the flags as in
	 *            {@link ClassVisitor#visitField(int, String, String, String, Object)}
	 * @param type the type
	 * @param name the name
	 * @param init the initial value
	 */
	static void decl(ClassVisitor cv, int flags, TLong type, String name, long init) {
		cv.visitField(flags, name, type.type().getDescriptor(), null, init);
	}

	/**
	 * Declare an initialized float field
	 * 
	 * @param cv the class visitor
	 * @param flags the flags as in
	 *            {@link ClassVisitor#visitField(int, String, String, String, Object)}
	 * @param type the type
	 * @param name the name
	 * @param init the initial value
	 */
	static void decl(ClassVisitor cv, int flags, TFloat type, String name, float init) {
		cv.visitField(flags, name, type.type().getDescriptor(), null, init);
	}

	/**
	 * Declare an initialized double field
	 * 
	 * @param cv the class visitor
	 * @param flags the flags as in
	 *            {@link ClassVisitor#visitField(int, String, String, String, Object)}
	 * @param type the type
	 * @param name the name
	 * @param init the initial value
	 */
	static void decl(ClassVisitor cv, int flags, TDouble type, String name, double init) {
		cv.visitField(flags, name, type.type().getDescriptor(), null, init);
	}

	/**
	 * Declare an initialized reference field
	 * <p>
	 * Note that only certain types of fields can have initial values specified in this manner. A
	 * {@link String} is one such type. For other types, the initializer must be provided in a
	 * generated class initializer (for static fields) or constructor (for instance fields).
	 * 
	 * @param cv the class visitor
	 * @param flags the flags as in
	 *            {@link ClassVisitor#visitField(int, String, String, String, Object)}
	 * @param type the type
	 * @param name the name
	 * @param init the initial value
	 */
	static <T> void decl(ClassVisitor cv, int flags, TRef<T> type, String name, T init) {
		cv.visitField(flags, name, type.type().getDescriptor(), null, init);
	}

	/**
	 * Declare an uninitialized field of any type
	 * 
	 * @param cv the class visitor
	 * @param flags the flags as in
	 *            {@link ClassVisitor#visitField(int, String, String, String, Object)}
	 * @param type the type
	 * @param name the name
	 */
	static <T> void decl(ClassVisitor cv, int flags, SNonVoid type, String name) {
		cv.visitField(flags, name, type.type().getDescriptor(), null, null);
	}

	/**
	 * Declare an uninitialized field of any type with a type signature
	 * 
	 * @param cv the class visitor
	 * @param flags the flags as in
	 *            {@link ClassVisitor#visitField(int, String, String, String, Object)}
	 * @param type the type with signature
	 * @param name the name
	 */
	static <T> void decl(ClassVisitor cv, int flags, TypeLiteral<T> type, String name) {
		Class<?> erased = JitJvmTypeUtils.erase(type.value);
		String signature = erased == type.value
				? null
				: JitJvmTypeUtils.typeToSignature(type.value);
		cv.visitField(flags, name, Type.getDescriptor(erased), signature, null);
	}
}
