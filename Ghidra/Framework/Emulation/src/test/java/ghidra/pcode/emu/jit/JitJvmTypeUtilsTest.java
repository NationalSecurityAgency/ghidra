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
package ghidra.pcode.emu.jit;

import static org.junit.Assert.assertEquals;

import java.io.InputStream;
import java.util.*;

import org.apache.commons.lang3.reflect.TypeLiteral;
import org.junit.Ignore;
import org.junit.Test;
import org.objectweb.asm.*;

import ghidra.pcode.emu.jit.JitPassage.AddrCtx;

@Ignore("Too tightly bound to java version")
public class JitJvmTypeUtilsTest {

	public static class HasFieldTypeSignatures {
		public static final List<AddrCtx> RECS = new ArrayList<>();
		public static final List<?> WILDS = new ArrayList<>();
		public static final List<? super AddrCtx> SUPERS = new ArrayList<>();
		public static final List<? extends AddrCtx> EXTENDS = new ArrayList<>();
	}

	@Test
	public void testTypeToSignature() throws Exception {
		Map<String, String> signatures = new HashMap<>();
		String filename = Type.getInternalName(HasFieldTypeSignatures.class) + ".class";
		try (InputStream is = getClass().getClassLoader().getResourceAsStream(filename)) {
			ClassReader cr = new ClassReader(is);
			//ClassNode cn = new ClassNode(Opcodes.ASM9);
			//ClassVisitor trace = new TraceClassVisitor(cn, new PrintWriter(System.out));
			ClassVisitor trace = null;
			cr.accept(new ClassVisitor(Opcodes.ASM9, trace) {
				@Override
				public FieldVisitor visitField(int access, String name, String descriptor,
						String signature, Object value) {
					signatures.put(name, signature);
					return super.visitField(access, filename, descriptor, signature, value);
				}
			}, 0);
		}

		assertEquals(signatures.get("RECS"), JitJvmTypeUtils
				.typeToSignature(new TypeLiteral<List<AddrCtx>>() {}.value));
		assertEquals(signatures.get("WILDS"), JitJvmTypeUtils
				.typeToSignature(new TypeLiteral<List<?>>() {}.value));
		assertEquals(signatures.get("SUPERS"), JitJvmTypeUtils
				.typeToSignature(new TypeLiteral<List<? super AddrCtx>>() {}.value));
		assertEquals(signatures.get("EXTENDS"), JitJvmTypeUtils
				.typeToSignature(new TypeLiteral<List<? extends AddrCtx>>() {}.value));
	}
}
