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

import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.io.PrintStream;
import java.lang.invoke.*;
import java.lang.invoke.MethodHandles.Lookup;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;

import javax.tools.*;
import javax.tools.Diagnostic.Kind;
import javax.tools.JavaCompiler.CompilationTask;

import org.junit.Test;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;

import generic.Unique;
import ghidra.pcode.emu.jit.gen.util.Emitter.*;
import ghidra.pcode.emu.jit.gen.util.EmitterTest.Generated;
import ghidra.pcode.emu.jit.gen.util.Methods.*;
import ghidra.pcode.emu.jit.gen.util.Types.*;

public class EmitterTest<THIS extends Generated> {
	static final TRef<Generated> T_GENERATED = Types.refOf(Generated.class);
	static final TRef<Object> T_OBJECT = Types.refOf(Object.class);
	static final TRef<PrintStream> T_PRINT_STREAM = Types.refOf(PrintStream.class);
	static final TRef<String> T_STRING = Types.refOf(String.class);
	static final TRef<System> T_SYSTEM = Types.refOf(System.class);

	public interface Generated {
		void run();
	}

	static final MthDesc<TVoid, Bot> MDESC_CONS = MthDesc.returns(Types.T_VOID).build();
	static final MthDesc<TVoid, Bot> MDESC_RUN = MthDesc.returns(Types.T_VOID).build();

	static final MthDesc<TVoid, Ent<Bot, TRef<String>>> MDESC_PRINTLN =
		MthDesc.returns(Types.T_VOID).param(T_STRING).build();

	final TRef<THIS> typeThis =
		Types.refExtends(Generated.class, "Lghidra/pcode/emu/jit/gen/util/TestGenerated;");

	public interface RunGenerator<THIS extends Generated, MR extends BType> {
		Emitter<Dead> gen(Emitter<Bot> em, Local<TRef<THIS>> localThis, RetReq<MR> ret);
	}

	public void generateAndRun(RunGenerator<THIS, TVoid> gen) throws Throwable {
		ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
		cw.visit(Opcodes.V21, Opcodes.ACC_PUBLIC, typeThis.internalName(), null,
			T_OBJECT.internalName(), new String[] { T_GENERATED.internalName() });

		var paramsInit = new Object() {
			Local<TRef<THIS>> this_;
		};
		var retInit = Emitter.start(typeThis, cw, Opcodes.ACC_PUBLIC, "<init>", MDESC_CONS)
				.param(Def::done, typeThis, l -> paramsInit.this_ = l);
		retInit.em()
				.emit(Op::aload, paramsInit.this_)
				.emit(Op::invokespecial, T_OBJECT, "<init>", MDESC_CONS, false)
				.step(Inv::takeObjRef)
				.step(Inv::retVoid)
				.emit(Op::return_, retInit.ret())
				.emit(Misc::finish);

		var paramsRun = new Object() {
			Local<TRef<THIS>> this_;
		};
		var retRun = Emitter.start(typeThis, cw, Opcodes.ACC_PUBLIC, "run", MDESC_RUN)
				.param(Def::done, typeThis, l -> paramsRun.this_ = l);
		retRun.em()
				.emit(gen::gen, paramsRun.this_, retRun.ret())
				.emit(Misc::finish);

		cw.visitEnd();
		byte[] classfile = cw.toByteArray();

		Lookup lookup = MethodHandles.lookup();
		Lookup defLookup = lookup.defineHiddenClass(classfile, true);
		@SuppressWarnings("unchecked")
		Class<? extends Generated> cls = (Class<? extends Generated>) defLookup.lookupClass();
		MethodHandle constructor =
			defLookup.findConstructor(cls, MethodType.methodType(void.class));
		Generated hw = (Generated) constructor.invoke();
		hw.run();
	}

	@Test
	public void testHelloWorld() throws Throwable {
		generateAndRun((em, localThis, ret) -> em
				.emit(Op::getstatic, T_SYSTEM, "out", T_PRINT_STREAM)
				.emit(Op::ldc__a, "Hello, World")
				.emit(Op::invokevirtual, T_PRINT_STREAM, "println", MDESC_PRINTLN, false)
				.step(Inv::takeArg)
				.step(Inv::takeObjRef)
				.step(Inv::retVoid)
				.emit(Op::return_, ret));
	}

	@Test
	public void testArrayLengthPrim() throws Throwable {
		generateAndRun((em, localThis, ret) -> em
				.emit(Op::ldc__i, 6)
				.emit(Op::newarray, Types.T_INT)
				.emit(Op::arraylength__prim, Types.T_INT)
				.emit(Op::pop)
				.emit(Op::return_, ret));
	}

	@Test
	public void testArrayLengthRef() throws Throwable {
		generateAndRun((em, localThis, ret) -> em
				.emit(Op::ldc__i, 6)
				.emit(Op::anewarray, Types.refOf(String.class))
				.emit(Op::arraylength__ref)
				.emit(Op::pop)
				.emit(Op::return_, ret));
	}

	@Test
	public void testArrayLengthWrong() throws Throwable {
		runExpectingCompilationError("""
				generateAndRun((em, localThis, ret) -> /*s*/em
						.emit(Op::ldc__i, 6)
						.emit(Op::arraylength__prim, Types.T_INT)/*e*/
						.emit(Op::pop)
						.emit(Op::return_, ret));
				""", List.of(Types.class, Op.class));
	}

	@Test
	public void testAstore() throws Throwable {
		generateAndRun((em, localThis, ret) -> {
			Local<TRef<Object>> test = em.rootScope().decl(Types.refOf(Object.class), "test");
			return em
					.emit(Op::aload, localThis)
					.emit(Op::astore, test)
					.emit(Op::return_, ret);
		});
	}

	// @Test // Because it won't actually run. Just a syntax check.
	public void syntaxTestAreturn() throws Throwable {
		RetReq<TRef<Object>> ret = null;
		generateAndRun((em, localThis, ignore) -> em
				.emit(Op::new_, Types.refOf(String.class))
				.emit(Op::areturn, ret));
	}

	protected static class JavaSourceFromString extends SimpleJavaFileObject {
		private final String code;

		protected JavaSourceFromString(String name, String code) {
			super(URI.create("string:///" + name), Kind.SOURCE);
			this.code = code;
		}

		@Override
		public CharSequence getCharContent(boolean ignoreEncodingErrors) throws IOException {
			return code;
		}
	};

	protected String genImports(Iterable<Class<?>> imports) {
		StringBuilder sb = new StringBuilder();
		for (Class<?> imp : imports) {
			sb.append("import ");
			sb.append(imp.getCanonicalName());
			sb.append(";\n");
		}
		return sb.toString();
	}

	protected void runExpectingCompilationError(String source, Iterable<Class<?>> imports)
			throws Throwable {

		List<Class<?>> importsPlus = new ArrayList<>();
		importsPlus.add(this.getClass());
		importsPlus.add(Generated.class);
		imports.forEach(importsPlus::add);

		String fullSource = """
				package test.source;
				%s
				public class TestSource<THIS extends Generated> extends %s<THIS> {
					public void testMethod() throws Throwable {
						%s
					}
				}
				""".formatted(genImports(importsPlus),
			this.getClass().getSimpleName(), source);

		int expectedStart = fullSource.indexOf("/*s*/");
		if (expectedStart == -1) {
			throw new AssertionError("Invalid test case. Missing start marker /*s*/");
		}
		int expectedEnd = fullSource.indexOf("/*e*/");
		if (expectedEnd == -1) {
			throw new AssertionError("Invalid test case. Missing end marker /*e*/");
		}
		if (fullSource.indexOf("/*s*/", expectedStart + 1) != -1) {
			throw new AssertionError("Invalid test case. Duplicate start marker /*s*/");
		}
		if (fullSource.indexOf("/*e*/", expectedEnd + 1) != -1) {
			throw new AssertionError("Invalid test case. Duplicate end marker /*e*/");
		}

		DiagnosticCollector<JavaFileObject> diagnostics = new DiagnosticCollector<>();
		JavaCompiler javac = ToolProvider.getSystemJavaCompiler();
		CompilationTask task = javac.getTask(null, null, diagnostics, List.of(
			"-cp", System.getProperty("java.class.path")), null,
			List.of(new JavaSourceFromString("test/source/TestSource.java", fullSource)));
		task.call();
		Diagnostic<?> oneError = Unique.assertOne(
			diagnostics.getDiagnostics().stream().filter(d -> d.getKind() == Kind.ERROR));
		assertEquals("Error position mismatch",
			fullSource.substring(expectedStart + "/*s*/".length(), expectedEnd),
			fullSource.substring((int) oneError.getStartPosition(),
				(int) oneError.getEndPosition()));
	}
}
