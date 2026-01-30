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
package ghidra.pcode.emu.jit.gen;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.io.*;
import java.lang.invoke.MethodHandles;
import java.math.BigInteger;
import java.nio.file.Files;
import java.util.*;
import java.util.Map.Entry;
import java.util.stream.Collectors;

import org.objectweb.asm.*;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.util.TraceClassVisitor;

import generic.Unique;
import ghidra.app.plugin.assembler.*;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.pcode.emu.PcodeEmulator;
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.emu.jit.*;
import ghidra.pcode.emu.jit.JitPassage.AddrCtx;
import ghidra.pcode.emu.jit.analysis.*;
import ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage;
import ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage.EntryPointPrototype;
import ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassageClass;
import ghidra.pcode.error.LowlevelError;
import ghidra.pcode.exec.*;
import ghidra.pcode.exec.PcodeArithmetic.Purpose;
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.NumericUtilities;
import ghidra.util.SystemUtilities;

@SuppressWarnings("javadoc")
public abstract class AbstractJitCodeGeneratorTest extends AbstractJitTest {

	// NOTE: Limit logged output in nightly/batch test mode
	protected static final boolean DEBUG_ENABLED = !SystemUtilities.isInTestingBatchMode();
	protected static final PrintWriter DEBUG_WRITER =
		DEBUG_ENABLED ? new PrintWriter(System.out) : null;

	protected static final long LONG_CONST = 0xdeadbeefcafebabeL;

	public static void dumpProgram(PcodeProgram program) {
		if (!DEBUG_ENABLED) {
			return;
		}
		System.out.println(program);
	}

	public static void dumpClass(byte[] classbytes) throws Exception {
		if (!DEBUG_ENABLED) {
			return;
		}
		File tmp = Files.createTempFile("gen", ".class").toFile();
		try (FileOutputStream out = new FileOutputStream(tmp)) {
			out.write(classbytes);
		}
		new ProcessBuilder("javap", "-c", "-l", tmp.getPath()).inheritIO().start().waitFor();
	}

	record Translation(PcodeProgram program, MethodNode init, MethodNode run, JitPcodeThread thread,
			TestUseropLibrary library, JitBytesPcodeExecutorState state,
			JitCompiledPassageClass passageCls, JitCompiledPassage passage) {

		public void runErr(Class<? extends Throwable> excType, String message) {
			try {
				passage.run(0);
			}
			catch (Throwable e) {
				if (!excType.isInstance(e)) {
					fail("Expected error of type " + excType.getSimpleName() + ", but was " + e);
				}
				assertEquals(message, e.getMessage());
				return;
			}
			fail("Expected error of type " + excType.getSimpleName() + ", but there was none.");
		}

		public void runLowlevelErr(String message) {
			runErr(LowlevelError.class, message);
		}

		public void runDecodeErr(long pc) {
			runErr(DecodePcodeExecutionException.class,
				"Unknown disassembly error (PC=%08x)".formatted(pc));
		}

		public void runFallthrough() {
			assertEquals(0xdeadbeefL, runClean());
		}

		public void runFallthrough32() {
			assertEquals(0xdeadbeef, (int) runClean());
		}

		public long runClean() {
			passage.run(0);
			return thread.getCounter().getOffset();
		}

		public long getLongRegVal(Register reg) {
			byte[] raw = state.getVar(reg, Reason.INSPECT);
			return thread.getArithmetic().toLong(raw, Purpose.INSPECT);
		}

		public RegisterValue getRegVal(Register reg) {
			byte[] raw = state.getVar(reg, Reason.INSPECT);
			return thread.getArithmetic().toRegisterValue(reg, raw, Purpose.INSPECT);
		}

		public long getLongRegVal(String name) {
			Register reg = thread.getLanguage().getRegister(name);
			return getLongRegVal(reg);
		}

		public long getLongVnVal(Varnode vn) {
			byte[] raw = state.getVar(vn, Reason.INSPECT);
			return thread.getArithmetic().toLong(raw, Purpose.INSPECT);
		}

		public long getLongMemVal(long offset, int size) {
			AddressSpace space = thread.getLanguage().getDefaultSpace();
			byte[] raw = state.getVar(space, offset, size, false, Reason.INSPECT);
			return thread.getArithmetic().toLong(raw, Purpose.INSPECT);
		}

		public void setLongRegVal(Register reg, long value) {
			byte[] raw = thread.getArithmetic().fromConst(value, reg.getNumBytes());
			state.setVar(reg, raw);
		}

		public void setLongRegVal(String name, long value) {
			Register reg = thread.getLanguage().getRegister(name);
			setLongRegVal(reg, value);
		}

		public void setLongVnVal(Varnode vn, long value) {
			byte[] raw = thread.getArithmetic().fromConst(value, vn.getSize());
			state.setVar(vn, raw);
		}

		public void setLongMemVal(long offset, long value, int size) {
			byte[] raw = thread.getArithmetic().fromConst(value, size);
			AddressSpace space = thread.getLanguage().getDefaultSpace();
			state.setVar(space, offset, size, false, raw);
		}

		public Entry<AddrCtx, EntryPointPrototype> entryPrototype(Address addr, RegisterValue ctx,
				int blockId) {
			return Map.entry(new AddrCtx(ctx, addr), new EntryPointPrototype(passageCls, blockId));
		}
	}

	public Translation translateProgram(PcodeProgram program, JitPcodeThread thread)
			throws Exception {

		dumpProgram(program);

		JitAnalysisContext context = makeContext(program, thread);
		JitControlFlowModel cfm = new JitControlFlowModel(context);
		JitDataFlowModel dfm = new JitDataFlowModel(context, cfm);
		JitVarScopeModel vsm = new JitVarScopeModel(cfm, dfm);
		JitTypeModel tm = new JitTypeModel(dfm);
		JitAllocationModel am = new JitAllocationModel(context, dfm, vsm, tm);
		JitOpUseModel oum = new JitOpUseModel(context, cfm, dfm, vsm);

		JitCodeGenerator<?> gen =
			new JitCodeGenerator<>(MethodHandles.lookup(), context, cfm, dfm, vsm, tm, am, oum);

		byte[] classbytes = gen.generate();

		dumpClass(classbytes);

		ClassNode cn = new ClassNode(Opcodes.ASM9);
		ClassReader cr = new ClassReader(classbytes);
		ClassVisitor cv = DEBUG_ENABLED ? new TraceClassVisitor(cn, DEBUG_WRITER) : cn;
		cr.accept(cv, 0);

		// Have the JVM validate this thing
		JitBytesPcodeExecutorState state = thread.getState();
		JitCompiledPassageClass passageCls =
			JitCompiledPassageClass.load(MethodHandles.lookup(), classbytes);
		JitCompiledPassage passage = passageCls.createInstance(thread);

		assertEquals(Set.of(
			"<clinit>", "<init>", "run", "thread"),
			cn.methods.stream().map(m -> m.name).collect(Collectors.toSet()));

		MethodNode initMethod =
			Unique.assertOne(cn.methods.stream().filter(m -> "<init>".equals(m.name)));
		MethodNode runMethod =
			Unique.assertOne(cn.methods.stream().filter(m -> "run".equals(m.name)));
		return new Translation(program, initMethod, runMethod, thread,
			(TestUseropLibrary) thread.getMachine().getUseropLibrary(), state, passageCls, passage);
	}

	public static class TestUseropLibrary extends AnnotatedPcodeUseropLibrary<byte[]> {
		boolean gotJavaUseropCall = false;
		PcodeOp recordedOp = null;
		boolean gotFuncUseropCall = false;
		boolean gotSleighUseropCall = false;

		@PcodeUserop
		public long java_userop(long a, long b, @OpOp PcodeOp op) {
			gotJavaUseropCall = true;
			recordedOp = op;
			return 2 * a + b;
		}

		@PcodeUserop(functional = true)
		public long func_userop(long a, long b) {
			gotFuncUseropCall = true;
			return 2 * a + b;
		}

		@PcodeUserop(functional = true)
		public static long func_st_userop(long a, long b) {
			return 3 * a + b;
		}

		@PcodeUserop(functional = true)
		public void func_mpUserop(@OpOutput int[] out, int[] a, int[] b) {
			gotFuncUseropCall = true;

			if (out == null) {
				return;
			}

			out[0] = b[0];
			out[1] = a[0];
			for (int i = 0; i < 8; i++) {
				out[0] |= out[0] << 4;
				out[1] |= out[1] << 4;
			}
		}

		@PcodeUserop(functional = true)
		public static void func_st_mpUserop(@OpOutput int[] out, int[] a, int[] b) {
			if (out == null) {
				return;
			}

			out[0] = b[0];
			out[1] = a[0];
			for (int i = 0; i < 8; i++) {
				out[0] |= out[0] << 8;
				out[1] |= out[1] << 8;
			}
		}

		@PcodeUserop(canInline = true)
		public void sleigh_userop(@OpExecutor PcodeExecutor<byte[]> executor,
				@OpLibrary PcodeUseropLibrary<byte[]> library,
				@OpOutput Varnode out, Varnode a, Varnode b) {
			gotSleighUseropCall = true;
			PcodeProgram opProg = SleighProgramCompiler.compileUserop(executor.getLanguage(),
				"sleigh_userop", List.of("__result", "a", "b"), """
						__result = 2*a + b;
						""", library, List.of(out, a, b));
			executor.execute(opProg, library);
		}

		@PcodeUserop(functional = true)
		public int tap_int(int a) {
			System.err.println("tap: %x".formatted(a));
			return a;
		}
	}

	public static class TestJitPcodeEmulator extends JitPcodeEmulator {
		public TestJitPcodeEmulator(Language language) {
			super(language, new JitConfiguration(), MethodHandles.lookup());
		}

		@Override
		protected PcodeUseropLibrary<byte[]> createUseropLibrary() {
			return new TestUseropLibrary();
		}
	}

	public static class TestPlainPcodeEmulator extends PcodeEmulator {
		public TestPlainPcodeEmulator(Language language) {
			super(language);
		}

		@Override
		protected PcodeUseropLibrary<byte[]> createUseropLibrary() {
			return new TestUseropLibrary();
		}
	}

	record Eval(String expr, BigInteger value) {}

	static Eval ev(String name, BigInteger value) {
		return new Eval(name, value);
	}

	static Eval ev(String name, String value) {
		BigInteger bi = NumericUtilities.decodeBigInteger(value);
		return ev(name, bi);
	}

	static Eval ev(String name, double value) {
		BigInteger bi = BigInteger.valueOf(Double.doubleToRawLongBits(value));
		return new Eval(name, bi);
	}

	static Eval ev(String name, float value) {
		BigInteger bi = BigInteger.valueOf(Integer.toUnsignedLong(Float.floatToRawIntBits(value)));
		return new Eval(name, bi);
	}

	record Case(String name, String init, List<Eval> evals) {}

	static final int nNaNf = Float.floatToRawIntBits(Float.NaN) | Integer.MIN_VALUE;
	static final long nNaNd = Double.doubleToRawLongBits(Double.NaN) | Long.MIN_VALUE;
	static final BigInteger nNaN_F = BigInteger.valueOf(nNaNf);
	static final BigInteger nNaN_D = BigInteger.valueOf(nNaNd);

	protected abstract LanguageID getLanguageID();

	protected void runEquivalenceTest(Translation tr, List<Case> cases) {
		PcodeEmulator plainEmu = new TestPlainPcodeEmulator(tr.program.getLanguage());
		PcodeThread<byte[]> plainThread = plainEmu.newThread();

		for (Case c : cases) {
			if (!c.init.isBlank()) {
				plainThread.getExecutor().executeSleigh(c.init);
				tr.thread.getExecutor().executeSleigh(c.init);
			}

			plainThread.getExecutor().execute(tr.program, plainThread.getUseropLibrary());
			assertEquals("Mismatch of PC.", plainThread.getCounter().getOffset(), tr.runClean());

			for (Eval e : c.evals) {
				PcodeExpression expr =
					SleighProgramCompiler.compileExpression(tr.program.getLanguage(), e.expr);
				BigInteger plnResult = plainThread.getArithmetic()
						.toBigInteger(expr.evaluate(plainThread.getExecutor()), Purpose.INSPECT);
				BigInteger jitResult = tr.thread.getArithmetic()
						.toBigInteger(expr.evaluate(tr.thread.getExecutor()), Purpose.INSPECT);

				BigInteger expResult =
					new RegisterValue(tr.program.getLanguage().getRegister(e.expr), e.value)
							.getUnsignedValue();

				assertEquals(
					"WRONG ASSERTION For case '%s': Mismatch of '%s'.".formatted(c.name, e.expr),
					expResult.toString(16), plnResult.toString(16));
				assertEquals("For case '%s': Mismatch of '%s'.".formatted(c.name, e.expr),
					expResult.toString(16), jitResult.toString(16));
			}
		}
	}

	public Translation translateSleigh(LanguageID langId, String source) throws Exception {
		SleighLanguage language = (SleighLanguage) DefaultLanguageService.getLanguageService()
				.getLanguage(langId);
		List<String> lines = new ArrayList<>(Arrays.asList(source.split("\n")));
		if (!lines.getLast().startsWith("goto ")) {
			// Cannot end with fall-through
			// TODO: how to specify positive?
			lines.add("goto 0xdeadbeef;");
			source = lines.stream().collect(Collectors.joining("\n"));
		}
		JitPcodeEmulator emu = new TestJitPcodeEmulator(language);
		JitPcodeThread thread = emu.newThread();
		PcodeProgram program = SleighProgramCompiler.compileProgram(language, "test", source,
			thread.getUseropLibrary());
		return translateProgram(program, thread);
	}

	public AssemblyBuffer createBuffer(LanguageID languageID, long entry) throws Exception {
		Language language = DefaultLanguageService.getLanguageService().getLanguage(languageID);
		Address addr = language.getDefaultSpace().getAddress(entry);
		Assembler asm = Assemblers.getAssembler(language);
		return new AssemblyBuffer(asm, addr);
	}

	public Translation translateBuffer(AssemblyBuffer buf, Address entry, Map<Long, String> injects)
			throws Exception {
		Language language = buf.getAssembler().getLanguage();

		JitPcodeEmulator emu = new TestJitPcodeEmulator(language);
		AddressSpace space = language.getDefaultSpace();
		for (Map.Entry<Long, String> ent : injects.entrySet()) {
			emu.inject(space.getAddress(ent.getKey()), ent.getValue());
		}
		JitPcodeThread thread = emu.newThread();
		byte[] bytes = buf.getBytes();
		emu.getSharedState().setVar(buf.getEntry(), bytes.length, false, bytes);

		thread.setCounter(entry);
		thread.overrideContextWithDefault();
		JitPassage passage = decodePassage(thread);
		return translateProgram(passage, thread);
	}

	public Translation translateLang(LanguageID languageID, long offset, String source,
			Map<Long, String> injects)
			throws Exception {
		AssemblyBuffer buf = createBuffer(languageID, offset);
		for (String line : source.split("\n")) {
			if (line.isBlank()) {
			}
			else if (line.startsWith(".emit ")) {
				buf.emit(NumericUtilities
						.convertStringToBytes(line.substring(".emit ".length()).replace(" ", "")));
			}
			else {
				buf.assemble(line);
			}
		}
		return translateBuffer(buf, buf.getEntry(), injects);
	}
}
