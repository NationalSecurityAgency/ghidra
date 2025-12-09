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

import static ghidra.lifecycle.Unfinished.*;
import static org.junit.Assert.*;

import java.io.*;
import java.lang.invoke.MethodHandles;
import java.math.BigInteger;
import java.nio.file.Files;
import java.util.*;
import java.util.Map.Entry;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.junit.Ignore;
import org.junit.Test;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.*;
import org.objectweb.asm.util.TraceClassVisitor;

import generic.Unique;
import ghidra.app.plugin.assembler.*;
import ghidra.app.plugin.assembler.sleigh.sem.AssemblyPatternBlock;
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
import ghidra.pcode.floatformat.FloatFormat;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.NumericUtilities;

@SuppressWarnings("javadoc")
public class JitCodeGeneratorTest extends AbstractJitTest {
	private static final LanguageID ID_TOYBE64 = new LanguageID("Toy:BE:64:default");
	private static final LanguageID ID_TOYLE64 = new LanguageID("Toy:LE:64:default");
	private static final LanguageID ID_TOYBE32 = new LanguageID("Toy:BE:32:default");
	private static final LanguageID ID_ARMv8LE = new LanguageID("ARM:LE:32:v8");
	private static final LanguageID ID_X8664 = new LanguageID("x86:LE:64:default");

	private static final long LONG_CONST = 0xdeadbeefcafebabeL;

	// NOTE: Limit logged output in nightly/batch test mode
	private static boolean DEBUG_ENABLED = false; // !SystemUtilities.isInTestingBatchMode();

	private PrintWriter debugWriter = DEBUG_ENABLED ? new PrintWriter(System.out) : null;

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
			assertEquals(0xdeadbeef, runClean());
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

		JitCodeGenerator gen =
			new JitCodeGenerator(MethodHandles.lookup(), context, cfm, dfm, vsm, tm, am, oum);

		byte[] classbytes = gen.generate();

		dumpClass(classbytes);

		ClassNode cn = new ClassNode(Opcodes.ASM9);
		ClassReader cr = new ClassReader(classbytes);
		cr.accept(new TraceClassVisitor(cn, debugWriter), 0);

		// Have the JVM validate this thing
		JitBytesPcodeExecutorState state = thread.getState();
		JitCompiledPassageClass passageCls =
			JitCompiledPassageClass.load(MethodHandles.lookup(), classbytes);
		JitCompiledPassage passage = passageCls.createInstance(thread);

		assertEquals(Set.of("<clinit>", "<init>", "run", "thread"),
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
		boolean gotFuncUseropCall = false;
		boolean gotSleighUseropCall = false;

		@PcodeUserop
		public long java_userop(long a, long b) {
			gotJavaUseropCall = true;
			return 2 * a + b;
		}

		@PcodeUserop(functional = true)
		public long func_userop(long a, long b) {
			gotFuncUseropCall = true;
			return 2 * a + b;
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

		@PcodeUserop(canInline = true)
		public void sleigh_userop(@OpExecutor PcodeExecutor<byte[]> executor,
				@OpLibrary PcodeUseropLibrary<byte[]> library, @OpOutput Varnode out, Varnode a,
				Varnode b) {
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

	record Eval(String expr, BigInteger value) {
	}

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

	/**
	 * @deprecated Because this one is accident prone when it comes to signedness. Use
	 *             {@link #ev(String, String)} instead.
	 */
	@Deprecated // Just produce a warning
	static Eval ev(String name, long value) {
		throw new AssertionError("Use the String or BigInteger one instead");
	}

	record Case(String name, String init, List<Eval> evals) {
	}

	static final int nNaNf = Float.floatToRawIntBits(Float.NaN) | Integer.MIN_VALUE;
	static final long nNaNd = Double.doubleToRawLongBits(Double.NaN) | Long.MIN_VALUE;
	static final BigInteger nNaN_F = BigInteger.valueOf(nNaNf);
	static final BigInteger nNaN_D = BigInteger.valueOf(nNaNd);

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
		SleighLanguage language =
			(SleighLanguage) DefaultLanguageService.getLanguageService().getLanguage(langId);
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
			Map<Long, String> injects) throws Exception {
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

	public Translation translateToy(long offset, String source) throws Exception {
		return translateLang(ID_TOYBE64, offset, source, Map.of());
	}

	@Test
	public void testSimpleInt() throws Exception {
		Translation tr = translateSleigh(ID_TOYBE64, """
				temp:4 = 0x1234;
				""");
		Varnode temp = tr.program.getCode().getFirst().getOutput();
		assertTrue(temp.isUnique());
		tr.runFallthrough();
		assertEquals(0x1234, tr.getLongVnVal(temp));
	}

	@Test
	public void testToyOneBlockHasFallthroughExit() throws Exception {
		Translation tr = translateToy(0x00400000, """
				imm r0, #0x123
				""");
		tr.runDecodeErr(0x00400002);
		assertEquals(0x123, tr.getLongRegVal("r0"));
	}

	@Test
	public void testSimpleLong() throws Exception {
		Translation tr = translateSleigh(ID_TOYBE64, """
				temp:8 = 0x1234;
				""");
		Varnode temp = tr.program.getCode().getFirst().getOutput();
		assertTrue(temp.isUnique());
		tr.runFallthrough();
		assertEquals(0x1234, tr.getLongVnVal(temp));
	}

	@Test
	public void testSimpleFloat() throws Exception {
		int fDot5 = Float.floatToRawIntBits(0.5f);
		int fDot75 = Float.floatToRawIntBits(0.75f);
		Translation tr = translateSleigh(ID_TOYBE64, """
				temp:4 = 0x%x f+ 0x%x;
				""".formatted(fDot5, fDot75));
		Varnode temp = tr.program.getCode().getFirst().getOutput();
		assertTrue(temp.isUnique());
		tr.runFallthrough();
		assertEquals(1.25f, Float.intBitsToFloat((int) tr.getLongVnVal(temp)), 0);
	}

	@Test
	public void testSimpleDouble() throws Exception {
		long dDot5 = Double.doubleToRawLongBits(0.5);
		long dDot75 = Double.doubleToRawLongBits(0.75);
		Translation tr = translateSleigh(ID_TOYBE64, """
				temp:8 = 0x%x f+ 0x%x;
				""".formatted(dDot5, dDot75));
		Varnode temp = tr.program.getCode().getFirst().getOutput();
		assertTrue(temp.isUnique());
		tr.runFallthrough();
		assertEquals(1.25f, Double.longBitsToDouble(tr.getLongVnVal(temp)), 0);
	}

	@Test
	public void testReadMemMappedRegBE() throws Exception {
		Translation tr = translateSleigh(ID_TOYBE64, """
				* 0:8 = 0x%x:8;
				temp:8 = mmr0;
				""".formatted(LONG_CONST));
		Varnode temp = tr.program.getCode().get(1).getOutput();
		assertTrue(temp.isUnique());
		tr.runFallthrough();
		assertEquals(LONG_CONST, tr.getLongVnVal(temp));
	}

	@Test
	public void testReadMemDirectWithPartsSpanningBlockBE() throws Exception {
		long offset = GenConsts.BLOCK_SIZE - 2;
		Translation tr = translateSleigh(ID_TOYBE64, """
				temp:8 = * 0x%x:8;
				""".formatted(offset));
		tr.setLongMemVal(offset, LONG_CONST, 8);
		Varnode temp = tr.program.getCode().getFirst().getOutput();
		assertTrue(temp.isUnique());
		tr.runFallthrough();
		assertEquals(LONG_CONST, tr.getLongVnVal(temp));
	}

	@Test
	public void testReadMemDirectWithPartsSpanningBlockLE() throws Exception {
		long offset = GenConsts.BLOCK_SIZE - 2;
		Translation tr = translateSleigh(ID_TOYLE64, """
				temp:8 = * 0x%x:8;
				""".formatted(offset));
		tr.setLongMemVal(offset, LONG_CONST, 8);
		Varnode temp = tr.program.getCode().getFirst().getOutput();
		assertTrue(temp.isUnique());
		tr.runFallthrough();
		assertEquals(LONG_CONST, tr.getLongVnVal(temp));
	}

	@Test
	@Ignore("Undefined")
	public void testReadMemDirectWithSpanWrapSpaceBE() throws Exception {
		long offset = -2;
		Translation tr = translateSleigh(ID_TOYBE64, """
				temp:8 = * 0x%x:8;
				""".formatted(offset));
		tr.setLongMemVal(offset, LONG_CONST, 8);
		Varnode temp = tr.program.getCode().getFirst().getOutput();
		assertTrue(temp.isUnique());
		tr.runFallthrough();
		assertEquals(LONG_CONST, tr.getLongVnVal(temp));
	}

	@Test
	@Ignore("Undefined")
	public void testReadMemDirectWithSpanWrapSpaceLE() throws Exception {
		long offset = -2;
		Translation tr = translateSleigh(ID_TOYLE64, """
				temp:8 = * 0x%x:8;
				""".formatted(offset));
		tr.setLongMemVal(offset, LONG_CONST, 8);
		Varnode temp = tr.program.getCode().getFirst().getOutput();
		assertTrue(temp.isUnique());
		tr.runFallthrough();
		assertEquals(LONG_CONST, tr.getLongVnVal(temp));
	}

	@Test
	public void testWriteMemDirectWithPartsSpanningBlockBE() throws Exception {
		long offset = GenConsts.BLOCK_SIZE - 2;
		Translation tr = translateSleigh(ID_TOYBE64, """
				local temp:8;
				* 0x%x:8 = temp;
				""".formatted(offset));
		Varnode temp = tr.program.getCode().getFirst().getInput(2);
		assertTrue(temp.isUnique());
		tr.setLongVnVal(temp, LONG_CONST);
		tr.runFallthrough();
		assertEquals(LONG_CONST, tr.getLongMemVal(offset, 8));
	}

	@Test
	public void testWriteMemDirectWithPartsSpanningBlockLE() throws Exception {
		long offset = GenConsts.BLOCK_SIZE - 2;
		Translation tr = translateSleigh(ID_TOYLE64, """
				local temp:8;
				* 0x%x:8 = temp;
				""".formatted(offset));
		Varnode temp = tr.program.getCode().getFirst().getInput(2);
		assertTrue(temp.isUnique());
		tr.setLongVnVal(temp, LONG_CONST);
		tr.runFallthrough();
		assertEquals(LONG_CONST, tr.getLongMemVal(offset, 8));
	}

	@Test
	@Ignore("Undefined")
	public void testWriteMemDirectWithSpanWrapSpaceBE() throws Exception {
		long offset = -2;
		Translation tr = translateSleigh(ID_TOYBE64, """
				local temp:8;
				* 0x%x:8 = temp;
				""".formatted(offset));
		Varnode temp = tr.program.getCode().getFirst().getInput(2);
		assertTrue(temp.isUnique());
		tr.setLongVnVal(temp, LONG_CONST);
		tr.runFallthrough();
		assertEquals(LONG_CONST, tr.getLongMemVal(offset, 8));
	}

	@Test
	@Ignore("Undefined")
	public void testWriteMemDirectWithSpanWrapSpaceLE() throws Exception {
		long offset = -2;
		Translation tr = translateSleigh(ID_TOYLE64, """
				local temp:8;
				* 0x%x:8 = temp;
				""".formatted(offset));
		Varnode temp = tr.program.getCode().getFirst().getInput(2);
		assertTrue(temp.isUnique());
		tr.setLongVnVal(temp, LONG_CONST);
		tr.runFallthrough();
		assertEquals(LONG_CONST, tr.getLongMemVal(offset, 8));
	}

	@Test
	public void testReadMemIndirectBE() throws Exception {
		long offset = GenConsts.BLOCK_SIZE - 2;
		Translation tr = translateSleigh(ID_TOYBE64, """
				local temp:8;
				local addr:8;
				temp = * addr;
				""");
		Varnode temp = tr.program.getCode().getFirst().getOutput();
		Varnode addr = tr.program.getCode().getFirst().getInput(1);
		assertTrue(temp.isUnique());
		assertTrue(addr.isUnique());
		tr.setLongMemVal(offset, LONG_CONST, 8);
		tr.setLongVnVal(addr, offset);
		tr.runFallthrough();
		assertEquals(LONG_CONST, tr.getLongVnVal(temp));
	}

	@Test
	public void testReadMemIndirectLE() throws Exception {
		long offset = GenConsts.BLOCK_SIZE - 2;
		Translation tr = translateSleigh(ID_TOYLE64, """
				local temp:8;
				local addr:8;
				temp = * addr;
				""");
		Varnode temp = tr.program.getCode().getFirst().getOutput();
		Varnode addr = tr.program.getCode().getFirst().getInput(1);
		assertTrue(temp.isUnique());
		assertTrue(addr.isUnique());
		tr.setLongMemVal(offset, LONG_CONST, 8);
		tr.setLongVnVal(addr, offset);
		tr.runFallthrough();
		assertEquals(LONG_CONST, tr.getLongVnVal(temp));
	}

	@Test
	public void testWriteMemIndirectBE() throws Exception {
		long offset = GenConsts.BLOCK_SIZE - 2;
		Translation tr = translateSleigh(ID_TOYBE64, """
				local temp:8;
				local addr:8;
				* addr = temp;
				""");
		Varnode temp = tr.program.getCode().getFirst().getInput(2);
		Varnode addr = tr.program.getCode().getFirst().getInput(1);
		assertTrue(temp.isUnique());
		assertTrue(addr.isUnique());
		tr.setLongVnVal(temp, LONG_CONST);
		tr.setLongVnVal(addr, offset);
		tr.runFallthrough();
		assertEquals(LONG_CONST, tr.getLongMemVal(offset, 8));
	}

	@Test
	public void testWriteMemIndirectLE() throws Exception {
		long offset = GenConsts.BLOCK_SIZE - 2;
		Translation tr = translateSleigh(ID_TOYLE64, """
				local temp:8;
				local addr:8;
				* addr = temp;
				""");
		Varnode temp = tr.program.getCode().getFirst().getInput(2);
		Varnode addr = tr.program.getCode().getFirst().getInput(1);
		assertTrue(temp.isUnique());
		assertTrue(addr.isUnique());
		tr.setLongVnVal(temp, LONG_CONST);
		tr.setLongVnVal(addr, offset);
		tr.runFallthrough();
		assertEquals(LONG_CONST, tr.getLongMemVal(offset, 8));
	}

	@Test
	public void testAddressSize32() throws Exception {
		long offset = GenConsts.BLOCK_SIZE - 2;
		Translation tr = translateSleigh(ID_TOYBE32, """
				local temp:8;
				local addr:4;
				* addr = temp;
				""");
		Varnode temp = tr.program.getCode().getFirst().getInput(2);
		Varnode addr = tr.program.getCode().getFirst().getInput(1);
		assertTrue(temp.isUnique());
		assertTrue(addr.isUnique());
		tr.setLongVnVal(temp, LONG_CONST);
		tr.setLongVnVal(addr, offset);
		tr.runFallthrough32();
		assertEquals(LONG_CONST, tr.getLongMemVal(offset, 8));
	}

	@Test
	public void testVariablesAreRetiredBranchInd() throws Exception {
		/**
		 * Considering detection of inter-passage indirect branching, I think this will complicate
		 * things way too much. All of the control-flow analysis must consider indirect flows, and
		 * then, the dataflow could be affected by that, so there's a circular dependency. With some
		 * care, that can be done, though I'm not sure it's always guaranteed to converge. Another
		 * possibility is to retire all the variables, but then, there has to be a special branch
		 * target that knows to birth the appropriate ones before entering the real block.
		 */
		Translation tr = translateSleigh(ID_TOYBE64, """
				local jump:8;
				temp:8 = 0x%x;
				goto [jump];
				""".formatted(LONG_CONST));
		Varnode temp = tr.program.getCode().getFirst().getOutput();
		Varnode jump = tr.program.getCode().get(1).getInput(0);
		assertTrue(temp.isUnique());
		assertTrue(jump.isUnique());
		tr.setLongVnVal(jump, 0x1234);
		assertEquals(0x1234, tr.runClean());
		assertEquals(LONG_CONST, tr.getLongVnVal(temp));
	}

	/**
	 * Test reading from a variable in an unreachable block.
	 * 
	 * <p>
	 * Yes, this test is valid, because, even though no slaspec should produce this, they could, but
	 * more to the point, a user injection could. Note that the underlying classfile writer may
	 * analyze and remove the unreachable code. Doesn't matter. What matters is that it doesn't
	 * crash, and that it produces correct results.
	 */
	@Test
	public void testWithMissingVariable() throws Exception {
		Translation tr = translateSleigh(ID_TOYBE64, """
				local temp:8;
				local temp2:8;
				temp2 = 1;
				goto 0xdeadbeef;
				temp2 = temp;
				""");
		Varnode temp2 = tr.program.getCode().getFirst().getOutput();
		assertTrue(temp2.isUnique());
		tr.runFallthrough();
		assertEquals(1, tr.getLongVnVal(temp2));
	}

	void runTestMpIntOffcutLoad(LanguageID langID) throws Exception {
		runEquivalenceTest(translateSleigh(langID, """
				local temp:16;
				temp[0,64] = r1;
				temp[64,64] = r2;
				temp2:14 = temp[8,112];
				r0 = zext(temp2);
				"""), List.of(new Case("only", """
				r1 = 0x1122334455667788;
				r2 = 0x99aabbccddeeff00;
				""", List.of(ev("r0", "0x11223344556677")))));
	}

	@Test
	public void testMpIntOffcutLoadBE() throws Exception {
		runTestMpIntOffcutLoad(ID_TOYBE64);
	}

	@Test
	public void testMpIntOffcutLoadLE() throws Exception {
		runTestMpIntOffcutLoad(ID_TOYLE64);
	}

	@Test
	public void testCallOtherSleighDef() throws Exception {
		Translation tr = translateSleigh(ID_TOYBE64, """
				r0 = sleigh_userop(6:8, 2:8);
				""");
		assertTrue(tr.library.gotSleighUseropCall);
		tr.library.gotSleighUseropCall = false;
		tr.runFallthrough();
		assertFalse(tr.library.gotSleighUseropCall);
		assertEquals(14, tr.getLongRegVal("r0"));
	}

	@Test
	public void testCallOtherJavaDef() throws Exception {
		Translation tr = translateSleigh(ID_TOYBE64, """
				r0 = java_userop(6:8, 2:8);
				""");
		assertFalse(tr.library.gotJavaUseropCall);
		tr.runFallthrough();
		assertTrue(tr.library.gotJavaUseropCall);
		assertEquals(14, tr.getLongRegVal("r0"));
	}

	@Test
	public void testCallOtherJavaDefNoOut() throws Exception {
		Translation tr = translateSleigh(ID_TOYBE64, """
				java_userop(6:8, 2:8);
				""");
		assertFalse(tr.library.gotJavaUseropCall);
		tr.runFallthrough();
		assertTrue(tr.library.gotJavaUseropCall);
		assertEquals(0, tr.getLongRegVal("r0"));
	}

	@Test
	public void testCallOtherFuncJavaDef() throws Exception {
		Translation tr = translateSleigh(ID_TOYBE64, """
				r0 = func_userop(6:8, 2:8);
				""");
		assertFalse(tr.library.gotFuncUseropCall);
		tr.runFallthrough();
		assertTrue(tr.library.gotFuncUseropCall);
		assertEquals(14, tr.getLongRegVal("r0"));
	}

	@Test
	public void testCallOtherFuncJavaDefNoOut() throws Exception {
		Translation tr = translateSleigh(ID_TOYBE64, """
				func_userop(6:8, 2:8);
				""");
		assertFalse(tr.library.gotFuncUseropCall);
		tr.runFallthrough();
		assertTrue(tr.library.gotFuncUseropCall);
		assertEquals(0, tr.getLongRegVal("r0"));
	}

	@Test
	public void testCallOtherFuncJavaDefMpInt() throws Exception {
		Translation tr = translateSleigh(ID_TOYBE64, """
				temp1:9 = zext(6:8);
				temp2:9 = zext(2:8);
				temp0:9 = func_mpUserop(temp1, temp2);
				r0 = temp0(0);
				""");
		assertFalse(tr.library.gotFuncUseropCall);
		tr.runFallthrough();
		assertTrue(tr.library.gotFuncUseropCall);
		assertEquals(0x6666666622222222L, tr.getLongRegVal("r0"));
	}

	@Test
	public void testCallOtherFuncJavaDefNoOutMpInt() throws Exception {
		Translation tr = translateSleigh(ID_TOYBE64, """
				temp1:9 = zext(6:8);
				temp2:9 = zext(2:8);
				func_mpUserop(temp1, temp2);
				""");
		assertFalse(tr.library.gotFuncUseropCall);
		tr.runFallthrough();
		assertTrue(tr.library.gotFuncUseropCall);
		assertEquals(0, tr.getLongRegVal("r0"));
	}

	/**
	 * Test that the emulator doesn't throw until the userop is actually encountered at run time.
	 * 
	 * <p>
	 * NOTE: The userop must be defined by the language, but left undefined by the library.
	 * Otherwise, we cannot even compile the sample Sleigh.
	 * 
	 * <p>
	 * NOTE: Must also use actual instructions, because the test passage constructor will fail fast
	 * on the undefined userop.
	 */
	@Test
	public void testCallOtherUndef() throws Exception {
		Translation tr = translateToy(0x00400000, """
				user_one r0
				""");
		tr.runErr(SleighLinkException.class, "Sleigh userop 'pcodeop_one' is not in the library");
		assertEquals(0x00400000, tr.thread.getCounter().getOffset());
	}

	/**
	 * I need to find an example of this:
	 * 
	 * <pre>
	 *  *[register] OFFSET = ... ?
	 * </pre>
	 * 
	 * <p>
	 * Honestly, if this actually occurs frequently, we could be in trouble. We would need either:
	 * 1) To re-write all the offending semantic blocks, or 2) Work out a way to re-write them
	 * during JIT compilation. People tell me this is done by some vector instructions, which makes
	 * me thing re-writing would be possible, since they should all fold to constants. If we're
	 * lucky, the planned constant folding would just take care of these; however, I'd still want to
	 * allocate them as locals, not just direct array access. For now, I'm just going to feign
	 * ignorance. If it becomes a problem, then we can treat all register accesses like memory
	 * within the entire passage containing one of these "indirect-register-access" ops.
	 */
	@Test
	@Ignore("No examples, yet")
	public void testComputedOffsetsInRegisterSpace() throws Exception {
		TODO();
	}

	/**
	 * This is interesting, because it may necessitate MpInt DIV
	 */
	@Test
	@Ignore("TODO")
	public void testX86DIV() throws Exception {
		TODO();
	}

	@Test
	public void testBranchOpGenInternal() throws Exception {
		runEquivalenceTest(translateSleigh(ID_TOYBE64, """
				r0 = 0xbeef;
				goto <skip>;
				r0 = 0xdead;
				<skip>
				"""), List.of(new Case("only", "", List.of(ev("r0", "0xbeef")))));
	}

	@Test
	public void testBranchOpGenExternal() throws Exception {
		runEquivalenceTest(translateSleigh(ID_TOYBE64, """
				r0 = 0xbeef;
				goto 0xdeadbeef;
				r0 = 0xdead;
				"""), List.of(new Case("only", "", List.of(ev("r0", "0xbeef")))));
	}

	@Test
	public void testCBranchOpGenInternalIntPredicate() throws Exception {
		runEquivalenceTest(translateSleigh(ID_TOYBE64, """
				r0 = 0xbeef;
				if (r1!=0) goto <skip>;
				r0 = 0xdead;
				<skip>
				"""), List.of(new Case("take", "r1=1;", List.of(ev("r0", "0xbeef"))),
			new Case("fall", "r1=0;", List.of(ev("r0", "0xdead")))));
	}

	@Test
	public void testCBranchOpGenExternalLongPredicate() throws Exception {
		runEquivalenceTest(translateSleigh(ID_TOYBE64, """
				r0 = 0xbeef;
				if (r1) goto 0xdeadbeef;
				r0 = 0xdead;
				"""), List.of(new Case("take", "r1=1;", List.of(ev("r0", "0xbeef"))),
			new Case("fall", "r1=0;", List.of(ev("r0", "0xdead")))));
	}

	@Test
	public void testCBranchOpGenExternalMpIntPredicate() throws Exception {
		runEquivalenceTest(translateSleigh(ID_TOYBE64, """
				r0 = 0xbeef;
				temp:9 = zext(r1);
				if (temp) goto 0xdeadbeef;
				r0 = 0xdead;
				"""),
			List.of(new Case("sm_take", "r1 = 1;", List.of(ev("r0", "0xbeef"))),
				new Case("sm_fall", "r1 = 0;", List.of(ev("r0", "0xdead"))),
				new Case("lg_take", "r1 = 0x8000000000000000;", List.of(ev("r0", "0xbeef")))));
	}

	@Test
	public void testBoolNegateOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(ID_TOYBE64, """
				r0 = !r1;
				r6l = !r7l;
				"""), List.of(new Case("f", """
				r1 = 0;
				r7l = 0;
				""", List.of(ev("r0", "1"), ev("r6", "1"))), new Case("t", """
				r1 = 1;
				r7l = 1;
				""", List.of(ev("r0", "0"), ev("r6", "0")))));
		// NOTE: Not testing cases with other bits set
	}

	@Test
	public void testBoolNegateMpIntOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(ID_TOYBE64, """
				temp:9 = zext(r1);
				temp = !temp;
				r0 = temp(1);
				"""), List.of(new Case("f", """
				r1 = 0;
				""", List.of(ev("r0", "0")))));
	}

	@Test
	public void testBoolAndOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(ID_TOYBE64, """
				r0 = r1 && r2;
				r3 = r4 && r5l;
				r6l = r7l && r8;
				r9l = r10l && r11l;
				"""),
			List.of(new Case("ff", """
					r1  =0; r2  =0;
					r4  =0; r5l =0;
					r7l =0; r8  =0;
					r10l=0; r11l=0;
					""", List.of(ev("r0", "0"), ev("r3", "0"), ev("r6", "0"), ev("r9", "0"))),
				new Case("ft", """
						r1  =0; r2  =1;
						r4  =0; r5l =1;
						r7l =0; r8  =1;
						r10l=0; r11l=1;
						""", List.of(ev("r0", "0"), ev("r3", "0"), ev("r6", "0"), ev("r9", "0"))),
				new Case("tf", """
						r1  =1; r2  =0;
						r4  =1; r5l =0;
						r7l =1; r8  =0;
						r10l=1; r11l=0;
						""", List.of(ev("r0", "0"), ev("r3", "0"), ev("r6", "0"), ev("r9", "0"))),
				new Case("tt", """
						r1  =1; r2  =1;
						r4  =1; r5l =1;
						r7l =1; r8  =1;
						r10l=1; r11l=1;
						""", List.of(ev("r0", "1"), ev("r3", "1"), ev("r6", "1"), ev("r9", "1")))));
		// NOTE: Not testing cases with other bits set
	}

	@Test
	public void testBoolAndMpIntOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(ID_TOYBE64, """
				temp1:9 = zext(r1);
				temp2:9 = zext(r2);
				temp0:9 = temp1 && temp2;
				r0 = temp0(0);
				r3 = temp0(1);
				"""), List.of(new Case("ff", """
				r1 = 0; r2 = 0;
				""", List.of(ev("r0", "0"), ev("r3", "0"))), new Case("ft", """
				r1  =0; r2 = 1;
				""", List.of(ev("r0", "0"), ev("r3", "0"))), new Case("tf", """
				r1 = 1; r2 = 0;
				""", List.of(ev("r0", "0"), ev("r3", "0"))), new Case("tt", """
				r1 = 1; r2 = 1;
				""", List.of(ev("r0", "1"), ev("r3", "0")))));
		// NOTE: Not testing cases with other bits set
	}

	@Test
	public void testBoolOrOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(ID_TOYBE64, """
				r0 = r1 || r2;
				r3 = r4 || r5l;
				r6l = r7l || r8;
				r9l = r10l || r11l;
				"""),
			List.of(new Case("ff", """
					r1  =0; r2  =0;
					r4  =0; r5l =0;
					r7l =0; r8  =0;
					r10l=0; r11l=0;
					""", List.of(ev("r0", "0"), ev("r3", "0"), ev("r6", "0"), ev("r9", "0"))),
				new Case("ft", """
						r1  =0; r2  =1;
						r4  =0; r5l =1;
						r7l =0; r8  =1;
						r10l=0; r11l=1;
						""", List.of(ev("r0", "1"), ev("r3", "1"), ev("r6", "1"), ev("r9", "1"))),
				new Case("tf", """
						r1  =1; r2  =0;
						r4  =1; r5l =0;
						r7l =1; r8  =0;
						r10l=1; r11l=0;
						""", List.of(ev("r0", "1"), ev("r3", "1"), ev("r6", "1"), ev("r9", "1"))),
				new Case("tt", """
						r1  =1; r2  =1;
						r4  =1; r5l =1;
						r7l =1; r8  =1;
						r10l=1; r11l=1;
						""", List.of(ev("r0", "1"), ev("r3", "1"), ev("r6", "1"), ev("r9", "1")))));
		// NOTE: Not testing cases with other bits set
	}

	@Test
	public void testBoolOrMpIntOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(ID_TOYBE64, """
				temp1:9 = zext(r1);
				temp2:9 = zext(r2);
				temp0:9 = temp1 || temp2;
				r0 = temp0(0);
				r3 = temp0(1);
				"""), List.of(new Case("ff", """
				r1  =0; r2  =0;
				""", List.of(ev("r0", "0"), ev("r3", "0"))), new Case("ft", """
				r1  =0; r2  =1;
				""", List.of(ev("r0", "1"), ev("r3", "0"))), new Case("tf", """
				r1  =1; r2  =0;
				""", List.of(ev("r0", "1"), ev("r3", "0"))), new Case("tt", """
				r1  =1; r2  =1;
				""", List.of(ev("r0", "1"), ev("r3", "0")))));
		// NOTE: Not testing cases with other bits set
	}

	@Test
	public void testBoolXorOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(ID_TOYBE64, """
				r0 = r1 ^^ r2;
				r3 = r4 ^^ r5l;
				r6l = r7l ^^ r8;
				r9l = r10l ^^ r11l;
				"""),
			List.of(new Case("ff", """
					r1  =0; r2  =0;
					r4  =0; r5l =0;
					r7l =0; r8  =0;
					r10l=0; r11l=0;
					""", List.of(ev("r0", "0"), ev("r3", "0"), ev("r6", "0"), ev("r9", "0"))),
				new Case("ft", """
						r1  =0; r2  =1;
						r4  =0; r5l =1;
						r7l =0; r8  =1;
						r10l=0; r11l=1;
						""", List.of(ev("r0", "1"), ev("r3", "1"), ev("r6", "1"), ev("r9", "1"))),
				new Case("tf", """
						r1  =1; r2  =0;
						r4  =1; r5l =0;
						r7l =1; r8  =0;
						r10l=1; r11l=0;
						""", List.of(ev("r0", "1"), ev("r3", "1"), ev("r6", "1"), ev("r9", "1"))),
				new Case("tt", """
						r1  =1; r2  =1;
						r4  =1; r5l =1;
						r7l =1; r8  =1;
						r10l=1; r11l=1;
						""", List.of(ev("r0", "0"), ev("r3", "0"), ev("r6", "0"), ev("r9", "0")))));
		// NOTE: Not testing cases with other bits set
	}

	@Test
	public void testBoolXorMpIntOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(ID_TOYBE64, """
				temp1:9 = zext(r1);
				temp2:9 = zext(r2);
				temp0:9 = temp1 ^^ temp2;
				r0 = temp0(0);
				r3 = temp0(1);
				"""), List.of(new Case("ff", """
				r1  =0; r2  =0;
				""", List.of(ev("r0", "0"), ev("r3", "0"))), new Case("ft", """
				r1  =0; r2  =1;
				""", List.of(ev("r0", "1"), ev("r3", "0"))), new Case("tf", """
				r1  =1; r2  =0;
				""", List.of(ev("r0", "1"), ev("r3", "0"))), new Case("tt", """
				r1  =1; r2  =1;
				""", List.of(ev("r0", "0"), ev("r3", "0")))));
		// NOTE: Not testing cases with other bits set
	}

	@Test
	public void testFloatAbsOpGen() throws Exception {
		long d0dot5 = Double.doubleToLongBits(0.5);
		long dn0dot5 = Double.doubleToLongBits(-0.5);
		int f0dot5 = Float.floatToIntBits(0.5f);
		int fn0dot5 = Float.floatToIntBits(-0.5f);
		runEquivalenceTest(translateSleigh(ID_TOYBE64, """
				r0 = abs(r1);
				r6l = abs(r7l);
				"""), List.of(new Case("p", """
				r1  =0x%x;
				r7l =0x%x;
				""".formatted(d0dot5, f0dot5), List.of(ev("r0", 0.5d), ev("r6", 0.5f))),
			new Case("n", """
					r1  =0x%x;
					r7l =0x%x;
					""".formatted(dn0dot5, fn0dot5), List.of(ev("r0", 0.5d), ev("r6", 0.5f)))));
	}

	/**
	 * Note that the test case for sqrt(n) where n is negative could be brittle, because of
	 * undefined behavior in the IEEE 754 spec. My JVM will result in "negative NaN." It used to be
	 * this test failed, but I've made an adjustment to {@link FloatFormat} to ensure it keeps
	 * whatever sign bit was returned by {@link Math#sqrt(double)}. It shouldn't matter to the
	 * emulation target one way or another (in theory), but I do want to ensure the two emulators
	 * behave the same. It seems easier to me to have {@link FloatFormat} keep the sign bit than to
	 * have the JIT compile in code that checks for and fixes "negative NaN." Less run-time cost,
	 * too.
	 */
	@Test
	public void testFloatSqrtOpGen() throws Exception {
		long d0dot5 = Double.doubleToLongBits(0.5);
		long dn0dot5 = Double.doubleToLongBits(-0.5);
		int f0dot5 = Float.floatToIntBits(0.5f);
		int fn0dot5 = Float.floatToIntBits(-0.5f);
		runEquivalenceTest(translateSleigh(ID_TOYBE64, """
				r0 = sqrt(r1);
				r6l = sqrt(r7l);
				"""),
			List.of(
				new Case("p", """
						r1  =0x%x;
						r7l =0x%x;
						""".formatted(d0dot5, f0dot5),
					List.of(ev("r0", Math.sqrt(0.5)), ev("r6", (float) Math.sqrt(0.5)))),
				new Case("n", """
						r1  =0x%x;
						r7l =0x%x;
						""".formatted(dn0dot5, fn0dot5),
					List.of(ev("r0", nNaN_D), ev("r6l", nNaN_F)))));
	}

	@Test
	public void testFloatCeilOpGen() throws Exception {
		long d0dot5 = Double.doubleToLongBits(0.5);
		long dn0dot5 = Double.doubleToLongBits(-0.5);
		int f0dot5 = Float.floatToIntBits(0.5f);
		int fn0dot5 = Float.floatToIntBits(-0.5f);
		runEquivalenceTest(translateSleigh(ID_TOYBE64, """
				r0 = ceil(r1);
				r6l = ceil(r7l);
				"""), List.of(new Case("p", """
				r1  =0x%x;
				r7l =0x%x;
				""".formatted(d0dot5, f0dot5), List.of(ev("r0", 1.0d), ev("r6", 1.0f))),
			new Case("n", """
					r1  =0x%x;
					r7l =0x%x;
					""".formatted(dn0dot5, fn0dot5), List.of(ev("r0", -0.0d), ev("r6", -0.0f)))));
	}

	@Test
	public void testFloatFloorOpGen() throws Exception {
		long d0dot5 = Double.doubleToLongBits(0.5);
		long dn0dot5 = Double.doubleToLongBits(-0.5);
		int f0dot5 = Float.floatToIntBits(0.5f);
		int fn0dot5 = Float.floatToIntBits(-0.5f);
		runEquivalenceTest(translateSleigh(ID_TOYBE64, """
				r0 = floor(r1);
				r6l = floor(r7l);
				"""), List.of(new Case("p", """
				r1  =0x%x;
				r7l =0x%x;
				""".formatted(d0dot5, f0dot5), List.of(ev("r0", 0.0d), ev("r6", 0.0f))),
			new Case("n", """
					r1  =0x%x;
					r7l =0x%x;
					""".formatted(dn0dot5, fn0dot5), List.of(ev("r0", -1.0d), ev("r6", -1.0f)))));
	}

	@Test
	public void testFloatRoundOpGen() throws Exception {
		long d0dot25 = Double.doubleToLongBits(0.25);
		long dn0dot25 = Double.doubleToLongBits(-0.25);
		int f0dot25 = Float.floatToIntBits(0.25f);
		int fn0dot25 = Float.floatToIntBits(-0.25f);
		long d0dot5 = Double.doubleToLongBits(0.5);
		long dn0dot5 = Double.doubleToLongBits(-0.5);
		int f0dot5 = Float.floatToIntBits(0.5f);
		int fn0dot5 = Float.floatToIntBits(-0.5f);
		long d0dot75 = Double.doubleToLongBits(0.75);
		long dn0dot75 = Double.doubleToLongBits(-0.75);
		int f0dot75 = Float.floatToIntBits(0.75f);
		int fn0dot75 = Float.floatToIntBits(-0.75f);
		long d1dot0 = Double.doubleToLongBits(1.0);
		long dn1dot0 = Double.doubleToLongBits(-1.0);
		int f1dot0 = Float.floatToIntBits(1.0f);
		int fn1dot0 = Float.floatToIntBits(-1.0f);
		runEquivalenceTest(translateSleigh(ID_TOYBE64, """
				r0 = round(r1);
				r6l = round(r7l);
				"""), List.of(new Case("+0.25", """
				r1  =0x%x;
				r7l =0x%x;
				""".formatted(d0dot25, f0dot25), List.of(ev("r0", 0.0d), ev("r6", 0.0f))),
			new Case("-0.25", """
					r1  =0x%x;
					r7l =0x%x;
					""".formatted(dn0dot25, fn0dot25), List.of(ev("r0", 0.0d), ev("r6", 0.0f))),
			new Case("+0.5", """
					r1  =0x%x;
					r7l =0x%x;
					""".formatted(d0dot5, f0dot5), List.of(ev("r0", 1.0d), ev("r6", 1.0f))),
			new Case("-0.5", """
					r1  =0x%x;
					r7l =0x%x;
					""".formatted(dn0dot5, fn0dot5), List.of(ev("r0", 0.0d), ev("r6", 0.0f))),
			new Case("+0.75", """
					r1  =0x%x;
					r7l =0x%x;
					""".formatted(d0dot75, f0dot75), List.of(ev("r0", 1.0d), ev("r6", 1.0f))),
			new Case("-0.75", """
					r1  =0x%x;
					r7l =0x%x;
					""".formatted(dn0dot75, fn0dot75), List.of(ev("r0", -1.0d), ev("r6", -1.0f))),
			new Case("+1.0", """
					r1  =0x%x;
					r7l =0x%x;
					""".formatted(d1dot0, f1dot0), List.of(ev("r0", 1.0d), ev("r6", 1.0f))),
			new Case("-1.0", """
					r1  =0x%x;
					r7l =0x%x;
					""".formatted(dn1dot0, fn1dot0), List.of(ev("r0", -1.0d), ev("r6", -1.0f)))));
	}

	@Test
	public void testFloat2FloatOpGen() throws Exception {
		long d0dot5 = Double.doubleToLongBits(0.5);
		int f0dot5 = Float.floatToIntBits(0.5f);
		runEquivalenceTest(translateSleigh(ID_TOYBE64, """
				r0 = float2float(r1l);
				r6l = float2float(r7);
				"""), List.of(new Case("only", """
				r1l =0x%x;
				r7  =0x%x;
				""".formatted(f0dot5, d0dot5), List.of(ev("r0", 0.5d), ev("r6", 0.5f)))));
	}

	@Test
	public void testFloatInt2FloatOpGen() throws Exception {
		/**
		 * The size swap is not necessary, but test anyway.
		 */
		runEquivalenceTest(translateSleigh(ID_TOYBE64, """
				r0 = int2float(r1l);
				r6l = int2float(r7);
				"""), List.of(new Case("only", """
				r1l =1;
				r7  =2;
				""", List.of(ev("r0", 1.0d), ev("r6", 2.0f)))));
	}

	@Test
	public void testFloatTruncOpGen() throws Exception {
		long d1dot0 = Double.doubleToLongBits(1.0);
		long d0dot5 = Double.doubleToLongBits(0.5);
		long dn0dot5 = Double.doubleToLongBits(-0.5);
		int f1dot0 = Float.floatToIntBits(1.0f);
		int f0dot5 = Float.floatToIntBits(0.5f);
		int fn0dot5 = Float.floatToIntBits(-0.5f);
		runEquivalenceTest(translateSleigh(ID_TOYBE64, """
				r0 = trunc(r1);
				r3 = trunc(r4l);
				r6l = trunc(r7);
				r9l = trunc(r10l);
				"""),
			List.of(
				new Case("+1.0", """
						r1  =0x%x;
						r4l =0x%x;
						r7  =0x%x;
						r10l=0x%x;
						""".formatted(d1dot0, f1dot0, d1dot0, f1dot0),
					List.of(ev("r0", "1"), ev("r3", "1"), ev("r6", "1"), ev("r9", "1"))),
				new Case("+0.5", """
						r1  =0x%x;
						r4l =0x%x;
						r7  =0x%x;
						r10l=0x%x;
						""".formatted(d0dot5, f0dot5, d0dot5, f0dot5),
					List.of(ev("r0", "0"), ev("r3", "0"), ev("r6", "0"), ev("r9", "0"))),
				new Case("-0.5", """
						r1  =0x%x;
						r4l =0x%x;
						r7  =0x%x;
						r10l=0x%x;
						""".formatted(dn0dot5, dn0dot5, dn0dot5, fn0dot5),
					List.of(ev("r0", "0"), ev("r3", "0"), ev("r6", "0"), ev("r9", "0")))));
	}

	@Test
	public void testFloatNaNOpGen() throws Exception {
		long d0dot5 = Double.doubleToLongBits(0.5);
		int f0dot5 = Float.floatToIntBits(0.5f);
		long dNaN = Double.doubleToRawLongBits(Double.NaN);
		int fNaN = Float.floatToRawIntBits(Float.NaN);
		/**
		 * The size swap is not necessary, but test anyway.
		 */
		runEquivalenceTest(translateSleigh(ID_TOYBE64, """
				r0 = nan(r1l);
				r6l = nan(r7);
				"""), List.of(new Case("num", """
				r1l =0x%x;
				r7  =0x%x;
				""".formatted(f0dot5, d0dot5), List.of(ev("r0", "0"), ev("r6", "0"))),
			new Case("nan", """
					r1l =0x%x;
					r7  =0x%x;
					""".formatted(fNaN, dNaN), List.of(ev("r0", "1"), ev("r6", "1")))));
	}

	@Test
	public void testFloatNegOpGen() throws Exception {
		long d0dot5 = Double.doubleToLongBits(0.5);
		int f0dot5 = Float.floatToIntBits(0.5f);
		runEquivalenceTest(translateSleigh(ID_TOYBE64, """
				r0 = f-r1;
				r6l = f-r7l;
				"""), List.of(new Case("num", """
				r1 =0x%x;
				r7l  =0x%x;
				""".formatted(d0dot5, f0dot5), List.of(ev("r0", -0.5d), ev("r6l", -0.5f)))));
	}

	@Test
	public void testFloatAddOpGen() throws Exception {
		long d0dot5 = Double.doubleToLongBits(0.5);
		int f0dot5 = Float.floatToIntBits(0.5f);
		long d0dot25 = Double.doubleToLongBits(0.25);
		int f0dot25 = Float.floatToIntBits(0.25f);
		runEquivalenceTest(translateSleigh(ID_TOYBE64, """
				r0 = r1 f+ r2;
				r9l = r10l f+ r11l;
				"""), List.of(new Case("only", """
				r1  =0x%x; r2  =0x%x;
				r10l=0x%x; r11l=0x%x;
				""".formatted(d0dot5, d0dot25, f0dot5, f0dot25),
			List.of(ev("r0", 0.75d), ev("r9", 0.75f)))));
	}

	@Test
	public void testFloatSubOpGen() throws Exception {
		long d0dot5 = Double.doubleToLongBits(0.5);
		int f0dot5 = Float.floatToIntBits(0.5f);
		long d0dot25 = Double.doubleToLongBits(0.25);
		int f0dot25 = Float.floatToIntBits(0.25f);
		runEquivalenceTest(translateSleigh(ID_TOYBE64, """
				r0 = r1 f- r2;
				r9l = r10l f- r11l;
				"""), List.of(new Case("only", """
				r1  =0x%x; r2  =0x%x;
				r10l=0x%x; r11l=0x%x;
				""".formatted(d0dot5, d0dot25, f0dot5, f0dot25),
			List.of(ev("r0", 0.25d), ev("r9", 0.25f)))));
	}

	@Test
	public void testFloatMultOpGen() throws Exception {
		long d0dot5 = Double.doubleToLongBits(0.5);
		int f0dot5 = Float.floatToIntBits(0.5f);
		long d0dot25 = Double.doubleToLongBits(0.25);
		int f0dot25 = Float.floatToIntBits(0.25f);
		runEquivalenceTest(translateSleigh(ID_TOYBE64, """
				r0 = r1 f* r2;
				r9l = r10l f* r11l;
				"""), List.of(new Case("only", """
				r1  =0x%x; r2  =0x%x;
				r10l=0x%x; r11l=0x%x;
				""".formatted(d0dot5, d0dot25, f0dot5, f0dot25),
			List.of(ev("r0", 0.125d), ev("r9", 0.125f)))));
	}

	@Test
	public void testFloatDivOpGen() throws Exception {
		long d0dot5 = Double.doubleToLongBits(0.5);
		int f0dot5 = Float.floatToIntBits(0.5f);
		long d0dot25 = Double.doubleToLongBits(0.25);
		int f0dot25 = Float.floatToIntBits(0.25f);
		runEquivalenceTest(translateSleigh(ID_TOYBE64, """
				r0 = r1 f/ r2;
				r9l = r10l f/ r11l;
				"""), List.of(new Case("only", """
				r1  =0x%x; r2  =0x%x;
				r10l=0x%x; r11l=0x%x;
				""".formatted(d0dot5, d0dot25, f0dot5, f0dot25),
			List.of(ev("r0", 2.0d), ev("r9", 2.0f)))));
	}

	@Test
	public void testFloatEqualOpGen() throws Exception {
		long d0dot5 = Double.doubleToLongBits(0.5);
		int f0dot5 = Float.floatToIntBits(0.5f);
		long d0dot25 = Double.doubleToLongBits(0.25);
		int f0dot25 = Float.floatToIntBits(0.25f);
		runEquivalenceTest(translateSleigh(ID_TOYBE64, """
				r0 = r1 f== r2;
				r9l = r10l f== r11l;
				"""),
			List.of(
				new Case("lt", """
						r1  =0x%x; r2  =0x%x;
						r10l=0x%x; r11l=0x%x;
						""".formatted(d0dot25, d0dot5, f0dot25, f0dot5),
					List.of(ev("r0", "0"), ev("r9", "0"))),
				new Case("eq", """
						r1  =0x%x; r2  =0x%x;
						r10l=0x%x; r11l=0x%x;
						""".formatted(d0dot5, d0dot5, f0dot5, f0dot5),
					List.of(ev("r0", "1"), ev("r9", "1"))),
				new Case("gt", """
						r1  =0x%x; r2  =0x%x;
						r10l=0x%x; r11l=0x%x;
						""".formatted(d0dot5, d0dot25, f0dot5, f0dot25),
					List.of(ev("r0", "0"), ev("r9", "0")))));
	}

	@Test
	public void testFloatNotEqualOpGen() throws Exception {
		long d0dot5 = Double.doubleToLongBits(0.5);
		int f0dot5 = Float.floatToIntBits(0.5f);
		long d0dot25 = Double.doubleToLongBits(0.25);
		int f0dot25 = Float.floatToIntBits(0.25f);
		runEquivalenceTest(translateSleigh(ID_TOYBE64, """
				r0 = r1 f!= r2;
				r9l = r10l f!= r11l;
				"""),
			List.of(
				new Case("lt", """
						r1  =0x%x; r2  =0x%x;
						r10l=0x%x; r11l=0x%x;
						""".formatted(d0dot25, d0dot5, f0dot25, f0dot5),
					List.of(ev("r0", "1"), ev("r9", "1"))),
				new Case("eq", """
						r1  =0x%x; r2  =0x%x;
						r10l=0x%x; r11l=0x%x;
						""".formatted(d0dot5, d0dot5, f0dot5, f0dot5),
					List.of(ev("r0", "0"), ev("r9", "0"))),
				new Case("gt", """
						r1  =0x%x; r2  =0x%x;
						r10l=0x%x; r11l=0x%x;
						""".formatted(d0dot5, d0dot25, f0dot5, f0dot25),
					List.of(ev("r0", "1"), ev("r9", "1")))));
	}

	@Test
	public void testFloatLessEqualOpGen() throws Exception {
		long d0dot5 = Double.doubleToLongBits(0.5);
		int f0dot5 = Float.floatToIntBits(0.5f);
		long d0dot25 = Double.doubleToLongBits(0.25);
		int f0dot25 = Float.floatToIntBits(0.25f);
		runEquivalenceTest(translateSleigh(ID_TOYBE64, """
				r0 = r1 f<= r2;
				r9l = r10l f<= r11l;
				"""),
			List.of(
				new Case("lt", """
						r1  =0x%x; r2  =0x%x;
						r10l=0x%x; r11l=0x%x;
						""".formatted(d0dot25, d0dot5, f0dot25, f0dot5),
					List.of(ev("r0", "1"), ev("r9", "1"))),
				new Case("eq", """
						r1  =0x%x; r2  =0x%x;
						r10l=0x%x; r11l=0x%x;
						""".formatted(d0dot5, d0dot5, f0dot5, f0dot5),
					List.of(ev("r0", "1"), ev("r9", "1"))),
				new Case("gt", """
						r1  =0x%x; r2  =0x%x;
						r10l=0x%x; r11l=0x%x;
						""".formatted(d0dot5, d0dot25, f0dot5, f0dot25),
					List.of(ev("r0", "0"), ev("r9", "0")))));
	}

	@Test
	public void testFloatLessOpGen() throws Exception {
		long d0dot5 = Double.doubleToLongBits(0.5);
		int f0dot5 = Float.floatToIntBits(0.5f);
		long d0dot25 = Double.doubleToLongBits(0.25);
		int f0dot25 = Float.floatToIntBits(0.25f);
		runEquivalenceTest(translateSleigh(ID_TOYBE64, """
				r0 = r1 f< r2;
				r9l = r10l f< r11l;
				"""),
			List.of(
				new Case("lt", """
						r1  =0x%x; r2  =0x%x;
						r10l=0x%x; r11l=0x%x;
						""".formatted(d0dot25, d0dot5, f0dot25, f0dot5),
					List.of(ev("r0", "1"), ev("r9", "1"))),
				new Case("eq", """
						r1  =0x%x; r2  =0x%x;
						r10l=0x%x; r11l=0x%x;
						""".formatted(d0dot5, d0dot5, f0dot5, f0dot5),
					List.of(ev("r0", "0"), ev("r9", "0"))),
				new Case("gt", """
						r1  =0x%x; r2  =0x%x;
						r10l=0x%x; r11l=0x%x;
						""".formatted(d0dot5, d0dot25, f0dot5, f0dot25),
					List.of(ev("r0", "0"), ev("r9", "0")))));
	}

	@Test
	public void testInt2CompOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(ID_TOYBE64, """
				r0  = -r1;
				r6l = -r7l;
				"""), List.of(new Case("pos", """
				r1  =4;
				r7l =4;
				""", List.of(ev("r0", "-4"), ev("r6l", "-4"))), new Case("neg", """
				r1  =-4;
				r7l =-4;
				""", List.of(ev("r0", "4"), ev("r6l", "4")))));
	}

	@Test
	public void testInt2CompMpIntOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(ID_TOYBE64, """
				temp1:9 = sext(r1);
				temp0:9 = -temp1;
				r0 = temp0(0);
				r2 = temp0(1);
				"""), List.of(new Case("pos", """
				r1 = 4;
				""", List.of(ev("r0", "-4"), ev("r2", "-1"))), new Case("neg", """
				r1 =-4;
				""", List.of(ev("r0", "4"), ev("r2", "0")))));
	}

	@Test
	public void testIntNegateOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(ID_TOYBE64, """
				r0  = ~r1;
				r6l = ~r7l;
				"""), List.of(new Case("pos", """
				r1  =4;
				r7l =4;
				""", List.of(ev("r0", "-5"), ev("r6l", "-5"))), new Case("neg", """
				r1  =-4;
				r7l =-4;
				""", List.of(ev("r0", "3"), ev("r6l", "3")))));
	}

	@Test
	public void testIntNegateMpIntOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(ID_TOYBE64, """
				temp1:9 = sext(r1);
				temp0:9 = ~temp1;
				r0 = temp0(0);
				r2 = temp0(1);
				"""), List.of(new Case("pos", """
				r1 = 4;
				""", List.of(ev("r0", "-5"), ev("r2", "-1"))), new Case("neg", """
				r1 = -4;
				""", List.of(ev("r0", "3"), ev("r2", "0")))));
	}

	@Test
	public void testIntSExtOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(ID_TOYBE64, """
				r0 = sext(r1l);
				"""), List.of(new Case("pos", """
				r1l =4;
				""", List.of(ev("r0", "4"))), new Case("neg", """
				r1l =-4;
				""", List.of(ev("r0", "-4")))));
	}

	@Test
	public void testIntSExtMpIntOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(ID_TOYBE64, """
				temp0:9 = sext(r1l);
				r0 = temp0(0);
				r2 = temp0(1);
				"""), List.of(new Case("pos", """
				r1l =4;
				""", List.of(ev("r0", "4"), ev("r2", "0"))), new Case("neg", """
				r1l =-4;
				""", List.of(ev("r0", "-4"), ev("r2", "-1")))));
	}

	@Test
	public void testIntZExtOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(ID_TOYBE64, """
				r0 = zext(r1l);
				"""), List.of(new Case("pos", """
				r1l =4;
				""", List.of(ev("r0", "4"))), new Case("neg", """
				r1l =-4;
				""", List.of(ev("r0", "0xfffffffc")))));
	}

	@Test
	public void testIntZExtMpIntOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(ID_TOYBE64, """
				temp0:9 = zext(r1l);
				r0 = temp0(0);
				r2 = temp0(1);
				"""), List.of(new Case("pos", """
				r1l =4;
				""", List.of(ev("r0", "4"), ev("r2", "0"))), new Case("neg", """
				r1l =-4;
				""", List.of(ev("r0", "0xfffffffc"), ev("r2", "0xffffff")))));
	}

	@Test
	public void testLzCountOpGen() throws Exception {
		// Test size change, even though not necessary here
		runEquivalenceTest(translateSleigh(ID_TOYBE64, """
				r0 = lzcount(r1l);

				temp:3 = r3(0);
				r2 = lzcount(temp);
				"""), List.of(new Case("pos", """
				r1l =4;
				r3  =4;
				""", List.of(ev("r0", "29"), ev("r2", "21"))), new Case("neg", """
				r1l =-4;
				r3  =-4;
				""", List.of(ev("r0", "0"), ev("r2", "0")))));
	}

	@Test
	public void testLzCountMpIntOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(ID_TOYBE64, """
				temp1s:9 = sext(r1);
				temp1z:9 = zext(r1);
				r0 = lzcount(temp1s);
				r2 = lzcount(temp1z);
				"""), List.of(new Case("pos", """
				r1 =4;
				""", List.of(ev("r0", "69"), ev("r2", "69"))), new Case("neg", """
				r1 =-4;
				""", List.of(ev("r0", "0"), ev("r2", "8")))));
	}

	@Test
	public void testPopCountOpGen() throws Exception {
		// Test size change, even though not necessary here
		runEquivalenceTest(translateSleigh(ID_TOYBE64, """
				r0 = popcount(r1l);
				"""), List.of(new Case("pos", """
				r1l =4;
				""", List.of(ev("r0", "1"))), new Case("neg", """
				r1l =-4;
				""", List.of(ev("r0", "30")))));
	}

	@Test
	public void testPopCountMpIntOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(ID_TOYBE64, """
				temp1s:9 = sext(r1);
				temp1z:9 = zext(r1);
				r0 = popcount(temp1s);
				r2 = popcount(temp1z);
				"""), List.of(new Case("pos", """
				r1 =4;
				""", List.of(ev("r0", "1"), ev("r2", "1"))), new Case("neg", """
				r1 =-4;
				""", List.of(ev("r0", "70"), ev("r2", "62")))));
	}

	@Test
	public void testSubPieceOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(ID_TOYBE64, """
				r0l = r1(3);
				r3 = r4l(3);
				"""), List.of(new Case("only", """
				r1 =0x%x;
				r4l=0x12345678;
				""".formatted(LONG_CONST), List.of(ev("r0l", "0xadbeefca"), ev("r3", "0x12")))));
	}

	@Test
	public void testSubPieceMpIntConst9_0() throws Exception {
		runEquivalenceTest(translateSleigh(ID_TOYBE64, """
				temp0:9 = 0x1122334455667788;
				r0 = temp0(0);
				"""), List.of(new Case("only", "", List.of(ev("r0", "0x1122334455667788")))));
	}

	@Test
	public void testSubPieceMpIntConst9_1() throws Exception {
		runEquivalenceTest(translateSleigh(ID_TOYBE64, """
				temp0:9 = 0x1122334455667788;
				r0 = temp0(1);
				"""), List.of(new Case("only", "", List.of(ev("r0", "0x11223344556677")))));
	}

	@Test
	public void testSubPieceMpIntConst10_0() throws Exception {
		runEquivalenceTest(translateSleigh(ID_TOYBE64, """
				temp0:10 = 0x1122334455667788;
				r0 = temp0(0);
				"""), List.of(new Case("only", "", List.of(ev("r0", "0x1122334455667788")))));
	}

	@Test
	public void testSubPieceMpIntConst10_1() throws Exception {
		runEquivalenceTest(translateSleigh(ID_TOYBE64, """
				temp0:10 = 0x1122334455667788;
				r0 = temp0(1);
				"""), List.of(new Case("only", "", List.of(ev("r0", "0x11223344556677")))));
	}

	@Test
	public void testSubPieceMpIntConst10_2() throws Exception {
		runEquivalenceTest(translateSleigh(ID_TOYBE64, """
				temp0:10 = 0x1122334455667788;
				r0 = temp0(2);
				"""), List.of(new Case("only", "", List.of(ev("r0", "0x112233445566")))));
	}

	@Test
	public void testSubPieceMpIntConst11_0() throws Exception {
		runEquivalenceTest(translateSleigh(ID_TOYBE64, """
				temp0:11 = 0x1122334455667788;
				r0 = temp0(0);
				"""), List.of(new Case("only", "", List.of(ev("r0", "0x1122334455667788")))));
	}

	@Test
	public void testSubPieceMpIntConst11_1() throws Exception {
		runEquivalenceTest(translateSleigh(ID_TOYBE64, """
				temp0:11 = 0x1122334455667788;
				r0 = temp0(1);
				"""), List.of(new Case("only", "", List.of(ev("r0", "0x11223344556677")))));
	}

	@Test
	public void testSubPieceMpIntConst11_2() throws Exception {
		runEquivalenceTest(translateSleigh(ID_TOYBE64, """
				temp0:11 = 0x1122334455667788;
				r0 = temp0(2);
				"""), List.of(new Case("only", "", List.of(ev("r0", "0x112233445566")))));
	}

	@Test
	public void testSubPieceMpIntConst11_3() throws Exception {
		runEquivalenceTest(translateSleigh(ID_TOYBE64, """
				temp0:11 = 0x1122334455667788;
				r0 = temp0(3);
				"""), List.of(new Case("only", "", List.of(ev("r0", "0x1122334455")))));
	}

	@Test
	public void testSubPieceMpIntConst12_0() throws Exception {
		runEquivalenceTest(translateSleigh(ID_TOYBE64, """
				temp0:12 = 0x1122334455667788;
				r0 = temp0(0);
				"""), List.of(new Case("only", "", List.of(ev("r0", "0x1122334455667788")))));
	}

	@Test
	public void testSubPieceMpIntConst12_1() throws Exception {
		runEquivalenceTest(translateSleigh(ID_TOYBE64, """
				temp0:12 = 0x1122334455667788;
				r0 = temp0(1);
				"""), List.of(new Case("only", "", List.of(ev("r0", "0x11223344556677")))));
	}

	@Test
	public void testSubPieceMpIntConst12_2() throws Exception {
		runEquivalenceTest(translateSleigh(ID_TOYBE64, """
				temp0:12 = 0x1122334455667788;
				r0 = temp0(2);
				"""), List.of(new Case("only", "", List.of(ev("r0", "0x112233445566")))));
	}

	@Test
	public void testSubPieceMpIntConst12_3() throws Exception {
		runEquivalenceTest(translateSleigh(ID_TOYBE64, """
				temp0:12 = 0x1122334455667788;
				r0 = temp0(3);
				"""), List.of(new Case("only", "", List.of(ev("r0", "0x1122334455")))));
	}

	@Test
	public void testSubPieceMpIntConst12_4() throws Exception {
		runEquivalenceTest(translateSleigh(ID_TOYBE64, """
				temp0:12 = 0x1122334455667788;
				r0 = temp0(4);
				"""), List.of(new Case("only", "", List.of(ev("r0", "0x11223344")))));
	}

	@Test
	public void testIntAddOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(ID_TOYBE64, """
				r0 = r1 + r2;
				r9l = r10l + r11l;
				"""), List.of(new Case("only", """
				r1  =2; r2  =2;
				r10l=2; r11l=2;
				""", List.of(ev("r0", "4"), ev("r9", "4")))));
	}

	@Test
	public void testIntAddMpIntOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(ID_TOYBE64, """
				temp1:9 = zext(r1);
				temp2:9 = zext(r2);
				temp0:9 = temp1 + temp2;
				r0 = temp0(0);
				"""), List.of(new Case("small", """
				r1 = 2; r2 = 2;
				""", List.of(ev("r0", "4"))), new Case("large", """
				r1 = 0x8111111122222222; r2 = 0x8765432112345678;
				""", List.of(ev("r0", "0x87654323456789a")))));
	}

	@Test
	public void testIntSubOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(ID_TOYBE64, """
				r0 = r1 - r2;
				r9l = r10l - r11l;
				"""), List.of(new Case("only", """
				r1  =2; r2  =2;
				r10l=2; r11l=2;
				""", List.of(ev("r0", "0"), ev("r9", "0")))));
	}

	@Test
	public void testIntSubMpIntOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(ID_TOYBE64, """
				temp1:9 = zext(r1);
				temp2:9 = zext(r2);
				temp0:9 = temp1 - temp2;
				r0 = temp0(0);
				r3 = temp0(1);
				"""), List.of(new Case("small", """
				r1 = 2; r2 = 2;
				""", List.of(ev("r0", "0"), ev("r3", "0"))), new Case("large", """
				r1 = 0x8111111122222222; r2 = 0x8765432112345678;
				""", List.of(ev("r0", "0xf9abcdf00fedcbaa"), ev("r3", "0xfff9abcdf00fedcb")))));
	}

	@Test
	public void testIntMultOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(ID_TOYBE64, """
				r0 = r1 * r2;
				r9l = r10l * r11l;
				"""), List.of(new Case("only", """
				r1  =2; r2  =2;
				r10l=2; r11l=2;
				""", List.of(ev("r0", "4"), ev("r9", "4")))));
	}

	@Test
	public void testIntMultMpIntOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(ID_TOYBE64, """
				temp0:16 = zext(r1) * zext(r2);
				r0 = temp0[0,64];
				r3 = temp0[64,64];
				"""), List.of(new Case("small", """
				r1 = 2; r2 = 7;
				""", List.of(ev("r0", "14"), ev("r3", "0"))), new Case("large", """
				r1 = 0xffeeddccbbaa9988; r2 = 0x8877665544332211;
				""", List.of(ev("r0", "0x30fdc971d4d04208"), ev("r3", "0x886e442c48bba72d")))));
	}

	@Test
	public void testIntDivOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(ID_TOYBE64, """
				r0 = r1 / r2;
				r9l = r10l / r11l;
				"""), List.of(new Case("pp", """
				r1  =5; r2  =2;
				r10l=5; r11l=2;
				""", List.of(ev("r0", "2"), ev("r9", "2"))), new Case("pn", """
				r1  =5; r2  =-2;
				r10l=5; r11l=-2;
				""", List.of(ev("r0", "0"), ev("r9", "0"))), new Case("np", """
				r1  =-5; r2  =2;
				r10l=-5; r11l=2;
				""", List.of(ev("r0", "0x7ffffffffffffffd"), ev("r9", "0x7ffffffd"))),
			new Case("nn", """
					r1  =-5; r2  =-2;
					r10l=-5; r11l=-2;
					""", List.of(ev("r0", "0"), ev("r9", "0")))));
	}

	@Test
	public void testIntDivOpGenWith3ByteOperand() throws Exception {
		runEquivalenceTest(translateSleigh(ID_TOYBE64, """
				temp:3 = r1 + r2;
				r0 = temp / r0;
				"""), List.of(new Case("only", """
				r1 = 0xdead;
				r2 = 0xbeef;
				r0 = 4;
				""", List.of(ev("r0", "0x6767")))));
	}

	@Test
	public void testIntDivMpIntOpGenNonUniform() throws Exception {
		runEquivalenceTest(translateSleigh(ID_TOYBE64, """
				temp1:9 = sext(r1);
				r0l = temp1 / r2;
				"""), List.of(new Case("pp", """
				r1 = 0x67452301efcdab89;
				r2 = 0x1234;
				""", List.of(ev("r0l", "0x2ee95b10"))), new Case("pn", """
				r1 = 0x67452301efcdab89;
				r2 = -0x1234;
				""", List.of(ev("r0l", "0x00000000"))), new Case("np", """
				r1 = -0x67452301efcdab89;
				r2 = 0x1234;
				""", List.of(ev("r0l", "0x0e658826"))), new Case("nn", """
				r1 = -0x67452301efcdab89;
				r2 = -0x1234;
				""", List.of(ev("r0l", "0x000000ff")))));
	}

	@Test
	public void testIntDivMpIntOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(ID_TOYBE64, """
				temp1:9 = sext(r1);
				temp2:9 = sext(r2);
				local quotient = temp1 / temp2;
				r0l = quotient(0);
				"""), List.of(new Case("pp", """
				r1 = 0x67452301efcdab89;
				r2 = 0x1234;
				""", List.of(ev("r0l", "0x2ee95b10"))), new Case("pn", """
				r1 = 0x67452301efcdab89;
				r2 = -0x1234;
				""", List.of(ev("r0l", "0x00000000"))), new Case("np", """
				r1 = -0x67452301efcdab89;
				r2 = 0x1234;
				""", List.of(ev("r0l", "0x0e658826"))),
			// NOTE: Result differs from NonUniform, because r2 is also sext()ed
			new Case("nn", """
					r1 = -0x67452301efcdab89;
					r2 = -0x1234;
					""", List.of(ev("r0l", "0x00000000")))));
	}

	@Test
	public void testIntSDivOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(ID_TOYBE64, """
				r0 = r1 s/ r2;
				r9l = r10l s/ r11l;
				"""), List.of(new Case("pp", """
				r1  =5; r2  =2;
				r10l=5; r11l=2;
				""", List.of(ev("r0", "2"), ev("r9l", "2"))), new Case("pn", """
				r1  =5; r2  =-2;
				r10l=5; r11l=-2;
				""", List.of(ev("r0", "-2"), ev("r9l", "-2"))), new Case("np", """
				r1  =-5; r2  =2;
				r10l=-5; r11l=2;
				""", List.of(ev("r0", "-2"), ev("r9l", "-2"))), new Case("nn", """
				r1  =-5; r2  =-2;
				r10l=-5; r11l=-2;
				""", List.of(ev("r0", "2"), ev("r9l", "2")))));
	}

	@Test
	public void testIntSDivMpIntOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(ID_TOYBE64, """
				temp1:9 = sext(r1);
				temp2:9 = sext(r2);
				local quotient = temp1 s/ temp2;
				r0l = quotient(0);
				"""), List.of(new Case("pp", """
				r1 = 0x67452301efcdab89;
				r2 = 0x1234;
				""", List.of(ev("r0", "0x2ee95b10"))), new Case("pn", """
				r1 = 0x67452301efcdab89;
				r2 = -0x1234;
				""", List.of(ev("r0", "0xd116a4f0"))), new Case("np", """
				r1 = -0x67452301efcdab89;
				r2 = 0x1234;
				""", List.of(ev("r0", "0xd116a4f0"))), new Case("nn", """
				r1 = -0x67452301efcdab89;
				r2 = -0x1234;
				""", List.of(ev("r0", "0x2ee95b10")))));
	}

	@Test
	public void testIntRemOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(ID_TOYBE64, """
				r0 = r1 % r2;
				r9l = r10l % r11l;
				"""), List.of(new Case("pp", """
				r1  =5; r2  =2;
				r10l=5; r11l=2;
				""", List.of(ev("r0", "1"), ev("r9l", "1"))), new Case("pn", """
				r1  =5; r2  =-2;
				r10l=5; r11l=-2;
				""", List.of(ev("r0", "5"), ev("r9l", "5"))), new Case("np", """
				r1  =-5; r2  =2;
				r10l=-5; r11l=2;
				""", List.of(ev("r0", "1"), ev("r9l", "1"))), new Case("nn", """
				r1  =-5; r2  =-2;
				r10l=-5; r11l=-2;
				""", List.of(ev("r0", "-5"), ev("r9l", "-5")))));
	}

	@Test
	public void testIntRemMpIntOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(ID_TOYBE64, """
				temp1:9 = sext(r1);
				temp2:9 = sext(r2);
				local remainder = temp1 % temp2;
				r0l = remainder(0);
				"""), List.of(new Case("pp", """
				r1 = 0x67452301efcdab89;
				r2 = 0x1234;
				""", List.of(ev("r0", "0x0c49"))), new Case("pn", """
				r1 = 0x67452301efcdab89;
				r2 = -0x1234;
				""", List.of(ev("r0", "0xefcdab89"))), new Case("np", """
				r1 = -0x67452301efcdab89;
				r2 = 0x1234;
				""", List.of(ev("r0", "0x00bf"))), new Case("nn", """
				r1 = -0x67452301efcdab89;
				r2 = -0x1234;
				""", List.of(ev("r0", "0x10325477")))));
	}

	@Test
	public void testIntSRemOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(ID_TOYBE64, """
				r0 = r1 s% r2;
				r9l = r10l s% r11l;
				"""), List.of(new Case("pp", """
				r1  =5; r2  =2;
				r10l=5; r11l=2;
				""", List.of(ev("r0", "1"), ev("r9l", "1"))), new Case("pn", """
				r1  =5; r2  =-2;
				r10l=5; r11l=-2;
				""", List.of(ev("r0", "1"), ev("r9l", "1"))), new Case("np", """
				r1  =-5; r2  =2;
				r10l=-5; r11l=2;
				""", List.of(ev("r0", "-1"), ev("r9l", "-1"))), new Case("nn", """
				r1  =-5; r2  =-2;
				r10l=-5; r11l=-2;
				""", List.of(ev("r0", "-1"), ev("r9l", "-1")))));
	}

	@Test
	public void testIntSRemMpIntOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(ID_TOYBE64, """
				temp1:9 = sext(r1);
				temp2:9 = sext(r2);
				local quotient = temp1 s% temp2;
				r0l = quotient(0);
				"""), List.of(new Case("pp", """
				r1 = 0x67452301efcdab89;
				r2 = 0x1234;
				""", List.of(ev("r0", "0x0c49"))), new Case("pn", """
				r1 = 0x67452301efcdab89;
				r2 = -0x1234;
				""", List.of(ev("r0", "0x0c49"))), new Case("np", """
				r1 = -0x67452301efcdab89;
				r2 = 0x1234;
				""", List.of(ev("r0", "0xfffff3b7"))), new Case("nn", """
				r1 = -0x67452301efcdab89;
				r2 = -0x1234;
				""", List.of(ev("r0", "0xfffff3b7")))));
	}

	@Test
	public void testIntAndOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(ID_TOYBE64, """
				r0 = r1 & r2;
				r9l = r10l & r11l;
				"""), List.of(new Case("only", """
				r1  =0x3; r2  =0x5;
				r10l=0x3; r11l=0x5;
				""", List.of(ev("r0", "1"), ev("r9", "1")))));
	}

	@Test
	public void testIntAndMpIntOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(ID_TOYBE64, """
				temp1:9 = zext(r1);
				temp2:9 = zext(r2);
				temp0:9 = temp1 & temp2;
				r0 = temp0(0);
				"""), List.of(new Case("small", """
				r1 = 2; r2 = 2;
				""", List.of(ev("r0", "2"))), new Case("large", """
				r1 = 0x8111111122222222; r2 = 0x8765432112345678;
				""", List.of(ev("r0", "0x8101010102200220")))));
	}

	@Test
	public void testIntOrOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(ID_TOYBE64, """
				r0 = r1 | r2;
				r9l = r10l | r11l;
				"""), List.of(new Case("only", """
				r1  =0x3; r2  =0x5;
				r10l=0x3; r11l=0x5;
				""", List.of(ev("r0", "7"), ev("r9", "7")))));
	}

	@Test
	public void testIntOrMpIntOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(ID_TOYBE64, """
				temp1:9 = zext(r1);
				temp2:9 = zext(r2);
				temp0:9 = temp1 | temp2;
				r0 = temp0(0);
				"""), List.of(new Case("small", """
				r1 = 2; r2 = 2;
				""", List.of(ev("r0", "2"))), new Case("large", """
				r1 = 0x8111111122222222; r2 = 0x8765432112345678;
				""", List.of(ev("r0", "0x877553313236767a")))));
	}

	@Test
	public void testIntXorOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(ID_TOYBE64, """
				r0 = r1 ^ r2;
				r9l = r10l ^ r11l;
				"""), List.of(new Case("only", """
				r1  =0x3; r2  =0x5;
				r10l=0x3; r11l=0x5;
				""", List.of(ev("r0", "6"), ev("r9", "6")))));
	}

	@Test
	public void testIntXorMpIntOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(ID_TOYBE64, """
				temp1:9 = zext(r1);
				temp2:9 = zext(r2);
				temp0:9 = temp1 ^ temp2;
				r0 = temp0(0);
				"""), List.of(new Case("small", """
				r1 = 2; r2 = 2;
				""", List.of(ev("r0", "0"))), new Case("large", """
				r1 = 0x8111111122222222; r2 = 0x8765432112345678;
				""", List.of(ev("r0", "0x67452303016745a")))));
	}

	@Test
	public void testIntEqualOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(ID_TOYBE64, """
				r0 = r1 == r2;
				r9l = r10l == r11l;
				"""), List.of(new Case("lt", """
				r1  =1; r2  =2;
				r10l=1; r11l=2;
				""", List.of(ev("r0", "0"), ev("r9", "0"))), new Case("slt", """
				r1  =-1; r2  =2;
				r10l=-1; r11l=2;
				""", List.of(ev("r0", "0"), ev("r9", "0"))), new Case("eq", """
				r1  =1; r2  =1;
				r10l=1; r11l=1;
				""", List.of(ev("r0", "1"), ev("r9", "1"))), new Case("gt", """
				r1  =2; r2  =1;
				r10l=2; r11l=1;
				""", List.of(ev("r0", "0"), ev("r9", "0"))), new Case("sgt", """
				r1  =2; r2  =-1;
				r10l=2; r11l=-1;
				""", List.of(ev("r0", "0"), ev("r9", "0")))));
	}

	@Test
	public void testIntEqualMpIntOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(ID_TOYBE64, """
				temp1:9 = sext(r1);
				temp2:9 = sext(r2);
				r0 = temp1 == temp2;
				"""), List.of(new Case("lt", """
				r1 = 1; r2 = 2;
				""", List.of(ev("r0", "0"))), new Case("slt", """
				r1 = -1; r2 = 0x7fffffffffffffff;
				""", List.of(ev("r0", "0"))), new Case("eq", """
				r1 = 1; r2 = 1;
				""", List.of(ev("r0", "1"))), new Case("gt", """
				r1 = 2; r2 = 1;
				""", List.of(ev("r0", "0"))), new Case("sgt", """
				r1 = 2; r2 = -1;
				""", List.of(ev("r0", "0")))));
	}

	@Test
	public void testIntNotEqualOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(ID_TOYBE64, """
				r0 = r1 != r2;
				r9l = r10l != r11l;
				"""), List.of(new Case("lt", """
				r1  =1; r2  =2;
				r10l=1; r11l=2;
				""", List.of(ev("r0", "1"), ev("r9", "1"))), new Case("slt", """
				r1  =-1; r2  =2;
				r10l=-1; r11l=2;
				""", List.of(ev("r0", "1"), ev("r9", "1"))), new Case("eq", """
				r1  =1; r2  =1;
				r10l=1; r11l=1;
				""", List.of(ev("r0", "0"), ev("r9", "0"))), new Case("gt", """
				r1  =2; r2  =1;
				r10l=2; r11l=1;
				""", List.of(ev("r0", "1"), ev("r9", "1"))), new Case("sgt", """
				r1  =2; r2  =-1;
				r10l=2; r11l=-1;
				""", List.of(ev("r0", "1"), ev("r9", "1")))));
	}

	@Test
	public void testIntNotEqualMpIntOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(ID_TOYBE64, """
				temp1:9 = sext(r1);
				temp2:9 = sext(r2);
				r0 = temp1 != temp2;
				"""), List.of(new Case("lt", """
				r1 = 1; r2 = 2;
				""", List.of(ev("r0", "1"))), new Case("slt", """
				r1 = -1; r2 = 0x7fffffffffffffff;
				""", List.of(ev("r0", "1"))), new Case("eq", """
				r1 = 1; r2 = 1;
				""", List.of(ev("r0", "0"))), new Case("gt", """
				r1 = 2; r2 = 1;
				""", List.of(ev("r0", "1"))), new Case("sgt", """
				r1 = 2; r2 = -1;
				""", List.of(ev("r0", "1")))));
	}

	@Test
	public void testIntLessEqualOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(ID_TOYBE64, """
				r0 = r1 <= r2;
				r9l = r10l <= r11l;
				"""), List.of(new Case("lt", """
				r1  =1; r2  =2;
				r10l=1; r11l=2;
				""", List.of(ev("r0", "1"), ev("r9", "1"))), new Case("slt", """
				r1  =-1; r2  =2;
				r10l=-1; r11l=2;
				""", List.of(ev("r0", "0"), ev("r9", "0"))), new Case("eq", """
				r1  =1; r2  =1;
				r10l=1; r11l=1;
				""", List.of(ev("r0", "1"), ev("r9", "1"))), new Case("gt", """
				r1  =2; r2  =1;
				r10l=2; r11l=1;
				""", List.of(ev("r0", "0"), ev("r9", "0"))), new Case("sgt", """
				r1  =2; r2  =-1;
				r10l=2; r11l=-1;
				""", List.of(ev("r0", "1"), ev("r9", "1")))));
	}

	@Test
	public void testIntLessEqualMpIntOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(ID_TOYBE64, """
				temp1:9 = sext(r1);
				temp2:9 = sext(r2);
				r0 = temp1 <= temp2;
				"""), List.of(new Case("lt", """
				r1 = 1; r2 = 2;
				""", List.of(ev("r0", "1"))), new Case("slt", """
				r1 = -1; r2 = 0x7fffffffffffffff;
				""", List.of(ev("r0", "0"))), new Case("eq", """
				r1 = 1; r2 = 1;
				""", List.of(ev("r0", "1"))), new Case("gt", """
				r1 = 2; r2 = 1;
				""", List.of(ev("r0", "0"))), new Case("sgt", """
				r1 = 2; r2 = -1;
				""", List.of(ev("r0", "1")))));
	}

	@Test
	public void testIntSLessEqualOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(ID_TOYBE64, """
				r0 = r1 s<= r2;
				r9l = r10l s<= r11l;
				"""), List.of(new Case("lt", """
				r1  =1; r2  =2;
				r10l=1; r11l=2;
				""", List.of(ev("r0", "1"), ev("r9", "1"))), new Case("slt", """
				r1  =-1; r2  =2;
				r10l=-1; r11l=2;
				""", List.of(ev("r0", "1"), ev("r9", "1"))), new Case("eq", """
				r1  =1; r2  =1;
				r10l=1; r11l=1;
				""", List.of(ev("r0", "1"), ev("r9", "1"))), new Case("gt", """
				r1  =2; r2  =1;
				r10l=2; r11l=1;
				""", List.of(ev("r0", "0"), ev("r9", "0"))), new Case("sgt", """
				r1  =2; r2  =-1;
				r10l=2; r11l=-1;
				""", List.of(ev("r0", "0"), ev("r9", "0")))));
	}

	@Test
	public void testIntSLessEqualMpIntOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(ID_TOYBE64, """
				temp1:9 = sext(r1);
				temp2:9 = sext(r2);
				r0 = temp1 s<= temp2;
				"""), List.of(new Case("lt", """
				r1 = 1; r2 = 2;
				""", List.of(ev("r0", "1"))), new Case("slt", """
				r1 = -1; r2 = 0x7fffffffffffffff;
				""", List.of(ev("r0", "1"))), new Case("eq", """
				r1 = 1; r2 = 1;
				""", List.of(ev("r0", "1"))), new Case("gt", """
				r1 = 2; r2 = 1;
				""", List.of(ev("r0", "0"))), new Case("sgt", """
				r1 = 2; r2 = -1;
				""", List.of(ev("r0", "0")))));
	}

	@Test
	public void testIntLessOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(ID_TOYBE64, """
				r0 = r1 < r2;
				r9l = r10l < r11l;
				"""), List.of(new Case("lt", """
				r1  =1; r2  =2;
				r10l=1; r11l=2;
				""", List.of(ev("r0", "1"), ev("r9", "1"))), new Case("slt", """
				r1  =-1; r2  =2;
				r10l=-1; r11l=2;
				""", List.of(ev("r0", "0"), ev("r9", "0"))), new Case("eq", """
				r1  =1; r2  =1;
				r10l=1; r11l=1;
				""", List.of(ev("r0", "0"), ev("r9", "0"))), new Case("gt", """
				r1  =2; r2  =1;
				r10l=2; r11l=1;
				""", List.of(ev("r0", "0"), ev("r9", "0"))), new Case("sgt", """
				r1  =2; r2  =-1;
				r10l=2; r11l=-1;
				""", List.of(ev("r0", "1"), ev("r9", "1")))));
	}

	@Test
	public void testIntLessMpIntOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(ID_TOYBE64, """
				temp1:9 = sext(r1);
				temp2:9 = sext(r2);
				r0 = temp1 < temp2;
				"""), List.of(new Case("lt", """
				r1 = 1; r2 = 2;
				""", List.of(ev("r0", "1"))), new Case("slt", """
				r1 = -1; r2 = 0x7fffffffffffffff;
				""", List.of(ev("r0", "0"))), new Case("eq", """
				r1 = 1; r2 = 1;
				""", List.of(ev("r0", "0"))), new Case("gt", """
				r1 = 2; r2 = 1;
				""", List.of(ev("r0", "0"))), new Case("sgt", """
				r1 = 2; r2 = -1;
				""", List.of(ev("r0", "1")))));
	}

	@Test
	public void testIntSLessOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(ID_TOYBE64, """
				r0 = r1 s< r2;
				r9l = r10l s< r11l;
				"""), List.of(new Case("lt", """
				r1  =1; r2  =2;
				r10l=1; r11l=2;
				""", List.of(ev("r0", "1"), ev("r9", "1"))), new Case("slt", """
				r1  =-1; r2  =2;
				r10l=-1; r11l=2;
				""", List.of(ev("r0", "1"), ev("r9", "1"))), new Case("eq", """
				r1  =1; r2  =1;
				r10l=1; r11l=1;
				""", List.of(ev("r0", "0"), ev("r9", "0"))), new Case("gt", """
				r1  =2; r2  =1;
				r10l=2; r11l=1;
				""", List.of(ev("r0", "0"), ev("r9", "0"))), new Case("sgt", """
				r1  =2; r2  =-1;
				r10l=2; r11l=-1;
				""", List.of(ev("r0", "0"), ev("r9", "0")))));
	}

	@Test
	public void testIntSLessMpIntOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(ID_TOYBE64, """
				temp1:9 = sext(r1);
				temp2:9 = sext(r2);
				r0 = temp1 s< temp2;
				"""), List.of(new Case("lt", """
				r1 = 1; r2 = 2;
				""", List.of(ev("r0", "1"))), new Case("slt", """
				r1 = -1; r2 = 0x7fffffffffffffff;
				""", List.of(ev("r0", "1"))), new Case("eq", """
				r1 = 1; r2 = 1;
				""", List.of(ev("r0", "0"))), new Case("gt", """
				r1 = 2; r2 = 1;
				""", List.of(ev("r0", "0"))), new Case("sgt", """
				r1 = 2; r2 = -1;
				""", List.of(ev("r0", "0")))));
	}

	@Test
	public void testIntCarryOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(ID_TOYBE64, """
				r0 = carry(r1, r2);
				r9l = carry(r10l, r11l);
				"""), List.of(new Case("f", """
				r1  =0x8000000000000000; r2  =0x4000000000000000;
				r10l=0x80000000;         r11l=0x40000000;
				""", List.of(ev("r0", "0"), ev("r9", "0"))), new Case("t", """
				r1  =0x8000000000000000; r2  =0x8000000000000000;
				r10l=0x80000000;         r11l=0x80000000;
				""", List.of(ev("r0", "1"), ev("r9", "1")))));
	}

	@Test
	public void testIntCarryMpIntOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(ID_TOYBE64, """
				temp1:9 = zext(r1) << 8;
				temp2:9 = zext(r2) << 8;
				r0 = carry(temp1, temp2);
				"""), List.of(new Case("f", """
				r1  =0x8000000000000000; r2  =0x4000000000000000;
				r10l=0x80000000;         r11l=0x40000000;
				""", List.of(ev("r0", "0"))), new Case("t", """
				r1  =0x8000000000000000; r2  =0x8000000000000000;
				r10l=0x80000000;         r11l=0x80000000;
				""", List.of(ev("r0", "1")))));
	}

	@Test
	public void testIntSCarryOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(ID_TOYBE64, """
				r0 = scarry(r1, r2);
				r9l = scarry(r10l, r11l);
				"""), List.of(new Case("f", """
				r1  =0x8000000000000000; r2  =0x4000000000000000;
				r10l=0x80000000;         r11l=0x40000000;
				""", List.of(ev("r0", "0"), ev("r9", "0"))), new Case("t", """
				r1  =0x4000000000000000; r2  =0x4000000000000000;
				r10l=0x40000000;         r11l=0x40000000;
				""", List.of(ev("r0", "1"), ev("r9", "1")))));
	}

	@Test
	public void testIntSCarryMpIntOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(ID_TOYBE64, """
				temp1:9 = zext(r1) << 8;
				temp2:9 = zext(r2) << 8;
				r0 = scarry(temp1, temp2);
				"""), List.of(new Case("f", """
				r1  =0x8000000000000000; r2  =0x4000000000000000;
				r10l=0x80000000;         r11l=0x40000000;
				""", List.of(ev("r0", "0"))), new Case("t", """
				r1  =0x4000000000000000; r2  =0x4000000000000000;
				r10l=0x40000000;         r11l=0x40000000;
				""", List.of(ev("r0", "1")))));
	}

	@Test
	public void testIntSBorrowOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(ID_TOYBE64, """
				r0 = sborrow(r1, r2);
				r9l = sborrow(r10l, r11l);
				"""), List.of(new Case("t", """
				r1  =0x8000000000000000; r2  =0x4000000000000000;
				r10l=0x80000000;         r11l=0x40000000;
				""", List.of(ev("r0", "1"), ev("r9", "1"))), new Case("f", """
				r1  =0xc000000000000000; r2  =0x4000000000000000;
				r10l=0xc0000000;         r11l=0x40000000;
				""", List.of(ev("r0", "0"), ev("r9", "0")))));
	}

	@Test
	public void testIntSBorrowMpIntOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(ID_TOYBE64, """
				temp1:9 = zext(r1) << 8;
				temp2:9 = zext(r2) << 8;
				r0 = sborrow(temp1, temp2);
				"""), List.of(new Case("t", """
				r1  =0x8000000000000000; r2  =0x4000000000000000;
				r10l=0x80000000;         r11l=0x40000000;
				""", List.of(ev("r0", "1"))), new Case("f", """
				r1  =0xc000000000000000; r2  =0x4000000000000000;
				r10l=0xc0000000;         r11l=0x40000000;
				""", List.of(ev("r0", "0")))));
	}

	@Test
	public void testIntLeftOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(ID_TOYBE64, """
				r0 = r1 << r2;
				r3 = r4 << r5l;
				r6l = r7l << r8;
				r9l = r10l << r11l;
				"""), List.of(
			new Case("posLposR", """
					r1  =100; r2  =4;
					r4  =100; r5l =4;
					r7l =100; r8  =4;
					r10l=100; r11l=4;
					""",
				List.of(ev("r0", "0x640"), ev("r3", "0x640"), ev("r6l", "0x640"),
					ev("r9l", "0x640"))),
			new Case("posLbigR", """
					r1  =100; r2  =0x100000004;
					r4  =100; r5l =0x100000004;
					r7l =100; r8  =0x100000004;
					r10l=100; r11l=0x100000004;
					""",
				List.of(ev("r0", "0"), ev("r3", "0x640"), ev("r6l", "0"), ev("r9l", "0x640"))),
			new Case("posLnegR", """
					r1  =100; r2  =-4;
					r4  =100; r5l =-4;
					r7l =100; r8  =-4;
					r10l=100; r11l=-4;
					""", List.of(ev("r0", "0"), ev("r3", "0"), ev("r6l", "0"), ev("r9l", "0"))),
			new Case("negLposR", """
					r1  =-100; r2  =4;
					r4  =-100; r5l =4;
					r7l =-100; r8  =4;
					r10l=-100; r11l=4;
					""",
				List.of(ev("r0", "-0x640"), ev("r3", "-0x640"), ev("r6l", "-0x640"),
					ev("r9l", "-0x640"))),
			new Case("negLnegR", """
					r1  =-100; r2  =-4;
					r4  =-100; r5l =-4;
					r7l =-100; r8  =-4;
					r10l=-100; r11l=-4;
					""", List.of(ev("r0", "0"), ev("r3", "0"), ev("r6l", "0"), ev("r9l", "0")))));
	}

	@Test
	public void testIntLeftMpIntOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(ID_TOYBE64, """
				temp1:9 = sext(r1);
				temp2:9 = (zext(r2) << 64) + r3;
				temp0:9 = temp1 << temp2;
				r0 = temp0(0);
				r4 = temp0(1);
				"""), List.of(new Case("posLposR", """
				r1 = 0x7edcba9876543210;
				r2 = 0;
				r3 = 4;
				""", List.of(ev("r0", "0xedcba98765432100"), ev("r4", "0x07edcba987654321"))),
			new Case("posLmedR", """
					r1 = 0x7edcba9876543210;
					r2 = 0;
					r3 = 36;
					""", List.of(ev("r0", "0x6543210000000000"), ev("r4", "0x8765432100000000"))),
			new Case("posLbigR", """
					r1 = 0x7edcba9876543210;
					r2 = 0x40;
					r3 = 4;
					""", List.of(ev("r0", "0"), ev("r4", "0"))), new Case("posLnegR", """
					r1 = 0x7edcba9876543210;
					r2 = -1;
					r3 = -4;
					""", List.of(ev("r0", "0"), ev("r4", "0"))), new Case("negLposR", """
					r1 = 0xfedcba9876543210;
					r2 = 0;
					r3 = 4;
					""", List.of(ev("r0", "0xedcba98765432100"), ev("r4", "0xffedcba987654321"))),
			new Case("negLnegR", """
					r1 = 0xfedcba9876543210;
					r2 = -1;
					r3 = -4;
					""", List.of(ev("r0", "0"), ev("r4", "0")))));
	}

	@Test
	public void testIntRightOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(ID_TOYBE64, """
				r0 = r1 >> r2;
				r3 = r4 >> r5l;
				r6l = r7l >> r8;
				r9l = r10l >> r11l;
				"""), List.of(new Case("posLposR", """
				r1  =100; r2  =4;
				r4  =100; r5l =4;
				r7l =100; r8  =4;
				r10l=100; r11l=4;
				""", List.of(ev("r0", "6"), ev("r3", "6"), ev("r6l", "6"), ev("r9l", "6"))),
			new Case("posLbigR", """
					r1  =100; r2  =0x100000004;
					r4  =100; r5l =0x100000004;
					r7l =100; r8  =0x100000004;
					r10l=100; r11l=0x100000004;
					""", List.of(ev("r0", "0"), ev("r3", "6"), ev("r6l", "0"), ev("r9l", "6"))),
			new Case("posLnegR", """
					r1  =100; r2  =-4;
					r4  =100; r5l =-4;
					r7l =100; r8  =-4;
					r10l=100; r11l=-4;
					""", List.of(ev("r0", "0"), ev("r3", "0"), ev("r6l", "0"), ev("r9l", "0"))),
			new Case("negLposR", """
					r1  =-100; r2  =4;
					r4  =-100; r5l =4;
					r7l =-100; r8  =4;
					r10l=-100; r11l=4;
					""",
				List.of(ev("r0", "0x0ffffffffffffff9"), ev("r3", "0x0ffffffffffffff9"),
					ev("r6l", "0x0ffffff9"), ev("r9l", "0x0ffffff9"))),
			new Case("negLnegR", """
					r1  =-100; r2  =-4;
					r4  =-100; r5l =-4;
					r7l =-100; r8  =-4;
					r10l=-100; r11l=-4;
					""", List.of(ev("r0", "0"), ev("r3", "0"), ev("r6l", "0"), ev("r9l", "0")))));
	}

	@Test
	public void testIntRightMpIntOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(ID_TOYBE64, """
				temp1:9 = sext(r1);
				temp2:9 = (zext(r2) << 64) + r3;
				temp0:9 = temp1 >> temp2;
				r0 = temp0(0);
				r4 = temp0(1);
				"""), List.of(new Case("posLposR", """
				r1 = 0x7edcba9876543210;
				r2 = 0;
				r3 = 4;
				""", List.of(ev("r0", "0x07edcba987654321"), ev("r4", "0x0007edcba9876543"))),
			new Case("posLmedR", """
					r1 = 0x7edcba9876543210;
					r2 = 0;
					r3 = 36;
					""", List.of(ev("r0", "0x0000000007edcba9"), ev("r4", "0x000000000007edcb"))),
			new Case("posLbigR", """
					r1 = 0x7edcba9876543210;
					r2 = 0x40;
					r3 = 4;
					""", List.of(ev("r0", "0"), ev("r4", "0"))), new Case("posLnegR", """
					r1 = 0x7edcba9876543210;
					r2 = -1;
					r3 = -4;
					""", List.of(ev("r0", "0"), ev("r4", "0"))), new Case("negLposR", """
					r1 = 0xfedcba9876543210;
					r2 = 0;
					r3 = 4;
					""", List.of(ev("r0", "0xffedcba987654321"), ev("r4", "0x0fffedcba9876543"))),
			new Case("negLmedR", """
					r1 = 0xfedcba9876543210;
					r2 = 0;
					r3 = 36;
					""", List.of(ev("r0", "0x0000000fffedcba9"), ev("r4", "0x000000000fffedcb"))),
			new Case("negLnegR", """
					r1 = 0xfedcba9876543210;
					r2 = -1;
					r3 = -4;
					""", List.of(ev("r0", "0"), ev("r4", "0")))));
	}

	@Test
	public void testIntSRightOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(ID_TOYBE64, """
				r0 = r1 s>> r2;
				r3 = r4 s>> r5l;
				r6l = r7l s>> r8;
				r9l = r10l s>> r11l;
				"""),
			List.of(new Case("posLposR", """
					r1  =100; r2  =4;
					r4  =100; r5l =4;
					r7l =100; r8  =4;
					r10l=100; r11l=4;
					""", List.of(ev("r0", "6"), ev("r3", "6"), ev("r6l", "6"), ev("r9l", "6"))),
				new Case("posLbigR", """
						r1  =100; r2  =0x100000004;
						r4  =100; r5l =0x100000004;
						r7l =100; r8  =0x100000004;
						r10l=100; r11l=0x100000004;
						""", List.of(ev("r0", "0"), ev("r3", "6"), ev("r6l", "0"), ev("r9l", "6"))),
				new Case("posLnegR", """
						r1  =100; r2  =-4;
						r4  =100; r5l =-4;
						r7l =100; r8  =-4;
						r10l=100; r11l=-4;
						""", List.of(ev("r0", "0"), ev("r3", "0"), ev("r6l", "0"), ev("r9l", "0"))),
				new Case("negLposR", """
						r1  =-100; r2  =4;
						r4  =-100; r5l =4;
						r7l =-100; r8  =4;
						r10l=-100; r11l=4;
						""",
					List.of(ev("r0", "-7"), ev("r3", "-7"), ev("r6l", "-7"), ev("r9l", "-7"))),
				new Case("negLnegR", """
						r1  =-100; r2  =-4;
						r4  =-100; r5l =-4;
						r7l =-100; r8  =-4;
						r10l=-100; r11l=-4;
						""",
					List.of(ev("r0", "-1"), ev("r3", "-1"), ev("r6l", "-1"), ev("r9l", "-1")))));
	}

	@Test
	public void testIntSRight3IntOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(ID_TOYBE64, """
				temp1:3 = r1(0);
				temp0:3 = temp1 s>> r2;
				r0 = zext(temp0);
				"""), List.of(new Case("posLposR", """
				r1 = 0xfedcba;
				r2 = 4;
				""", List.of(ev("r0", "0xffedcb")))));
	}

	@Test
	public void testIntSRightMpIntOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(ID_TOYBE64, """
				temp1:9 = sext(r1);
				temp2:9 = (zext(r2) << 64) + r3;
				temp0:9 = temp1 s>> temp2;
				r0 = temp0(0);
				r4 = temp0(1);
				"""), List.of(new Case("posLposR", """
				r1 = 0x7edcba9876543210;
				r2 = 0;
				r3 = 4;
				""", List.of(ev("r0", "0x07edcba987654321"), ev("r4", "0x0007edcba9876543"))),
			new Case("posLmedR", """
					r1 = 0x7edcba9876543210;
					r2 = 0;
					r3 = 36;
					""", List.of(ev("r0", "0x0000000007edcba9"), ev("r4", "0x000000000007edcb"))),
			new Case("posLbigR", """
					r1 = 0x7edcba9876543210;
					r2 = 0x40;
					r3 = 4;
					""", List.of(ev("r0", "0"), ev("r4", "0"))), new Case("posLnegR", """
					r1 = 0x7edcba9876543210;
					r2 = -1;
					r3 = -4;
					""", List.of(ev("r0", "0"), ev("r4", "0"))), new Case("negLposR", """
					r1 = 0xfedcba9876543210;
					r2 = 0;
					r3 = 4;
					""", List.of(ev("r0", "0xffedcba987654321"), ev("r4", "0xffffedcba9876543"))),
			new Case("negLlegR", """
					r1 = 0xfedcba9876543210;
					r2 = 0;
					r3 = 32;
					""", List.of(ev("r0", "0xfffffffffedcba98"), ev("r4", "0xfffffffffffedcba"))),
			new Case("negLmedR", """
					r1 = 0xfedcba9876543210;
					r2 = 0;
					r3 = 36;
					""", List.of(ev("r0", "0xffffffffffedcba9"), ev("r4", "0xffffffffffffedcb"))),
			new Case("negLnegR", """
					r1 = 0xfedcba9876543210;
					r2 = -1;
					r3 = -4;
					""", List.of(ev("r0", "-1"), ev("r4", "-1")))));
	}

	@Test
	public void testFloatAsOffset() throws Exception {
		int fDot5 = Float.floatToRawIntBits(0.5f);
		int f1Dot0 = Float.floatToRawIntBits(1.0f);
		Translation tr = translateSleigh(ID_TOYBE64, """
				temp:4 = 0x%x f+ 0x%x;
				temp2:8 = *temp;
				""".formatted(fDot5, fDot5));
		Varnode temp2 = tr.program.getCode().get(1).getOutput();
		assertTrue(temp2.isUnique());
		tr.setLongMemVal(f1Dot0, LONG_CONST, 8);
		tr.runFallthrough();
		assertEquals(LONG_CONST, tr.getLongVnVal(temp2));
	}

	@Test
	public void testDoubleAsOffset() throws Exception {
		long dDot5 = Double.doubleToRawLongBits(0.5);
		long d1Dot0 = Double.doubleToRawLongBits(1.0);
		Translation tr = translateSleigh(ID_TOYBE64, """
				temp:8 = 0x%x f+ 0x%x;
				temp2:8 = *temp;
				""".formatted(dDot5, dDot5));
		Varnode temp2 = tr.program.getCode().get(1).getOutput();
		assertTrue(temp2.isUnique());
		tr.setLongMemVal(d1Dot0, LONG_CONST, 8);
		tr.runFallthrough();
		assertEquals(LONG_CONST, tr.getLongVnVal(temp2));
	}

	@Test
	public void testArmThumbFunc() throws Exception {
		AssemblyBuffer asm = createBuffer(ID_ARMv8LE, 0x00400000);

		Language language = asm.getAssembler().getLanguage();
		Register regCtx = language.getContextBaseRegister();
		Register regT = language.getRegister("T");
		RegisterValue rvDefault = new RegisterValue(regCtx,
			asm.getAssembler().getContextAt(asm.getNext()).toBigInteger(regCtx.getNumBytes()));
		RegisterValue rvArm = rvDefault.assign(regT, BigInteger.ZERO);
		RegisterValue rvThumb = rvDefault.assign(regT, BigInteger.ONE);

		AssemblyPatternBlock ctxThumb = AssemblyPatternBlock.fromRegisterValue(rvThumb);

		asm.assemble("mov r1, #456");
		Address addrBlx = asm.getNext();
		asm.assemble("blx 0x0");
		Address addrRet = asm.getNext(); // The address where we expect to return
		asm.assemble("bx lr"); // Follows CALL, so principally, must be here, but not decoded
		Address addrThumb = asm.getNext();
		asm.assemble("add r0, r1", ctxThumb);
		asm.assemble("bx lr", ctxThumb);

		asm.assemble(addrBlx, "blx 0x%s".formatted(addrThumb));

		Translation tr = translateBuffer(asm, asm.getEntry(), Map.of());

		assertEquals(Map.ofEntries(tr.entryPrototype(asm.getEntry(), rvArm, 0),
			tr.entryPrototype(addrThumb, rvThumb, 1)), tr.passageCls.getBlockEntries());

		/**
		 * The blx will be a direct branch, so that will get executed in the bytecode. However, the
		 * bx lr (from THUMB) will be an indirect jump, causing a passage exit, so we should expect
		 * the return value to be the address immediately after the blx. Of course, that's not all
		 * that convincing.... So, we'll assert that r0 was set, too.
		 */
		assertEquals(addrRet.getOffset(), tr.runClean());
		assertEquals(456, tr.getLongRegVal("r0"));
	}

	/**
	 * This is more diagnostics, but at the least, I should document that it doesn't work as
	 * expected, or perhaps just turn it completely off.
	 */
	@Test
	@Ignore("TODO")
	public void testUninitializedVsInitializedReads() {
		TODO();
	}

	@Test
	public void testExitAsThumb() throws Exception {
		Translation tr = translateLang(ID_ARMv8LE, 0x00400000, """
				blx 0x00500000
				""", Map.of());
		Language language = tr.state.getLanguage();
		Register regCtx = language.getContextBaseRegister();
		Register regT = language.getRegister("T");

		tr.runDecodeErr(0x00500000);
		RegisterValue actualCtx = tr.getRegVal(regCtx);
		RegisterValue expectedCtx = actualCtx.assign(regT, BigInteger.ONE);
		assertEquals(expectedCtx, actualCtx);
	}

	@Test
	public void testDelaySlot() throws Exception {
		Translation tr = translateLang(ID_TOYBE64, 0x00400000, """
				brds r0
				imm r0, #123
				""", Map.of());
		tr.setLongRegVal("r0", 0x1234);
		assertEquals(0x1234, tr.runClean());
		assertEquals(123, tr.getLongRegVal("r0"));
	}

	@Test
	public void testX86OffcutJump() throws Exception {
		Translation tr = translateLang(ID_X8664, 0x00400000, """
				.emit eb ff c0
				CALL 0x0dedbeef
				""".formatted(LONG_CONST), Map.of());
		tr.runDecodeErr(0x0dedbeef);
	}

	@Test
	public void testEmuInjectionCallEmuSwi() throws Exception {
		Translation tr = translateLang(ID_TOYBE64, 0x00400000, """
				imm r0,#123
				add r0,#7
				""", Map.ofEntries(Map.entry(0x00400002L, "emu_swi();")));

		tr.runErr(InterruptPcodeExecutionException.class, "Execution hit breakpoint");

		/**
		 * Two reasons we don't reach the add: 1) It's overridden, and there's no deferral to the
		 * decoded instruction. 2) Even if there were, we got interrupted before it executed.
		 */
		assertEquals(123, tr.getLongRegVal("r0"));
	}

	@Test
	public void testEmuInjectionCallEmuExecDecoded() throws Exception {
		Translation tr = translateLang(ID_TOYBE64, 0x00400000, """
				imm r0,#123
				add r0,#7
				""", Map.ofEntries(Map.entry(0x00400002L, """
				r1 = sleigh_userop(r0, 4:8);
				emu_exec_decoded();
				""")));

		tr.runDecodeErr(0x00400004);
		assertEquals(123 + 7, tr.getLongRegVal("r0"));
		assertEquals(123 * 2 + 4, tr.getLongRegVal("r1"));
	}

	@Test
	public void testEmuInjectionCallEmuSkipDecoded() throws Exception {
		Translation tr = translateLang(ID_TOYBE64, 0x00400000, """
				imm r0,#123
				add r0,#7
				""", Map.ofEntries(Map.entry(0x00400002L, """
				r1 = sleigh_userop(r0, 4:8);
				emu_skip_decoded();
				""")));

		tr.runDecodeErr(0x00400004);
		assertEquals(123, tr.getLongRegVal("r0"));
		assertEquals(123 * 2 + 4, tr.getLongRegVal("r1"));
	}

	@Test
	public void testFlagOpsRemoved() throws Exception {
		Translation tr = translateLang(ID_TOYBE64, 0x00400000, """
				add r0,#6
				add r0,#7
				""", Map.of());

		tr.runDecodeErr(0x00400004);
		assertEquals(13, tr.getLongRegVal("r0"));

		long countSCarrys = Stream.of(tr.run.instructions.toArray()).filter(i -> {
			if (!(i instanceof MethodInsnNode mi)) {
				return false;
			}
			return "sCarryLongRaw".equals(mi.name);
		}).count();
		assertEquals(1, countSCarrys);
	}

	@Test
	public void testCtxHazardousFallthrough() throws Exception {
		Translation tr = translateLang(ID_ARMv8LE, 0x00400000, """
				mov r0,#6
				mov r1,#7
				""", Map.ofEntries(Map.entry(0x00400000L, """
				setISAMode(1:1);
				emu_exec_decoded();
				""")));

		tr.runClean();
		assertEquals(6, tr.getLongRegVal("r0"));
		// Should not execute second instruction, because of injected ctx change
		assertEquals(0, tr.getLongRegVal("r1"));
	}

	@Test
	public void testCtxMaybeHazardousFallthrough() throws Exception {
		/**
		 * For this test to produce the "MAYBE" case, the multiple paths have to be
		 * <em>internal</em> to an instruction (or inject). All that logic is only applied on an
		 * instruction-by-instruction basis.
		 */
		Translation tr = translateLang(ID_ARMv8LE, 0x00400000, """
				mov r0,#6
				mov r1,#7
				""", Map.ofEntries(Map.entry(0x00400000L, """
				if (!ZR) goto <skip>;
				  ISAModeSwitch = 1;
				  setISAMode(ISAModeSwitch);
				<skip>
				emu_exec_decoded();
				""")));

		tr.setLongRegVal("r1", 0); // Reset
		tr.setLongRegVal("ZR", 0);
		// Since ctx wasn't touched at runtime, we fall out of program
		tr.runDecodeErr(0x00400008);
		assertEquals(6, tr.getLongRegVal("r0"));
		assertEquals(7, tr.getLongRegVal("r1"));
		assertEquals(0, tr.getLongRegVal("ISAModeSwitch"));

		tr.setLongRegVal("r1", 0); // Reset
		tr.setLongRegVal("ZR", 1);
		// Hazard causes exit before 2nd instruction
		tr.runClean();
		assertEquals(6, tr.getLongRegVal("r0"));
		assertEquals(0, tr.getLongRegVal("r1"));
		assertEquals(1, tr.getLongRegVal("ISAModeSwitch"));
	}
}
