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

import static ghidra.lifecycle.Unfinished.TODO;
import static org.junit.Assert.*;

import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import org.junit.Ignore;
import org.junit.Test;
import org.objectweb.asm.tree.MethodInsnNode;

import ghidra.pcode.emu.jit.gen.JitCodeGenerator.PcodeOpKey;
import ghidra.pcode.exec.InterruptPcodeExecutionException;
import ghidra.pcode.exec.SleighLinkException;
import ghidra.pcode.floatformat.FloatFormat;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

public abstract class AbstractToyJitCodeGeneratorTest extends AbstractJitCodeGeneratorTest {

	protected static final LanguageID ID_TOYBE64 = new LanguageID("Toy:BE:64:default");
	protected static final LanguageID ID_TOYLE64 = new LanguageID("Toy:LE:64:default");
	protected static final LanguageID ID_TOYBE32 = new LanguageID("Toy:BE:32:default");

	protected abstract Endian getEndian();

	@Override
	protected LanguageID getLanguageID() {
		return switch (getEndian()) {
			case BIG -> ID_TOYBE64;
			case LITTLE -> ID_TOYLE64;
		};
	}

	public Translation translateToy(long offset, String source) throws Exception {
		return translateLang(getLanguageID(), offset, source, Map.of());
	}

	@Test
	public void testSimpleInt() throws Exception {
		Translation tr = translateSleigh(getLanguageID(), """
				temp:4 = 0x1234;
				""");
		Varnode temp = tr.program().getCode().getFirst().getOutput();
		assertTrue(temp.isUnique());
		tr.runFallthrough();
		assertEquals(0x1234, tr.getLongVnVal(temp));
	}

	@Test
	public void testByteInIntLoad() throws Exception {
		Translation tr = translateSleigh(getLanguageID(), """
				temp:1 = r1l(2) + 0x34;
				r0 = zext(temp);
				""");
		runEquivalenceTest(tr, List.of(
			new Case("only", "r1l = 0x11223344;", List.of(ev("r0", "0x56")))));
		// NOTE: Would be nice to assert about positioning and masking
	}

	@Test
	public void testByteInIntStore() throws Exception {
		Translation tr = translateSleigh(getLanguageID(), """
				r0l = 0xffffffff;
				r0l[16,8] = 0x12;
				""");
		runEquivalenceTest(tr, List.of(
			new Case("only", "", List.of(ev("r0", "0xff12ffff")))));
	}

	@Test
	public void testByteInLongLoad() throws Exception {
		Translation tr = translateSleigh(getLanguageID(), """
				temp:1 = r1(3) + 0x34;
				r0 = zext(temp);
				""");
		runEquivalenceTest(tr, List.of(
			new Case("only", "r1l = 0x1122334455667788;", List.of(ev("r0", "0x89")))));
		// NOTE: Would be nice to assert about positioning and masking
	}

	@Test
	public void testByteInLongStore() throws Exception {
		Translation tr = translateSleigh(getLanguageID(), """
				r0 = 0xffffffffffffffff;
				r0[24,8] = 0x12;
				""");
		runEquivalenceTest(tr, List.of(
			new Case("only", "", List.of(ev("r0", "0xffffffff12ffffff")))));
	}

	/**
	 * NOTE: There's no case where it should generate code reading a byte out of a float local.
	 * Instead, the coalescing should cause the local to be an int. It'll get converted to float
	 * when a float op requires it. Still, we should get the semantics we expect. That said, there's
	 * no no need (I think) to test "storing" into a float (nor into a double).
	 * 
	 * @throws Exception because
	 */
	@Test
	public void testByteInFloatLoad() throws Exception {
		int f2Dot5 = Float.floatToRawIntBits(2.5f);
		int f7Dot5 = Float.floatToRawIntBits(7.5f);
		Translation tr = translateSleigh(getLanguageID(), """
				r1l = r2l f+ r3l;
				r1l = sqrt(r1l);
				temp:1 = r1l(2);
				r0 = zext(temp);
				""");
		runEquivalenceTest(tr, List.of(
			new Case("only", "r2l = 0x%x; r3l = 0x%x;".formatted(f2Dot5, f7Dot5),
				List.of(ev("r0", "0x4a")))));
	}

	@Test
	public void testByteInDoubleLoad() throws Exception {
		long d2Dot5 = Double.doubleToRawLongBits(2.5);
		long d7Dot5 = Double.doubleToRawLongBits(7.5);
		Translation tr = translateSleigh(getLanguageID(), """
				r1 = r2 f+ r3;
				r1 = sqrt(r1);
				temp:1 = r1(2);
				r0 = zext(temp);
				""");
		runEquivalenceTest(tr, List.of(
			new Case("only", "r2 = 0x%x; r3 = 0x%x;".formatted(d2Dot5, d7Dot5),
				List.of(ev("r0", "0xda")))));
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
		Translation tr = translateSleigh(getLanguageID(), """
				temp:8 = 0x1234;
				""");
		Varnode temp = tr.program().getCode().getFirst().getOutput();
		assertTrue(temp.isUnique());
		tr.runFallthrough();
		assertEquals(0x1234, tr.getLongVnVal(temp));
	}

	@Test
	public void testSimpleFloat() throws Exception {
		int fDot5 = Float.floatToRawIntBits(0.5f);
		int fDot75 = Float.floatToRawIntBits(0.75f);
		Translation tr = translateSleigh(getLanguageID(), """
				temp:4 = 0x%x f+ 0x%x;
				""".formatted(fDot5, fDot75));
		Varnode temp = tr.program().getCode().getFirst().getOutput();
		assertTrue(temp.isUnique());
		tr.runFallthrough();
		assertEquals(1.25f, Float.intBitsToFloat((int) tr.getLongVnVal(temp)), 0);
	}

	@Test
	public void testSimpleDouble() throws Exception {
		long dDot5 = Double.doubleToRawLongBits(0.5);
		long dDot75 = Double.doubleToRawLongBits(0.75);
		Translation tr = translateSleigh(getLanguageID(), """
				temp:8 = 0x%x f+ 0x%x;
				""".formatted(dDot5, dDot75));
		Varnode temp = tr.program().getCode().getFirst().getOutput();
		assertTrue(temp.isUnique());
		tr.runFallthrough();
		assertEquals(1.25f, Double.longBitsToDouble(tr.getLongVnVal(temp)), 0);
	}

	@Test
	public void testReadMemMappedRegBE() throws Exception {
		Translation tr = translateSleigh(getLanguageID(), """
				* 0:8 = 0x%x:8;
				temp:8 = mmr0;
				""".formatted(LONG_CONST));
		Varnode temp = tr.program().getCode().get(1).getOutput();
		assertTrue(temp.isUnique());
		tr.runFallthrough();
		assertEquals(LONG_CONST, tr.getLongVnVal(temp));
	}

	@Test
	public void testReadMemDirectWithPartsSpanningBlock() throws Exception {
		long offset = GenConsts.BLOCK_SIZE - 2;
		Translation tr = translateSleigh(getLanguageID(), """
				temp:8 = * 0x%x:8;
				""".formatted(offset));
		tr.setLongMemVal(offset, LONG_CONST, 8);
		Varnode temp = tr.program().getCode().getFirst().getOutput();
		assertTrue(temp.isUnique());
		tr.runFallthrough();
		assertEquals(LONG_CONST, tr.getLongVnVal(temp));
	}

	@Test
	@Ignore("Undefined")
	public void testReadMemDirectWithSpanWrapSpace() throws Exception {
		long offset = -2;
		Translation tr = translateSleigh(getLanguageID(), """
				temp:8 = * 0x%x:8;
				""".formatted(offset));
		tr.setLongMemVal(offset, LONG_CONST, 8);
		Varnode temp = tr.program().getCode().getFirst().getOutput();
		assertTrue(temp.isUnique());
		tr.runFallthrough();
		assertEquals(LONG_CONST, tr.getLongVnVal(temp));
	}

	@Test
	public void testWriteMemDirectWithPartsSpanningBlock() throws Exception {
		long offset = GenConsts.BLOCK_SIZE - 2;
		Translation tr = translateSleigh(getLanguageID(), """
				local temp:8;
				* 0x%x:8 = temp;
				""".formatted(offset));
		Varnode temp = tr.program().getCode().getFirst().getInput(2);
		assertTrue(temp.isUnique());
		tr.setLongVnVal(temp, LONG_CONST);
		tr.runFallthrough();
		assertEquals(LONG_CONST, tr.getLongMemVal(offset, 8));
	}

	@Test
	@Ignore("Undefined")
	public void testWriteMemDirectWithSpanWrapSpace() throws Exception {
		long offset = -2;
		Translation tr = translateSleigh(getLanguageID(), """
				local temp:8;
				* 0x%x:8 = temp;
				""".formatted(offset));
		Varnode temp = tr.program().getCode().getFirst().getInput(2);
		assertTrue(temp.isUnique());
		tr.setLongVnVal(temp, LONG_CONST);
		tr.runFallthrough();
		assertEquals(LONG_CONST, tr.getLongMemVal(offset, 8));
	}

	@Test
	public void testReadMemIndirect() throws Exception {
		long offset = GenConsts.BLOCK_SIZE - 2;
		Translation tr = translateSleigh(getLanguageID(), """
				local temp:8;
				local addr:8;
				temp = * addr;
				""");
		Varnode temp = tr.program().getCode().getFirst().getOutput();
		Varnode addr = tr.program().getCode().getFirst().getInput(1);
		assertTrue(temp.isUnique());
		assertTrue(addr.isUnique());
		tr.setLongMemVal(offset, LONG_CONST, 8);
		tr.setLongVnVal(addr, offset);
		tr.runFallthrough();
		assertEquals(LONG_CONST, tr.getLongVnVal(temp));
	}

	@Test
	public void testWriteMemIndirect() throws Exception {
		long offset = GenConsts.BLOCK_SIZE - 2;
		Translation tr = translateSleigh(getLanguageID(), """
				local temp:8;
				local addr:8;
				* addr = temp;
				""");
		Varnode temp = tr.program().getCode().getFirst().getInput(2);
		Varnode addr = tr.program().getCode().getFirst().getInput(1);
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
		Varnode temp = tr.program().getCode().getFirst().getInput(2);
		Varnode addr = tr.program().getCode().getFirst().getInput(1);
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
		Translation tr = translateSleigh(getLanguageID(), """
				local jump:8;
				temp:8 = 0x%x;
				goto [jump];
				""".formatted(LONG_CONST));
		Varnode temp = tr.program().getCode().getFirst().getOutput();
		Varnode jump = tr.program().getCode().get(1).getInput(0);
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
	 * 
	 * @throws Exception because
	 */
	@Test
	public void testWithMissingVariable() throws Exception {
		Translation tr = translateSleigh(getLanguageID(), """
				local temp:8;
				local temp2:8;
				temp2 = 1;
				goto 0xdeadbeef;
				temp2 = temp;
				""");
		Varnode temp2 = tr.program().getCode().getFirst().getOutput();
		assertTrue(temp2.isUnique());
		tr.runFallthrough();
		assertEquals(1, tr.getLongVnVal(temp2));
	}

	@Test
	public void testMpIntOffcutLoadBE() throws Exception {
		runEquivalenceTest(translateSleigh(getLanguageID(), """
				local temp:16;
				temp[0,64] = r1;
				temp[64,64] = r2;
				temp2:14 = temp[8,112];
				r0 = zext(temp2);
				"""),
			List.of(
				new Case("only", """
						r1 = 0x1122334455667788;
						r2 = 0x99aabbccddeeff00;
						""",
					List.of(
						ev("r0", "0x0011223344556677")))));
	}

	@Test
	public void testLongOffcutLoadBE() throws Exception {
		runEquivalenceTest(translateSleigh(getLanguageID(), """
				local temp:16;
				temp[0,64] = r1;
				temp[64,64] = r2;
				r0 = temp[24,64];
				"""),
			List.of(
				new Case("only", """
						r1 = 0x1122334455667788;
						r2 = 0x99aabbccddeeff00;
						""",
					List.of(
						ev("r0", "0xeeff001122334455")))));
	}

	@Test
	public void testLongOffcutStore() throws Exception {
		runEquivalenceTest(translateSleigh(getLanguageID(), """
				local temp:16;
				temp[0,64] = r0;
				temp[64,64] = r1;
				temp[24,64] = 0xdeadbeefcafebabe;
				r0 = temp[0,64];
				r1 = temp[64,64];
				"""),
			List.of(
				new Case("only", """
						r0 = 0x1122334455667788;
						r1 = 0x99aabbccddeeff00;
						""",
					List.of(
						ev("r0", "0xefcafebabe667788"),
						ev("r1", "0x99aabbccdddeadbe")))));
	}

	@Test
	public void testCallOtherSleighDef() throws Exception {
		Translation tr = translateSleigh(getLanguageID(), """
				r0 = sleigh_userop(6:8, 2:8);
				""");
		assertTrue(tr.library().gotSleighUseropCall);
		tr.library().gotSleighUseropCall = false;
		tr.runFallthrough();
		assertFalse(tr.library().gotSleighUseropCall);
		assertEquals(14, tr.getLongRegVal("r0"));
	}

	@Test
	public void testCallOtherJavaDef() throws Exception {
		Translation tr = translateSleigh(getLanguageID(), """
				r0 = java_userop(6:8, 2:8);
				""");
		AddressFactory factory = tr.program().getLanguage().getAddressFactory();
		Register regR0 = tr.program().getLanguage().getRegister("r0");

		assertFalse(tr.library().gotJavaUseropCall);
		tr.runFallthrough();
		assertTrue(tr.library().gotJavaUseropCall);
		assertEquals(14, tr.getLongRegVal("r0"));

		int opNo = tr.program().getUseropNumber("java_userop");
		PcodeOp exp = new PcodeOp(Address.NO_ADDRESS, 0, PcodeOp.CALLOTHER, new Varnode[] {
			new Varnode(factory.getConstantAddress(opNo), 4),
			new Varnode(factory.getConstantAddress(6), 8),
			new Varnode(factory.getConstantAddress(2), 8)
		}, new Varnode(regR0.getAddress(), regR0.getNumBytes()));
		assertEquals(new PcodeOpKey(exp), new PcodeOpKey(tr.library().recordedOp));
	}

	@Test
	public void testCallOtherJavaDefNoOut() throws Exception {
		Translation tr = translateSleigh(getLanguageID(), """
				java_userop(6:8, 2:8);
				""");
		AddressFactory factory = tr.program().getLanguage().getAddressFactory();

		assertFalse(tr.library().gotJavaUseropCall);
		tr.runFallthrough();
		assertTrue(tr.library().gotJavaUseropCall);
		assertEquals(0, tr.getLongRegVal("r0"));

		int opNo = tr.program().getUseropNumber("java_userop");
		PcodeOp exp = new PcodeOp(Address.NO_ADDRESS, 0, PcodeOp.CALLOTHER, new Varnode[] {
			new Varnode(factory.getConstantAddress(opNo), 4),
			new Varnode(factory.getConstantAddress(6), 8),
			new Varnode(factory.getConstantAddress(2), 8)
		}, null);
		assertEquals(new PcodeOpKey(exp), new PcodeOpKey(tr.library().recordedOp));
	}

	@Test
	public void testCallOtherFuncJavaDef() throws Exception {
		Translation tr = translateSleigh(getLanguageID(), """
				r0 = func_userop(6:8, 2:8);
				""");
		assertFalse(tr.library().gotFuncUseropCall);
		tr.runFallthrough();
		assertTrue(tr.library().gotFuncUseropCall);
		assertEquals(14, tr.getLongRegVal("r0"));
	}

	@Test
	public void testCallOtherFuncJavaDefNoOut() throws Exception {
		Translation tr = translateSleigh(getLanguageID(), """
				func_userop(6:8, 2:8);
				""");
		assertFalse(tr.library().gotFuncUseropCall);
		tr.runFallthrough();
		assertTrue(tr.library().gotFuncUseropCall);
		assertEquals(0, tr.getLongRegVal("r0"));
	}

	@Test
	public void testCallOtherFuncJavaDefStatic() throws Exception {
		Translation tr = translateSleigh(getLanguageID(), """
				r0 = func_st_userop(6:8, 2:8);
				""");
		assertFalse(tr.library().gotFuncUseropCall);
		tr.runFallthrough();
		assertFalse(tr.library().gotFuncUseropCall);
		assertEquals(20, tr.getLongRegVal("r0"));
	}

	@Test
	public void testCallOtherFuncJavaDefMpInt() throws Exception {
		Translation tr = translateSleigh(getLanguageID(), """
				temp1:9 = zext(6:8);
				temp2:9 = zext(2:8);
				temp0:9 = func_mpUserop(temp1, temp2);
				r0 = temp0(0);
				""");
		assertFalse(tr.library().gotFuncUseropCall);
		tr.runFallthrough();
		assertTrue(tr.library().gotFuncUseropCall);
		assertEquals(0x6666666622222222L, tr.getLongRegVal("r0"));
	}

	@Test
	public void testCallOtherFuncJavaDefNoOutMpInt() throws Exception {
		Translation tr = translateSleigh(getLanguageID(), """
				temp1:9 = zext(6:8);
				temp2:9 = zext(2:8);
				func_mpUserop(temp1, temp2);
				""");
		assertFalse(tr.library().gotFuncUseropCall);
		tr.runFallthrough();
		assertTrue(tr.library().gotFuncUseropCall);
		assertEquals(0, tr.getLongRegVal("r0"));
	}

	@Test
	public void testCallOtherFuncJavaDefStaticMpInt() throws Exception {
		Translation tr = translateSleigh(getLanguageID(), """
				temp1:9 = zext(6:8);
				temp2:9 = zext(2:8);
				temp0:9 = func_st_mpUserop(temp1, temp2);
				r0 = temp0(0);
				""");
		assertFalse(tr.library().gotFuncUseropCall);
		tr.runFallthrough();
		assertFalse(tr.library().gotFuncUseropCall);
		assertEquals(0x0606060602020202L, tr.getLongRegVal("r0"));
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
	 * 
	 * @throws Exception because
	 */
	@Test
	public void testCallOtherUndef() throws Exception {
		Translation tr = translateToy(0x00400000, """
				user_one r0
				""");
		tr.runErr(SleighLinkException.class, "Sleigh userop 'pcodeop_one' is not in the library");
		assertEquals(0x00400000, tr.thread().getCounter().getOffset());
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
	 * 
	 * @throws Exception because
	 */
	@Test
	@Ignore("No examples, yet")
	public void testComputedOffsetsInRegisterSpace() throws Exception {
		TODO();
	}

	@Test
	public void testBranchOpGenInternal() throws Exception {
		runEquivalenceTest(translateSleigh(getLanguageID(), """
				r0 = 0xbeef;
				goto <skip>;
				r0 = 0xdead;
				<skip>
				"""),
			List.of(
				new Case("only", "", List.of(
					ev("r0", "0xbeef")))));
	}

	@Test
	public void testBranchOpGenExternal() throws Exception {
		runEquivalenceTest(translateSleigh(getLanguageID(), """
				r0 = 0xbeef;
				goto 0xdeadbeef;
				r0 = 0xdead;
				"""),
			List.of(
				new Case("only", "", List.of(
					ev("r0", "0xbeef")))));
	}

	@Test
	public void testCBranchOpGenInternalIntPredicate() throws Exception {
		runEquivalenceTest(translateSleigh(getLanguageID(), """
				r0 = 0xbeef;
				if (r1!=0) goto <skip>;
				r0 = 0xdead;
				<skip>
				"""),
			List.of(
				new Case("take", "r1=1;", List.of(
					ev("r0", "0xbeef"))),
				new Case("fall", "r1=0;", List.of(
					ev("r0", "0xdead")))));
	}

	@Test
	public void testCBranchOpGenExternalLongPredicate() throws Exception {
		runEquivalenceTest(translateSleigh(getLanguageID(), """
				r0 = 0xbeef;
				if (r1) goto 0xdeadbeef;
				r0 = 0xdead;
				"""),
			List.of(
				new Case("take", "r1=1;", List.of(
					ev("r0", "0xbeef"))),
				new Case("fall", "r1=0;", List.of(
					ev("r0", "0xdead")))));
	}

	@Test
	public void testCBranchOpGenExternalMpIntPredicate() throws Exception {
		runEquivalenceTest(translateSleigh(getLanguageID(), """
				r0 = 0xbeef;
				temp:9 = zext(r1);
				if (temp) goto 0xdeadbeef;
				r0 = 0xdead;
				"""),
			List.of(
				new Case("sm_take", "r1 = 1;", List.of(
					ev("r0", "0xbeef"))),
				new Case("sm_fall", "r1 = 0;", List.of(
					ev("r0", "0xdead"))),
				new Case("lg_take", "r1 = 0x8000000000000000;", List.of(
					ev("r0", "0xbeef")))));
	}

	@Test
	public void testBoolNegateOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(getLanguageID(), """
				r0 = !r1;
				r6l = !r7l;
				"""),
			List.of(
				new Case("f", """
						r1 = 0;
						r7l = 0;
						""",
					List.of(
						ev("r0", "1"),
						ev("r6", "1"))),
				new Case("t", """
						r1 = 1;
						r7l = 1;
						""",
					List.of(
						ev("r0", "0"),
						ev("r6", "0")))));
		// NOTE: Not testing cases with other bits set
	}

	@Test
	public void testBoolNegateMpIntOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(getLanguageID(), """
				temp:9 = zext(r1);
				temp = !temp;
				r0 = temp(1);
				"""),
			List.of(
				new Case("f", """
						r1 = 0;
						""",
					List.of(
						ev("r0", "0")))));
	}

	@Test
	public void testBoolAndOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(getLanguageID(), """
				r0 = r1 && r2;
				r3 = r4 && r5l;
				r6l = r7l && r8;
				r9l = r10l && r11l;
				"""),
			List.of(
				new Case("ff", """
						r1  =0; r2  =0;
						r4  =0; r5l =0;
						r7l =0; r8  =0;
						r10l=0; r11l=0;
						""",
					List.of(
						ev("r0", "0"),
						ev("r3", "0"),
						ev("r6", "0"),
						ev("r9", "0"))),
				new Case("ft", """
						r1  =0; r2  =1;
						r4  =0; r5l =1;
						r7l =0; r8  =1;
						r10l=0; r11l=1;
						""",
					List.of(
						ev("r0", "0"),
						ev("r3", "0"),
						ev("r6", "0"),
						ev("r9", "0"))),
				new Case("tf", """
						r1  =1; r2  =0;
						r4  =1; r5l =0;
						r7l =1; r8  =0;
						r10l=1; r11l=0;
						""",
					List.of(
						ev("r0", "0"),
						ev("r3", "0"),
						ev("r6", "0"),
						ev("r9", "0"))),
				new Case("tt", """
						r1  =1; r2  =1;
						r4  =1; r5l =1;
						r7l =1; r8  =1;
						r10l=1; r11l=1;
						""",
					List.of(
						ev("r0", "1"),
						ev("r3", "1"),
						ev("r6", "1"),
						ev("r9", "1")))));
		// NOTE: Not testing cases with other bits set
	}

	@Test
	public void testBoolAndMpIntOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(getLanguageID(), """
				temp1:9 = zext(r1);
				temp2:9 = zext(r2);
				temp0:9 = temp1 && temp2;
				r0 = temp0(0);
				r3 = temp0(1);
				"""),
			List.of(
				new Case("ff", """
						r1 = 0; r2 = 0;
						""",
					List.of(
						ev("r0", "0"),
						ev("r3", "0"))),
				new Case("ft", """
						r1  =0; r2 = 1;
						""",
					List.of(
						ev("r0", "0"),
						ev("r3", "0"))),
				new Case("tf", """
						r1 = 1; r2 = 0;
						""",
					List.of(
						ev("r0", "0"),
						ev("r3", "0"))),
				new Case("tt", """
						r1 = 1; r2 = 1;
						""",
					List.of(
						ev("r0", "1"),
						ev("r3", "0")))));
		// NOTE: Not testing cases with other bits set
	}

	@Test
	public void testBoolOrOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(getLanguageID(), """
				r0 = r1 || r2;
				r3 = r4 || r5l;
				r6l = r7l || r8;
				r9l = r10l || r11l;
				"""),
			List.of(
				new Case("ff", """
						r1  =0; r2  =0;
						r4  =0; r5l =0;
						r7l =0; r8  =0;
						r10l=0; r11l=0;
						""",
					List.of(
						ev("r0", "0"),
						ev("r3", "0"),
						ev("r6", "0"),
						ev("r9", "0"))),
				new Case("ft", """
						r1  =0; r2  =1;
						r4  =0; r5l =1;
						r7l =0; r8  =1;
						r10l=0; r11l=1;
						""",
					List.of(
						ev("r0", "1"),
						ev("r3", "1"),
						ev("r6", "1"),
						ev("r9", "1"))),
				new Case("tf", """
						r1  =1; r2  =0;
						r4  =1; r5l =0;
						r7l =1; r8  =0;
						r10l=1; r11l=0;
						""",
					List.of(
						ev("r0", "1"),
						ev("r3", "1"),
						ev("r6", "1"),
						ev("r9", "1"))),
				new Case("tt", """
						r1  =1; r2  =1;
						r4  =1; r5l =1;
						r7l =1; r8  =1;
						r10l=1; r11l=1;
						""",
					List.of(
						ev("r0", "1"),
						ev("r3", "1"),
						ev("r6", "1"),
						ev("r9", "1")))));
		// NOTE: Not testing cases with other bits set
	}

	@Test
	public void testBoolOrMpIntOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(getLanguageID(), """
				temp1:9 = zext(r1);
				temp2:9 = zext(r2);
				temp0:9 = temp1 || temp2;
				r0 = temp0(0);
				r3 = temp0(1);
				"""),
			List.of(
				new Case("ff", """
						r1  =0; r2  =0;
						""",
					List.of(
						ev("r0", "0"),
						ev("r3", "0"))),
				new Case("ft", """
						r1  =0; r2  =1;
						""",
					List.of(
						ev("r0", "1"),
						ev("r3", "0"))),
				new Case("tf", """
						r1  =1; r2  =0;
						""",
					List.of(
						ev("r0", "1"),
						ev("r3", "0"))),
				new Case("tt", """
						r1  =1; r2  =1;
						""",
					List.of(
						ev("r0", "1"),
						ev("r3", "0")))));
		// NOTE: Not testing cases with other bits set
	}

	@Test
	public void testBoolXorOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(getLanguageID(), """
				r0 = r1 ^^ r2;
				r3 = r4 ^^ r5l;
				r6l = r7l ^^ r8;
				r9l = r10l ^^ r11l;
				"""),
			List.of(
				new Case("ff", """
						r1  =0; r2  =0;
						r4  =0; r5l =0;
						r7l =0; r8  =0;
						r10l=0; r11l=0;
						""",
					List.of(
						ev("r0", "0"),
						ev("r3", "0"),
						ev("r6", "0"),
						ev("r9", "0"))),
				new Case("ft", """
						r1  =0; r2  =1;
						r4  =0; r5l =1;
						r7l =0; r8  =1;
						r10l=0; r11l=1;
						""",
					List.of(
						ev("r0", "1"),
						ev("r3", "1"),
						ev("r6", "1"),
						ev("r9", "1"))),
				new Case("tf", """
						r1  =1; r2  =0;
						r4  =1; r5l =0;
						r7l =1; r8  =0;
						r10l=1; r11l=0;
						""",
					List.of(
						ev("r0", "1"),
						ev("r3", "1"),
						ev("r6", "1"),
						ev("r9", "1"))),
				new Case("tt", """
						r1  =1; r2  =1;
						r4  =1; r5l =1;
						r7l =1; r8  =1;
						r10l=1; r11l=1;
						""",
					List.of(
						ev("r0", "0"),
						ev("r3", "0"),
						ev("r6", "0"),
						ev("r9", "0")))));
		// NOTE: Not testing cases with other bits set
	}

	@Test
	public void testBoolXorMpIntOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(getLanguageID(), """
				temp1:9 = zext(r1);
				temp2:9 = zext(r2);
				temp0:9 = temp1 ^^ temp2;
				r0 = temp0(0);
				r3 = temp0(1);
				"""),
			List.of(
				new Case("ff", """
						r1  =0; r2  =0;
						""",
					List.of(
						ev("r0", "0"),
						ev("r3", "0"))),
				new Case("ft", """
						r1  =0; r2  =1;
						""",
					List.of(
						ev("r0", "1"),
						ev("r3", "0"))),
				new Case("tf", """
						r1  =1; r2  =0;
						""",
					List.of(
						ev("r0", "1"),
						ev("r3", "0"))),
				new Case("tt", """
						r1  =1; r2  =1;
						""",
					List.of(
						ev("r0", "0"),
						ev("r3", "0")))));
		// NOTE: Not testing cases with other bits set
	}

	@Test
	public void testFloatAbsOpGen() throws Exception {
		long d0dot5 = Double.doubleToLongBits(0.5);
		long dn0dot5 = Double.doubleToLongBits(-0.5);
		int f0dot5 = Float.floatToIntBits(0.5f);
		int fn0dot5 = Float.floatToIntBits(-0.5f);
		runEquivalenceTest(translateSleigh(getLanguageID(), """
				r0 = abs(r1);
				r6l = abs(r7l);
				"""),
			List.of(
				new Case("p", """
						r1  =0x%x;
						r7l =0x%x;
						""".formatted(d0dot5, f0dot5),
					List.of(
						ev("r0", 0.5d),
						ev("r6", 0.5f))),
				new Case("n", """
						r1  =0x%x;
						r7l =0x%x;
						""".formatted(dn0dot5, fn0dot5),
					List.of(
						ev("r0", 0.5d),
						ev("r6", 0.5f)))));
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
	 * 
	 * @throws Exception because
	 */
	@Test
	public void testFloatSqrtOpGen() throws Exception {
		long d0dot5 = Double.doubleToLongBits(0.5);
		long dn0dot5 = Double.doubleToLongBits(-0.5);
		int f0dot5 = Float.floatToIntBits(0.5f);
		int fn0dot5 = Float.floatToIntBits(-0.5f);
		runEquivalenceTest(translateSleigh(getLanguageID(), """
				r0 = sqrt(r1);
				r6l = sqrt(r7l);
				"""),
			List.of(
				new Case("p", """
						r1  =0x%x;
						r7l =0x%x;
						""".formatted(d0dot5, f0dot5),
					List.of(
						ev("r0", Math.sqrt(0.5)),
						ev("r6", (float) Math.sqrt(0.5)))),
				new Case("n", """
						r1  =0x%x;
						r7l =0x%x;
						""".formatted(dn0dot5, fn0dot5),
					List.of(
						ev("r0", nNaN_D),
						ev("r6l", nNaN_F)))));
	}

	@Test
	public void testFloatCeilOpGen() throws Exception {
		long d0dot5 = Double.doubleToLongBits(0.5);
		long dn0dot5 = Double.doubleToLongBits(-0.5);
		int f0dot5 = Float.floatToIntBits(0.5f);
		int fn0dot5 = Float.floatToIntBits(-0.5f);
		runEquivalenceTest(translateSleigh(getLanguageID(), """
				r0 = ceil(r1);
				r6l = ceil(r7l);
				"""),
			List.of(
				new Case("p", """
						r1  =0x%x;
						r7l =0x%x;
						""".formatted(d0dot5, f0dot5),
					List.of(
						ev("r0", 1.0d),
						ev("r6", 1.0f))),
				new Case("n", """
						r1  =0x%x;
						r7l =0x%x;
						""".formatted(dn0dot5, fn0dot5),
					List.of(
						ev("r0", -0.0d),
						ev("r6", -0.0f)))));
	}

	@Test
	public void testFloatFloorOpGen() throws Exception {
		long d0dot5 = Double.doubleToLongBits(0.5);
		long dn0dot5 = Double.doubleToLongBits(-0.5);
		int f0dot5 = Float.floatToIntBits(0.5f);
		int fn0dot5 = Float.floatToIntBits(-0.5f);
		runEquivalenceTest(translateSleigh(getLanguageID(), """
				r0 = floor(r1);
				r6l = floor(r7l);
				"""),
			List.of(
				new Case("p", """
						r1  =0x%x;
						r7l =0x%x;
						""".formatted(d0dot5, f0dot5),
					List.of(
						ev("r0", 0.0d),
						ev("r6", 0.0f))),
				new Case("n", """
						r1  =0x%x;
						r7l =0x%x;
						""".formatted(dn0dot5, fn0dot5),
					List.of(
						ev("r0", -1.0d),
						ev("r6", -1.0f)))));
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
		runEquivalenceTest(translateSleigh(getLanguageID(), """
				r0 = round(r1);
				r6l = round(r7l);
				"""),
			List.of(
				new Case("+0.25", """
						r1  =0x%x;
						r7l =0x%x;
						""".formatted(d0dot25, f0dot25),
					List.of(
						ev("r0", 0.0d),
						ev("r6", 0.0f))),
				new Case("-0.25", """
						r1  =0x%x;
						r7l =0x%x;
						""".formatted(dn0dot25, fn0dot25),
					List.of(
						ev("r0", 0.0d),
						ev("r6", 0.0f))),
				new Case("+0.5", """
						r1  =0x%x;
						r7l =0x%x;
						""".formatted(d0dot5, f0dot5),
					List.of(
						ev("r0", 1.0d),
						ev("r6", 1.0f))),
				new Case("-0.5", """
						r1  =0x%x;
						r7l =0x%x;
						""".formatted(dn0dot5, fn0dot5),
					List.of(
						ev("r0", 0.0d),
						ev("r6", 0.0f))),
				new Case("+0.75", """
						r1  =0x%x;
						r7l =0x%x;
						""".formatted(d0dot75, f0dot75),
					List.of(
						ev("r0", 1.0d),
						ev("r6", 1.0f))),
				new Case("-0.75", """
						r1  =0x%x;
						r7l =0x%x;
						""".formatted(dn0dot75, fn0dot75),
					List.of(
						ev("r0", -1.0d),
						ev("r6", -1.0f))),
				new Case("+1.0", """
						r1  =0x%x;
						r7l =0x%x;
						""".formatted(d1dot0, f1dot0),
					List.of(
						ev("r0", 1.0d),
						ev("r6", 1.0f))),
				new Case("-1.0", """
						r1  =0x%x;
						r7l =0x%x;
						""".formatted(dn1dot0, fn1dot0),
					List.of(
						ev("r0", -1.0d),
						ev("r6", -1.0f)))));
	}

	@Test
	public void testFloat2FloatOpGen() throws Exception {
		long d0dot5 = Double.doubleToLongBits(0.5);
		int f0dot5 = Float.floatToIntBits(0.5f);
		runEquivalenceTest(translateSleigh(getLanguageID(), """
				r0 = float2float(r1l);
				r6l = float2float(r7);
				"""),
			List.of(
				new Case("only", """
						r1l =0x%x;
						r7  =0x%x;
						""".formatted(f0dot5, d0dot5),
					List.of(
						ev("r0", 0.5d),
						ev("r6", 0.5f)))));
	}

	@Test
	public void testFloatInt2FloatOpGen() throws Exception {
		/**
		 * The size swap is not necessary, but test anyway.
		 */
		runEquivalenceTest(translateSleigh(getLanguageID(), """
				r0 = int2float(r1l);
				r6l = int2float(r7);
				"""),
			List.of(
				new Case("only", """
						r1l =1;
						r7  =2;
						""",
					List.of(
						ev("r0", 1.0d),
						ev("r6", 2.0f)))));
	}

	@Test
	public void testFloatTruncOpGen() throws Exception {
		long d1dot0 = Double.doubleToLongBits(1.0);
		long d0dot5 = Double.doubleToLongBits(0.5);
		long dn0dot5 = Double.doubleToLongBits(-0.5);
		int f1dot0 = Float.floatToIntBits(1.0f);
		int f0dot5 = Float.floatToIntBits(0.5f);
		int fn0dot5 = Float.floatToIntBits(-0.5f);
		runEquivalenceTest(translateSleigh(getLanguageID(), """
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
					List.of(
						ev("r0", "1"),
						ev("r3", "1"),
						ev("r6", "1"),
						ev("r9", "1"))),
				new Case("+0.5", """
						r1  =0x%x;
						r4l =0x%x;
						r7  =0x%x;
						r10l=0x%x;
						""".formatted(d0dot5, f0dot5, d0dot5, f0dot5),
					List.of(
						ev("r0", "0"),
						ev("r3", "0"),
						ev("r6", "0"),
						ev("r9", "0"))),
				new Case("-0.5", """
						r1  =0x%x;
						r4l =0x%x;
						r7  =0x%x;
						r10l=0x%x;
						""".formatted(dn0dot5, dn0dot5, dn0dot5, fn0dot5),
					List.of(
						ev("r0", "0"),
						ev("r3", "0"),
						ev("r6", "0"),
						ev("r9", "0")))));
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
		runEquivalenceTest(translateSleigh(getLanguageID(), """
				r0 = nan(r1l);
				r6l = nan(r7);
				"""),
			List.of(
				new Case("num", """
						r1l =0x%x;
						r7  =0x%x;
						""".formatted(f0dot5, d0dot5),
					List.of(
						ev("r0", "0"),
						ev("r6", "0"))),
				new Case("nan", """
						r1l =0x%x;
						r7  =0x%x;
						""".formatted(fNaN, dNaN),
					List.of(
						ev("r0", "1"),
						ev("r6", "1")))));
	}

	@Test
	public void testFloatNegOpGen() throws Exception {
		long d0dot5 = Double.doubleToLongBits(0.5);
		int f0dot5 = Float.floatToIntBits(0.5f);
		runEquivalenceTest(translateSleigh(getLanguageID(), """
				r0 = f-r1;
				r6l = f-r7l;
				"""),
			List.of(
				new Case("num", """
						r1 =0x%x;
						r7l  =0x%x;
						""".formatted(d0dot5, f0dot5),
					List.of(
						ev("r0", -0.5d),
						ev("r6l", -0.5f)))));
	}

	@Test
	public void testFloatAddOpGen() throws Exception {
		long d0dot5 = Double.doubleToLongBits(0.5);
		int f0dot5 = Float.floatToIntBits(0.5f);
		long d0dot25 = Double.doubleToLongBits(0.25);
		int f0dot25 = Float.floatToIntBits(0.25f);
		runEquivalenceTest(translateSleigh(getLanguageID(), """
				r0 = r1 f+ r2;
				r9l = r10l f+ r11l;
				"""),
			List.of(
				new Case("only", """
						r1  =0x%x; r2  =0x%x;
						r10l=0x%x; r11l=0x%x;
						""".formatted(d0dot5, d0dot25, f0dot5, f0dot25),
					List.of(
						ev("r0", 0.75d),
						ev("r9", 0.75f)))));
	}

	@Test
	public void testFloatSubOpGen() throws Exception {
		long d0dot5 = Double.doubleToLongBits(0.5);
		int f0dot5 = Float.floatToIntBits(0.5f);
		long d0dot25 = Double.doubleToLongBits(0.25);
		int f0dot25 = Float.floatToIntBits(0.25f);
		runEquivalenceTest(translateSleigh(getLanguageID(), """
				r0 = r1 f- r2;
				r9l = r10l f- r11l;
				"""),
			List.of(
				new Case("only", """
						r1  =0x%x; r2  =0x%x;
						r10l=0x%x; r11l=0x%x;
						""".formatted(d0dot5, d0dot25, f0dot5, f0dot25),
					List.of(
						ev("r0", 0.25d),
						ev("r9", 0.25f)))));
	}

	@Test
	public void testFloatMultOpGen() throws Exception {
		long d0dot5 = Double.doubleToLongBits(0.5);
		int f0dot5 = Float.floatToIntBits(0.5f);
		long d0dot25 = Double.doubleToLongBits(0.25);
		int f0dot25 = Float.floatToIntBits(0.25f);
		runEquivalenceTest(translateSleigh(getLanguageID(), """
				r0 = r1 f* r2;
				r9l = r10l f* r11l;
				"""),
			List.of(
				new Case("only", """
						r1  =0x%x; r2  =0x%x;
						r10l=0x%x; r11l=0x%x;
						""".formatted(d0dot5, d0dot25, f0dot5, f0dot25),
					List.of(
						ev("r0", 0.125d),
						ev("r9", 0.125f)))));
	}

	@Test
	public void testFloatDivOpGen() throws Exception {
		long d0dot5 = Double.doubleToLongBits(0.5);
		int f0dot5 = Float.floatToIntBits(0.5f);
		long d0dot25 = Double.doubleToLongBits(0.25);
		int f0dot25 = Float.floatToIntBits(0.25f);
		runEquivalenceTest(translateSleigh(getLanguageID(), """
				r0 = r1 f/ r2;
				r9l = r10l f/ r11l;
				"""),
			List.of(
				new Case("only", """
						r1  =0x%x; r2  =0x%x;
						r10l=0x%x; r11l=0x%x;
						""".formatted(d0dot5, d0dot25, f0dot5, f0dot25),
					List.of(
						ev("r0", 2.0d),
						ev("r9", 2.0f)))));
	}

	@Test
	public void testFloatEqualOpGen() throws Exception {
		long d0dot5 = Double.doubleToLongBits(0.5);
		int f0dot5 = Float.floatToIntBits(0.5f);
		long d0dot25 = Double.doubleToLongBits(0.25);
		int f0dot25 = Float.floatToIntBits(0.25f);
		runEquivalenceTest(translateSleigh(getLanguageID(), """
				r0 = r1 f== r2;
				r9l = r10l f== r11l;
				"""),
			List.of(
				new Case("lt", """
						r1  =0x%x; r2  =0x%x;
						r10l=0x%x; r11l=0x%x;
						""".formatted(d0dot25, d0dot5, f0dot25, f0dot5),
					List.of(
						ev("r0", "0"),
						ev("r9", "0"))),
				new Case("eq", """
						r1  =0x%x; r2  =0x%x;
						r10l=0x%x; r11l=0x%x;
						""".formatted(d0dot5, d0dot5, f0dot5, f0dot5),
					List.of(
						ev("r0", "1"),
						ev("r9", "1"))),
				new Case("gt", """
						r1  =0x%x; r2  =0x%x;
						r10l=0x%x; r11l=0x%x;
						""".formatted(d0dot5, d0dot25, f0dot5, f0dot25),
					List.of(
						ev("r0", "0"),
						ev("r9", "0")))));
	}

	@Test
	public void testFloatNotEqualOpGen() throws Exception {
		long d0dot5 = Double.doubleToLongBits(0.5);
		int f0dot5 = Float.floatToIntBits(0.5f);
		long d0dot25 = Double.doubleToLongBits(0.25);
		int f0dot25 = Float.floatToIntBits(0.25f);
		runEquivalenceTest(translateSleigh(getLanguageID(), """
				r0 = r1 f!= r2;
				r9l = r10l f!= r11l;
				"""),
			List.of(
				new Case("lt", """
						r1  =0x%x; r2  =0x%x;
						r10l=0x%x; r11l=0x%x;
						""".formatted(d0dot25, d0dot5, f0dot25, f0dot5),
					List.of(
						ev("r0", "1"),
						ev("r9", "1"))),
				new Case("eq", """
						r1  =0x%x; r2  =0x%x;
						r10l=0x%x; r11l=0x%x;
						""".formatted(d0dot5, d0dot5, f0dot5, f0dot5),
					List.of(
						ev("r0", "0"),
						ev("r9", "0"))),
				new Case("gt", """
						r1  =0x%x; r2  =0x%x;
						r10l=0x%x; r11l=0x%x;
						""".formatted(d0dot5, d0dot25, f0dot5, f0dot25),
					List.of(
						ev("r0", "1"),
						ev("r9", "1")))));
	}

	@Test
	public void testFloatLessEqualOpGen() throws Exception {
		long d0dot5 = Double.doubleToLongBits(0.5);
		int f0dot5 = Float.floatToIntBits(0.5f);
		long d0dot25 = Double.doubleToLongBits(0.25);
		int f0dot25 = Float.floatToIntBits(0.25f);
		runEquivalenceTest(translateSleigh(getLanguageID(), """
				r0 = r1 f<= r2;
				r9l = r10l f<= r11l;
				"""),
			List.of(
				new Case("lt", """
						r1  =0x%x; r2  =0x%x;
						r10l=0x%x; r11l=0x%x;
						""".formatted(d0dot25, d0dot5, f0dot25, f0dot5),
					List.of(
						ev("r0", "1"),
						ev("r9", "1"))),
				new Case("eq", """
						r1  =0x%x; r2  =0x%x;
						r10l=0x%x; r11l=0x%x;
						""".formatted(d0dot5, d0dot5, f0dot5, f0dot5),
					List.of(
						ev("r0", "1"),
						ev("r9", "1"))),
				new Case("gt", """
						r1  =0x%x; r2  =0x%x;
						r10l=0x%x; r11l=0x%x;
						""".formatted(d0dot5, d0dot25, f0dot5, f0dot25),
					List.of(
						ev("r0", "0"),
						ev("r9", "0")))));
	}

	@Test
	public void testFloatLessOpGen() throws Exception {
		long d0dot5 = Double.doubleToLongBits(0.5);
		int f0dot5 = Float.floatToIntBits(0.5f);
		long d0dot25 = Double.doubleToLongBits(0.25);
		int f0dot25 = Float.floatToIntBits(0.25f);
		runEquivalenceTest(translateSleigh(getLanguageID(), """
				r0 = r1 f< r2;
				r9l = r10l f< r11l;
				"""),
			List.of(
				new Case("lt", """
						r1  =0x%x; r2  =0x%x;
						r10l=0x%x; r11l=0x%x;
						""".formatted(d0dot25, d0dot5, f0dot25, f0dot5),
					List.of(
						ev("r0", "1"),
						ev("r9", "1"))),
				new Case("eq", """
						r1  =0x%x; r2  =0x%x;
						r10l=0x%x; r11l=0x%x;
						""".formatted(d0dot5, d0dot5, f0dot5, f0dot5),
					List.of(
						ev("r0", "0"),
						ev("r9", "0"))),
				new Case("gt", """
						r1  =0x%x; r2  =0x%x;
						r10l=0x%x; r11l=0x%x;
						""".formatted(d0dot5, d0dot25, f0dot5, f0dot25),
					List.of(
						ev("r0", "0"),
						ev("r9", "0")))));
	}

	@Test
	public void testInt2CompOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(getLanguageID(), """
				r0  = -r1;
				r6l = -r7l;
				"""),
			List.of(
				new Case("pos", """
						r1  =4;
						r7l =4;
						""",
					List.of(
						ev("r0", "-4"),
						ev("r6l", "-4"))),
				new Case("neg", """
						r1  =-4;
						r7l =-4;
						""",
					List.of(
						ev("r0", "4"),
						ev("r6l", "4")))));
	}

	@Test
	public void testInt2CompMpIntOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(getLanguageID(), """
				temp1:9 = sext(r1);
				temp0:9 = -temp1;
				r0 = temp0(0);
				r2 = temp0(1);
				"""),
			List.of(
				new Case("pos", """
						r1 = 4;
						""",
					List.of(
						ev("r0", "-4"),
						ev("r2", "-1"))),
				new Case("neg", """
						r1 =-4;
						""",
					List.of(
						ev("r0", "4"),
						ev("r2", "0")))));
	}

	@Test
	public void testIntNegateOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(getLanguageID(), """
				r0  = ~r1;
				r6l = ~r7l;
				"""),
			List.of(
				new Case("pos", """
						r1  =4;
						r7l =4;
						""",
					List.of(
						ev("r0", "-5"),
						ev("r6l", "-5"))),
				new Case("neg", """
						r1  =-4;
						r7l =-4;
						""",
					List.of(
						ev("r0", "3"),
						ev("r6l", "3")))));
	}

	@Test
	public void testIntNegateMpIntOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(getLanguageID(), """
				temp1:9 = sext(r1);
				temp0:9 = ~temp1;
				r0 = temp0(0);
				r2 = temp0(1);
				"""),
			List.of(
				new Case("pos", """
						r1 = 4;
						""",
					List.of(
						ev("r0", "-5"),
						ev("r2", "-1"))),
				new Case("neg", """
						r1 = -4;
						""",
					List.of(
						ev("r0", "3"),
						ev("r2", "0")))));
	}

	@Test
	public void testIntSExtOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(getLanguageID(), """
				r0 = sext(r1l);
				"""),
			List.of(
				new Case("pos", """
						r1l =4;
						""",
					List.of(
						ev("r0", "4"))),
				new Case("neg", """
						r1l =-4;
						""",
					List.of(
						ev("r0", "-4")))));
	}

	@Test
	public void testIntSExtMpIntOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(getLanguageID(), """
				temp0:9 = sext(r1l);
				r0 = temp0(0);
				r2 = temp0(1);
				"""),
			List.of(
				new Case("pos", """
						r1l =4;
						""",
					List.of(
						ev("r0", "4"),
						ev("r2", "0"))),
				new Case("neg", """
						r1l =-4;
						""",
					List.of(
						ev("r0", "-4"),
						ev("r2", "-1")))));
	}

	@Test
	public void testIntZExtOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(getLanguageID(), """
				r0 = zext(r1l);
				"""),
			List.of(
				new Case("pos", """
						r1l =4;
						""",
					List.of(
						ev("r0", "4"))),
				new Case("neg", """
						r1l =-4;
						""",
					List.of(
						ev("r0", "0xfffffffc")))));
	}

	@Test
	public void testIntZExtMpIntOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(getLanguageID(), """
				temp0:9 = zext(r1l);
				r0 = temp0(0);
				r2 = temp0(1);
				"""),
			List.of(
				new Case("pos", """
						r1l =4;
						""",
					List.of(
						ev("r0", "4"),
						ev("r2", "0"))),
				new Case("neg", """
						r1l =-4;
						""",
					List.of(
						ev("r0", "0xfffffffc"),
						ev("r2", "0xffffff")))));
	}

	@Test
	public void testLzCountOpGen() throws Exception {
		// Test size change, even though not necessary here
		runEquivalenceTest(translateSleigh(getLanguageID(), """
				r0 = lzcount(r1l);

				temp:3 = r3(0);
				r2 = lzcount(temp);
				"""),
			List.of(
				new Case("pos", """
						r1l =4;
						r3  =4;
						""",
					List.of(
						ev("r0", "29"),
						ev("r2", "21"))),
				new Case("neg", """
						r1l =-4;
						r3  =-4;
						""",
					List.of(
						ev("r0", "0"),
						ev("r2", "0")))));
	}

	@Test
	public void testLzCountMpIntOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(getLanguageID(), """
				temp1s:9 = sext(r1);
				temp1z:9 = zext(r1);
				r0 = lzcount(temp1s);
				r2 = lzcount(temp1z);
				"""),
			List.of(
				new Case("pos", """
						r1 =4;
						""",
					List.of(
						ev("r0", "69"),
						ev("r2", "69"))),
				new Case("neg", """
						r1 =-4;
						""",
					List.of(
						ev("r0", "0"),
						ev("r2", "8")))));
	}

	@Test
	public void testPopCountOpGen() throws Exception {
		// Test size change, even though not necessary here
		runEquivalenceTest(translateSleigh(getLanguageID(), """
				r0 = popcount(r1l);
				"""),
			List.of(
				new Case("pos", """
						r1l =4;
						""",
					List.of(
						ev("r0", "1"))),
				new Case("neg", """
						r1l =-4;
						""",
					List.of(
						ev("r0", "30")))));
	}

	@Test
	public void testPopCountMpIntOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(getLanguageID(), """
				temp1s:9 = sext(r1);
				temp1z:9 = zext(r1);
				r0 = popcount(temp1s);
				r2 = popcount(temp1z);
				"""),
			List.of(
				new Case("pos", """
						r1 =4;
						""",
					List.of(
						ev("r0", "1"),
						ev("r2", "1"))),
				new Case("neg", """
						r1 =-4;
						""",
					List.of(
						ev("r0", "70"),
						ev("r2", "62")))));
	}

	@Test
	public void testSubPieceOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(getLanguageID(), """
				r0l = r1(3);
				r3 = r4l(3);
				"""),
			List.of(
				new Case("only", """
						r1 =0x%x;
						r4l=0x12345678;
						""".formatted(LONG_CONST),
					List.of(
						ev("r0l", "0xadbeefca"),
						ev("r3", "0x12")))));
	}

	@Test
	public void testSubPieceMpIntConst9_0() throws Exception {
		runEquivalenceTest(translateSleigh(getLanguageID(), """
				temp0:9 = 0x1122334455667788;
				r0 = temp0(0);
				"""),
			List.of(
				new Case("only", "", List.of(
					ev("r0", "0x1122334455667788")))));
	}

	@Test
	public void testSubPieceMpIntConst9_1() throws Exception {
		runEquivalenceTest(translateSleigh(getLanguageID(), """
				temp0:9 = 0x1122334455667788;
				r0 = temp0(1);
				"""),
			List.of(
				new Case("only", "", List.of(
					ev("r0", "0x11223344556677")))));
	}

	@Test
	public void testSubPieceMpIntConst10_0() throws Exception {
		runEquivalenceTest(translateSleigh(getLanguageID(), """
				temp0:10 = 0x1122334455667788;
				r0 = temp0(0);
				"""),
			List.of(
				new Case("only", "", List.of(
					ev("r0", "0x1122334455667788")))));
	}

	@Test
	public void testSubPieceMpIntConst10_1() throws Exception {
		runEquivalenceTest(translateSleigh(getLanguageID(), """
				temp0:10 = 0x1122334455667788;
				r0 = temp0(1);
				"""),
			List.of(
				new Case("only", "", List.of(
					ev("r0", "0x11223344556677")))));
	}

	@Test
	public void testSubPieceMpIntConst10_2() throws Exception {
		runEquivalenceTest(translateSleigh(getLanguageID(), """
				temp0:10 = 0x1122334455667788;
				r0 = temp0(2);
				"""),
			List.of(
				new Case("only", "", List.of(
					ev("r0", "0x112233445566")))));
	}

	@Test
	public void testSubPieceMpIntConst11_0() throws Exception {
		runEquivalenceTest(translateSleigh(getLanguageID(), """
				temp0:11 = 0x1122334455667788;
				r0 = temp0(0);
				"""),
			List.of(
				new Case("only", "", List.of(
					ev("r0", "0x1122334455667788")))));
	}

	@Test
	public void testSubPieceMpIntConst11_1() throws Exception {
		runEquivalenceTest(translateSleigh(getLanguageID(), """
				temp0:11 = 0x1122334455667788;
				r0 = temp0(1);
				"""),
			List.of(
				new Case("only", "", List.of(
					ev("r0", "0x11223344556677")))));
	}

	@Test
	public void testSubPieceMpIntConst11_2() throws Exception {
		runEquivalenceTest(translateSleigh(getLanguageID(), """
				temp0:11 = 0x1122334455667788;
				r0 = temp0(2);
				"""),
			List.of(
				new Case("only", "", List.of(
					ev("r0", "0x112233445566")))));
	}

	@Test
	public void testSubPieceMpIntConst11_3() throws Exception {
		runEquivalenceTest(translateSleigh(getLanguageID(), """
				temp0:11 = 0x1122334455667788;
				r0 = temp0(3);
				"""),
			List.of(
				new Case("only", "", List.of(
					ev("r0", "0x1122334455")))));
	}

	@Test
	public void testSubPieceMpIntConst12_0() throws Exception {
		runEquivalenceTest(translateSleigh(getLanguageID(), """
				temp0:12 = 0x1122334455667788;
				r0 = temp0(0);
				"""),
			List.of(
				new Case("only", "", List.of(
					ev("r0", "0x1122334455667788")))));
	}

	@Test
	public void testSubPieceMpIntConst12_1() throws Exception {
		runEquivalenceTest(translateSleigh(getLanguageID(), """
				temp0:12 = 0x1122334455667788;
				r0 = temp0(1);
				"""),
			List.of(
				new Case("only", "", List.of(
					ev("r0", "0x11223344556677")))));
	}

	@Test
	public void testSubPieceMpIntConst12_2() throws Exception {
		runEquivalenceTest(translateSleigh(getLanguageID(), """
				temp0:12 = 0x1122334455667788;
				r0 = temp0(2);
				"""),
			List.of(
				new Case("only", "", List.of(
					ev("r0", "0x112233445566")))));
	}

	@Test
	public void testSubPieceMpIntConst12_3() throws Exception {
		runEquivalenceTest(translateSleigh(getLanguageID(), """
				temp0:12 = 0x1122334455667788;
				r0 = temp0(3);
				"""),
			List.of(
				new Case("only", "", List.of(
					ev("r0", "0x1122334455")))));
	}

	@Test
	public void testSubPieceMpIntConst12_4() throws Exception {
		runEquivalenceTest(translateSleigh(getLanguageID(), """
				temp0:12 = 0x1122334455667788;
				r0 = temp0(4);
				"""),
			List.of(
				new Case("only", "", List.of(
					ev("r0", "0x11223344")))));
	}

	@Test
	public void testIntAddOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(getLanguageID(), """
				r0 = r1 + r2;
				r9l = r10l + r11l;
				"""),
			List.of(
				new Case("only", """
						r1  =2; r2  =2;
						r10l=2; r11l=2;
						""",
					List.of(
						ev("r0", "4"),
						ev("r9", "4")))));
	}

	protected void runTestIntAddMpIntOpGen(Endian endian) throws Exception {
		/**
		 * NOTE: We copy temp1 and temp2 back into r1 and r2 and assert their values, to ensure the
		 * input operands remain unmodified.
		 */
		runEquivalenceTest(translateSleigh(endian.isBigEndian() ? getLanguageID() : ID_TOYLE64, """
				temp1:9 = zext(r1);
				temp2:9 = zext(r2);
				temp0:9 = temp1 + temp2;
				r0 = temp0(0);
				r1 = temp1(0);
				r2 = temp2(0);
				"""),
			List.of(
				new Case("small", """
						r1 = 2; r2 = 2;
						""",
					List.of(
						ev("r0", "4"), ev("r1", "2"), ev("r2", "2"))),
				new Case("large", """
						r1 = 0x8111111122222222; r2 = 0x8765432112345678;
						""",
					List.of(
						ev("r0", "0x087654323456789a"),
						ev("r1", "0x8111111122222222"),
						ev("r2", "0x8765432112345678")))));
	}

	@Test
	public void testIntAddMpIntOpGenBE() throws Exception {
		runTestIntAddMpIntOpGen(Endian.BIG);
	}

	@Test
	public void testIntAddMpIntOpGenLE() throws Exception {
		runTestIntAddMpIntOpGen(Endian.LITTLE);
	}

	@Test
	public void testIntSubOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(getLanguageID(), """
				r0 = r1 - r2;
				r9l = r10l - r11l;
				"""),
			List.of(
				new Case("only", """
						r1  =2; r2  =2;
						r10l=2; r11l=2;
						""",
					List.of(
						ev("r0", "0"),
						ev("r9", "0")))));
	}

	@Test
	public void testIntSubMpIntOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(getLanguageID(), """
				temp1:9 = zext(r1);
				temp2:9 = zext(r2);
				temp0:9 = temp1 - temp2;
				r0 = temp0(0);
				r3 = temp0(1);
				"""),
			List.of(
				new Case("small", """
						r1 = 2; r2 = 2;
						""",
					List.of(
						ev("r0", "0"),
						ev("r3", "0"))),
				new Case("large", """
						r1 = 0x8111111122222222; r2 = 0x8765432112345678;
						""",
					List.of(
						ev("r0", "0xf9abcdf00fedcbaa"),
						ev("r3", "0xfff9abcdf00fedcb")))));
	}

	@Test
	public void testIntMultOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(getLanguageID(), """
				r0 = r1 * r2;
				r9l = r10l * r11l;
				"""),
			List.of(
				new Case("only", """
						r1  =2; r2  =2;
						r10l=2; r11l=2;
						""",
					List.of(
						ev("r0", "4"),
						ev("r9", "4")))));
	}

	@Test
	public void testIntMultMpIntOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(getLanguageID(), """
				temp0:16 = zext(r1) * zext(r2);
				r0 = temp0[0,64];
				r3 = temp0[64,64];
				"""),
			List.of(
				new Case("small", """
						r1 = 2; r2 = 7;
						""",
					List.of(
						ev("r0", "14"),
						ev("r3", "0"))),
				new Case("large", """
						r1 = 0xffeeddccbbaa9988; r2 = 0x8877665544332211;
						""",
					List.of(
						ev("r0", "0x30fdc971d4d04208"),
						ev("r3", "0x886e442c48bba72d")))));
	}

	@Test
	public void testIntDivOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(getLanguageID(), """
				r0 = r1 / r2;
				r9l = r10l / r11l;
				"""),
			List.of(
				new Case("pp", """
						r1  =5; r2  =2;
						r10l=5; r11l=2;
						""",
					List.of(
						ev("r0", "2"),
						ev("r9", "2"))),
				new Case("pn", """
						r1  =5; r2  =-2;
						r10l=5; r11l=-2;
						""",
					List.of(
						ev("r0", "0"),
						ev("r9", "0"))),
				new Case("np", """
						r1  =-5; r2  =2;
						r10l=-5; r11l=2;
						""",
					List.of(
						ev("r0", "0x7ffffffffffffffd"),
						ev("r9", "0x7ffffffd"))),
				new Case("nn", """
						r1  =-5; r2  =-2;
						r10l=-5; r11l=-2;
						""",
					List.of(
						ev("r0", "0"),
						ev("r9", "0")))));
	}

	@Test
	public void testIntDivOpGenWith3ByteOperand() throws Exception {
		runEquivalenceTest(translateSleigh(getLanguageID(), """
				temp:3 = r1 + r2;
				r0 = temp / r0;
				"""),
			List.of(
				new Case("only", """
						r1 = 0xdead;
						r2 = 0xbeef;
						r0 = 4;
						""",
					List.of(
						ev("r0", "0x6767")))));
	}

	@Test
	public void testIntDivMpIntOpGenNonUniform() throws Exception {
		runEquivalenceTest(translateSleigh(getLanguageID(), """
				temp1:9 = sext(r1);
				r0l = temp1 / r2;
				"""),
			List.of(
				new Case("pp", """
						r1 = 0x67452301efcdab89;
						r2 = 0x1234;
						""",
					List.of(
						ev("r0l", "0x2ee95b10"))),
				new Case("pn", """
						r1 = 0x67452301efcdab89;
						r2 = -0x1234;
						""",
					List.of(
						ev("r0l", "0x00000000"))),
				new Case("np", """
						r1 = -0x67452301efcdab89;
						r2 = 0x1234;
						""",
					List.of(
						ev("r0l", "0x0e658826"))),
				new Case("nn", """
						r1 = -0x67452301efcdab89;
						r2 = -0x1234;
						""",
					List.of(
						ev("r0l", "0x000000ff")))));
	}

	@Test
	public void testIntDivMpIntOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(getLanguageID(), """
				temp1:9 = sext(r1);
				temp2:9 = sext(r2);
				local quotient = temp1 / temp2;
				r0l = quotient(0);
				"""),
			List.of(
				new Case("pp", """
						r1 = 0x67452301efcdab89;
						r2 = 0x1234;
						""",
					List.of(
						ev("r0l", "0x2ee95b10"))),
				new Case("pn", """
						r1 = 0x67452301efcdab89;
						r2 = -0x1234;
						""",
					List.of(
						ev("r0l", "0x00000000"))),
				new Case("np", """
						r1 = -0x67452301efcdab89;
						r2 = 0x1234;
						""",
					List.of(
						ev("r0l", "0x0e658826"))),
				// NOTE: Result differs from NonUniform, because r2 is also sext()ed
				new Case("nn", """
						r1 = -0x67452301efcdab89;
						r2 = -0x1234;
						""",
					List.of(
						ev("r0l", "0x00000000")))));
	}

	@Test
	public void testIntSDivOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(getLanguageID(), """
				r0 = r1 s/ r2;
				r9l = r10l s/ r11l;
				"""),
			List.of(
				new Case("pp", """
						r1  =5; r2  =2;
						r10l=5; r11l=2;
						""",
					List.of(
						ev("r0", "2"),
						ev("r9l", "2"))),
				new Case("pn", """
						r1  =5; r2  =-2;
						r10l=5; r11l=-2;
						""",
					List.of(
						ev("r0", "-2"),
						ev("r9l", "-2"))),
				new Case("np", """
						r1  =-5; r2  =2;
						r10l=-5; r11l=2;
						""",
					List.of(
						ev("r0", "-2"),
						ev("r9l", "-2"))),
				new Case("nn", """
						r1  =-5; r2  =-2;
						r10l=-5; r11l=-2;
						""",
					List.of(
						ev("r0", "2"),
						ev("r9l", "2")))));
	}

	@Test
	public void testIntSDivMpIntOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(getLanguageID(), """
				temp1:9 = sext(r1);
				temp2:9 = sext(r2);
				local quotient = temp1 s/ temp2;
				r0l = quotient(0);
				"""),
			List.of(
				new Case("pp", """
						r1 = 0x67452301efcdab89;
						r2 = 0x1234;
						""",
					List.of(
						ev("r0", "0x2ee95b10"))),
				new Case("pn", """
						r1 = 0x67452301efcdab89;
						r2 = -0x1234;
						""",
					List.of(
						ev("r0", "0xd116a4f0"))),
				new Case("np", """
						r1 = -0x67452301efcdab89;
						r2 = 0x1234;
						""",
					List.of(
						ev("r0", "0xd116a4f0"))),
				new Case("nn", """
						r1 = -0x67452301efcdab89;
						r2 = -0x1234;
						""",
					List.of(
						ev("r0", "0x2ee95b10")))));
	}

	@Test
	public void testIntRemOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(getLanguageID(), """
				r0 = r1 % r2;
				r9l = r10l % r11l;
				"""),
			List.of(
				new Case("pp", """
						r1  =5; r2  =2;
						r10l=5; r11l=2;
						""",
					List.of(
						ev("r0", "1"),
						ev("r9l", "1"))),
				new Case("pn", """
						r1  =5; r2  =-2;
						r10l=5; r11l=-2;
						""",
					List.of(
						ev("r0", "5"),
						ev("r9l", "5"))),
				new Case("np", """
						r1  =-5; r2  =2;
						r10l=-5; r11l=2;
						""",
					List.of(
						ev("r0", "1"),
						ev("r9l", "1"))),
				new Case("nn", """
						r1  =-5; r2  =-2;
						r10l=-5; r11l=-2;
						""",
					List.of(
						ev("r0", "-5"),
						ev("r9l", "-5")))));
	}

	@Test
	public void testIntRemMpIntOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(getLanguageID(), """
				temp1:9 = sext(r1);
				temp2:9 = sext(r2);
				local remainder = temp1 % temp2;
				r0l = remainder(0);
				"""),
			List.of(
				new Case("pp", """
						r1 = 0x67452301efcdab89;
						r2 = 0x1234;
						""",
					List.of(
						ev("r0", "0x0c49"))),
				new Case("pn", """
						r1 = 0x67452301efcdab89;
						r2 = -0x1234;
						""",
					List.of(
						ev("r0", "0xefcdab89"))),
				new Case("np", """
						r1 = -0x67452301efcdab89;
						r2 = 0x1234;
						""",
					List.of(
						ev("r0", "0x00bf"))),
				new Case("nn", """
						r1 = -0x67452301efcdab89;
						r2 = -0x1234;
						""",
					List.of(
						ev("r0", "0x10325477")))));
	}

	@Test
	public void testIntSRemOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(getLanguageID(), """
				r0 = r1 s% r2;
				r9l = r10l s% r11l;
				"""),
			List.of(
				new Case("pp", """
						r1  =5; r2  =2;
						r10l=5; r11l=2;
						""",
					List.of(
						ev("r0", "1"),
						ev("r9l", "1"))),
				new Case("pn", """
						r1  =5; r2  =-2;
						r10l=5; r11l=-2;
						""",
					List.of(
						ev("r0", "1"),
						ev("r9l", "1"))),
				new Case("np", """
						r1  =-5; r2  =2;
						r10l=-5; r11l=2;
						""",
					List.of(
						ev("r0", "-1"),
						ev("r9l", "-1"))),
				new Case("nn", """
						r1  =-5; r2  =-2;
						r10l=-5; r11l=-2;
						""",
					List.of(
						ev("r0", "-1"),
						ev("r9l", "-1")))));
	}

	@Test
	public void testIntSRemMpIntOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(getLanguageID(), """
				temp1:9 = sext(r1);
				temp2:9 = sext(r2);
				local quotient = temp1 s% temp2;
				r0l = quotient(0);
				"""),
			List.of(
				new Case("pp", """
						r1 = 0x67452301efcdab89;
						r2 = 0x1234;
						""",
					List.of(
						ev("r0", "0x0c49"))),
				new Case("pn", """
						r1 = 0x67452301efcdab89;
						r2 = -0x1234;
						""",
					List.of(
						ev("r0", "0x0c49"))),
				new Case("np", """
						r1 = -0x67452301efcdab89;
						r2 = 0x1234;
						""",
					List.of(
						ev("r0", "0xfffff3b7"))),
				new Case("nn", """
						r1 = -0x67452301efcdab89;
						r2 = -0x1234;
						""",
					List.of(
						ev("r0", "0xfffff3b7")))));
	}

	@Test
	public void testIntAndOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(getLanguageID(), """
				r0 = r1 & r2;
				r9l = r10l & r11l;
				"""),
			List.of(
				new Case("only", """
						r1  =0x3; r2  =0x5;
						r10l=0x3; r11l=0x5;
						""",
					List.of(
						ev("r0", "1"),
						ev("r9", "1")))));
	}

	@Test
	public void testIntAndMpIntOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(getLanguageID(), """
				temp1:9 = zext(r1);
				temp2:9 = zext(r2);
				temp0:9 = temp1 & temp2;
				r0 = temp0(0);
				"""),
			List.of(
				new Case("small", """
						r1 = 2; r2 = 2;
						""",
					List.of(
						ev("r0", "2"))),
				new Case("large", """
						r1 = 0x8111111122222222; r2 = 0x8765432112345678;
						""",
					List.of(
						ev("r0", "0x8101010102200220")))));
	}

	@Test
	public void testIntOrOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(getLanguageID(), """
				r0 = r1 | r2;
				r9l = r10l | r11l;
				"""),
			List.of(
				new Case("only", """
						r1  =0x3; r2  =0x5;
						r10l=0x3; r11l=0x5;
						""",
					List.of(
						ev("r0", "7"),
						ev("r9", "7")))));
	}

	@Test
	public void testIntOrMpIntOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(getLanguageID(), """
				temp1:9 = zext(r1);
				temp2:9 = zext(r2);
				temp0:9 = temp1 | temp2;
				r0 = temp0(0);
				"""),
			List.of(
				new Case("small", """
						r1 = 2; r2 = 2;
						""",
					List.of(
						ev("r0", "2"))),
				new Case("large", """
						r1 = 0x8111111122222222; r2 = 0x8765432112345678;
						""",
					List.of(
						ev("r0", "0x877553313236767a")))));
	}

	@Test
	public void testIntXorOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(getLanguageID(), """
				r0 = r1 ^ r2;
				r9l = r10l ^ r11l;
				"""),
			List.of(
				new Case("only", """
						r1  =0x3; r2  =0x5;
						r10l=0x3; r11l=0x5;
						""",
					List.of(
						ev("r0", "6"),
						ev("r9", "6")))));
	}

	@Test
	public void testIntXorMpIntOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(getLanguageID(), """
				temp1:9 = zext(r1);
				temp2:9 = zext(r2);
				temp0:9 = temp1 ^ temp2;
				r0 = temp0(0);
				"""),
			List.of(
				new Case("small", """
						r1 = 2; r2 = 2;
						""",
					List.of(
						ev("r0", "0"))),
				new Case("large", """
						r1 = 0x8111111122222222; r2 = 0x8765432112345678;
						""",
					List.of(
						ev("r0", "0x67452303016745a")))));
	}

	@Test
	public void testIntEqualOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(getLanguageID(), """
				r0 = r1 == r2;
				r9l = r10l == r11l;
				"""),
			List.of(
				new Case("lt", """
						r1  =1; r2  =2;
						r10l=1; r11l=2;
						""",
					List.of(
						ev("r0", "0"),
						ev("r9", "0"))),
				new Case("slt", """
						r1  =-1; r2  =2;
						r10l=-1; r11l=2;
						""",
					List.of(
						ev("r0", "0"),
						ev("r9", "0"))),
				new Case("eq", """
						r1  =1; r2  =1;
						r10l=1; r11l=1;
						""",
					List.of(
						ev("r0", "1"),
						ev("r9", "1"))),
				new Case("gt", """
						r1  =2; r2  =1;
						r10l=2; r11l=1;
						""",
					List.of(
						ev("r0", "0"),
						ev("r9", "0"))),
				new Case("sgt", """
						r1  =2; r2  =-1;
						r10l=2; r11l=-1;
						""",
					List.of(
						ev("r0", "0"),
						ev("r9", "0")))));
	}

	@Test
	public void testIntEqualMpIntOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(getLanguageID(), """
				temp1:9 = sext(r1);
				temp2:9 = sext(r2);
				r0 = temp1 == temp2;
				"""),
			List.of(
				new Case("lt", """
						r1 = 1; r2 = 2;
						""",
					List.of(
						ev("r0", "0"))),
				new Case("slt", """
						r1 = -1; r2 = 0x7fffffffffffffff;
						""",
					List.of(
						ev("r0", "0"))),
				new Case("eq", """
						r1 = 1; r2 = 1;
						""",
					List.of(
						ev("r0", "1"))),
				new Case("gt", """
						r1 = 2; r2 = 1;
						""",
					List.of(
						ev("r0", "0"))),
				new Case("sgt", """
						r1 = 2; r2 = -1;
						""",
					List.of(
						ev("r0", "0")))));
	}

	@Test
	public void testIntNotEqualOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(getLanguageID(), """
				r0 = r1 != r2;
				r9l = r10l != r11l;
				"""),
			List.of(
				new Case("lt", """
						r1  =1; r2  =2;
						r10l=1; r11l=2;
						""",
					List.of(
						ev("r0", "1"),
						ev("r9", "1"))),
				new Case("slt", """
						r1  =-1; r2  =2;
						r10l=-1; r11l=2;
						""",
					List.of(
						ev("r0", "1"),
						ev("r9", "1"))),
				new Case("eq", """
						r1  =1; r2  =1;
						r10l=1; r11l=1;
						""",
					List.of(
						ev("r0", "0"),
						ev("r9", "0"))),
				new Case("gt", """
						r1  =2; r2  =1;
						r10l=2; r11l=1;
						""",
					List.of(
						ev("r0", "1"),
						ev("r9", "1"))),
				new Case("sgt", """
						r1  =2; r2  =-1;
						r10l=2; r11l=-1;
						""",
					List.of(
						ev("r0", "1"),
						ev("r9", "1")))));
	}

	@Test
	public void testIntNotEqualMpIntOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(getLanguageID(), """
				temp1:9 = sext(r1);
				temp2:9 = sext(r2);
				r0 = temp1 != temp2;
				"""),
			List.of(
				new Case("lt", """
						r1 = 1; r2 = 2;
						""",
					List.of(
						ev("r0", "1"))),
				new Case("slt", """
						r1 = -1; r2 = 0x7fffffffffffffff;
						""",
					List.of(
						ev("r0", "1"))),
				new Case("eq", """
						r1 = 1; r2 = 1;
						""",
					List.of(
						ev("r0", "0"))),
				new Case("gt", """
						r1 = 2; r2 = 1;
						""",
					List.of(
						ev("r0", "1"))),
				new Case("sgt", """
						r1 = 2; r2 = -1;
						""",
					List.of(
						ev("r0", "1")))));
	}

	@Test
	public void testIntLessEqualOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(getLanguageID(), """
				r0 = r1 <= r2;
				r9l = r10l <= r11l;
				"""),
			List.of(
				new Case("lt", """
						r1  =1; r2  =2;
						r10l=1; r11l=2;
						""",
					List.of(
						ev("r0", "1"),
						ev("r9", "1"))),
				new Case("slt", """
						r1  =-1; r2  =2;
						r10l=-1; r11l=2;
						""",
					List.of(
						ev("r0", "0"),
						ev("r9", "0"))),
				new Case("eq", """
						r1  =1; r2  =1;
						r10l=1; r11l=1;
						""",
					List.of(
						ev("r0", "1"),
						ev("r9", "1"))),
				new Case("gt", """
						r1  =2; r2  =1;
						r10l=2; r11l=1;
						""",
					List.of(
						ev("r0", "0"),
						ev("r9", "0"))),
				new Case("sgt", """
						r1  =2; r2  =-1;
						r10l=2; r11l=-1;
						""",
					List.of(
						ev("r0", "1"),
						ev("r9", "1")))));
	}

	@Test
	public void testIntLessEqualMpIntOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(getLanguageID(), """
				temp1:9 = sext(r1);
				temp2:9 = sext(r2);
				r0 = temp1 <= temp2;
				"""),
			List.of(
				new Case("lt", """
						r1 = 1; r2 = 2;
						""",
					List.of(
						ev("r0", "1"))),
				new Case("slt", """
						r1 = -1; r2 = 0x7fffffffffffffff;
						""",
					List.of(
						ev("r0", "0"))),
				new Case("eq", """
						r1 = 1; r2 = 1;
						""",
					List.of(
						ev("r0", "1"))),
				new Case("gt", """
						r1 = 2; r2 = 1;
						""",
					List.of(
						ev("r0", "0"))),
				new Case("sgt", """
						r1 = 2; r2 = -1;
						""",
					List.of(
						ev("r0", "1")))));
	}

	@Test
	public void testIntSLessEqualOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(getLanguageID(), """
				r0 = r1 s<= r2;
				r9l = r10l s<= r11l;
				"""),
			List.of(
				new Case("lt", """
						r1  =1; r2  =2;
						r10l=1; r11l=2;
						""",
					List.of(
						ev("r0", "1"),
						ev("r9", "1"))),
				new Case("slt", """
						r1  =-1; r2  =2;
						r10l=-1; r11l=2;
						""",
					List.of(
						ev("r0", "1"),
						ev("r9", "1"))),
				new Case("eq", """
						r1  =1; r2  =1;
						r10l=1; r11l=1;
						""",
					List.of(
						ev("r0", "1"),
						ev("r9", "1"))),
				new Case("gt", """
						r1  =2; r2  =1;
						r10l=2; r11l=1;
						""",
					List.of(
						ev("r0", "0"),
						ev("r9", "0"))),
				new Case("sgt", """
						r1  =2; r2  =-1;
						r10l=2; r11l=-1;
						""",
					List.of(
						ev("r0", "0"),
						ev("r9", "0")))));
	}

	@Test
	public void testIntSLessEqualMpIntOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(getLanguageID(), """
				temp1:9 = sext(r1);
				temp2:9 = sext(r2);
				r0 = temp1 s<= temp2;
				"""),
			List.of(
				new Case("lt", """
						r1 = 1; r2 = 2;
						""",
					List.of(
						ev("r0", "1"))),
				new Case("slt", """
						r1 = -1; r2 = 0x7fffffffffffffff;
						""",
					List.of(
						ev("r0", "1"))),
				new Case("eq", """
						r1 = 1; r2 = 1;
						""",
					List.of(
						ev("r0", "1"))),
				new Case("gt", """
						r1 = 2; r2 = 1;
						""",
					List.of(
						ev("r0", "0"))),
				new Case("sgt", """
						r1 = 2; r2 = -1;
						""",
					List.of(
						ev("r0", "0")))));
	}

	@Test
	public void testIntLessOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(getLanguageID(), """
				r0 = r1 < r2;
				r9l = r10l < r11l;
				"""),
			List.of(
				new Case("lt", """
						r1  =1; r2  =2;
						r10l=1; r11l=2;
						""",
					List.of(
						ev("r0", "1"),
						ev("r9", "1"))),
				new Case("slt", """
						r1  =-1; r2  =2;
						r10l=-1; r11l=2;
						""",
					List.of(
						ev("r0", "0"),
						ev("r9", "0"))),
				new Case("eq", """
						r1  =1; r2  =1;
						r10l=1; r11l=1;
						""",
					List.of(
						ev("r0", "0"),
						ev("r9", "0"))),
				new Case("gt", """
						r1  =2; r2  =1;
						r10l=2; r11l=1;
						""",
					List.of(
						ev("r0", "0"),
						ev("r9", "0"))),
				new Case("sgt", """
						r1  =2; r2  =-1;
						r10l=2; r11l=-1;
						""",
					List.of(
						ev("r0", "1"),
						ev("r9", "1")))));
	}

	@Test
	public void testIntLessMpIntOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(getLanguageID(), """
				temp1:9 = sext(r1);
				temp2:9 = sext(r2);
				r0 = temp1 < temp2;
				"""),
			List.of(
				new Case("lt", """
						r1 = 1; r2 = 2;
						""",
					List.of(
						ev("r0", "1"))),
				new Case("slt", """
						r1 = -1; r2 = 0x7fffffffffffffff;
						""",
					List.of(
						ev("r0", "0"))),
				new Case("eq", """
						r1 = 1; r2 = 1;
						""",
					List.of(
						ev("r0", "0"))),
				new Case("gt", """
						r1 = 2; r2 = 1;
						""",
					List.of(
						ev("r0", "0"))),
				new Case("sgt", """
						r1 = 2; r2 = -1;
						""",
					List.of(
						ev("r0", "1")))));
	}

	@Test
	public void testIntSLessOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(getLanguageID(), """
				r0 = r1 s< r2;
				r9l = r10l s< r11l;
				"""),
			List.of(
				new Case("lt", """
						r1  =1; r2  =2;
						r10l=1; r11l=2;
						""",
					List.of(
						ev("r0", "1"),
						ev("r9", "1"))),
				new Case("slt", """
						r1  =-1; r2  =2;
						r10l=-1; r11l=2;
						""",
					List.of(
						ev("r0", "1"),
						ev("r9", "1"))),
				new Case("eq", """
						r1  =1; r2  =1;
						r10l=1; r11l=1;
						""",
					List.of(
						ev("r0", "0"),
						ev("r9", "0"))),
				new Case("gt", """
						r1  =2; r2  =1;
						r10l=2; r11l=1;
						""",
					List.of(
						ev("r0", "0"),
						ev("r9", "0"))),
				new Case("sgt", """
						r1  =2; r2  =-1;
						r10l=2; r11l=-1;
						""",
					List.of(
						ev("r0", "0"),
						ev("r9", "0")))));
	}

	@Test
	public void testIntSLessMpIntOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(getLanguageID(), """
				temp1:9 = sext(r1);
				temp2:9 = sext(r2);
				r0 = temp1 s< temp2;
				"""),
			List.of(
				new Case("lt", """
						r1 = 1; r2 = 2;
						""",
					List.of(
						ev("r0", "1"))),
				new Case("slt", """
						r1 = -1; r2 = 0x7fffffffffffffff;
						""",
					List.of(
						ev("r0", "1"))),
				new Case("eq", """
						r1 = 1; r2 = 1;
						""",
					List.of(
						ev("r0", "0"))),
				new Case("gt", """
						r1 = 2; r2 = 1;
						""",
					List.of(
						ev("r0", "0"))),
				new Case("sgt", """
						r1 = 2; r2 = -1;
						""",
					List.of(
						ev("r0", "0")))));
	}

	@Test
	public void testIntCarryOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(getLanguageID(), """
				r0 = carry(r1, r2);
				r9l = carry(r10l, r11l);
				"""),
			List.of(
				new Case("f", """
						r1  =0x8000000000000000; r2  =0x4000000000000000;
						r10l=0x80000000;         r11l=0x40000000;
						""",
					List.of(
						ev("r0", "0"),
						ev("r9", "0"))),
				new Case("t", """
						r1  =0x8000000000000000; r2  =0x8000000000000000;
						r10l=0x80000000;         r11l=0x80000000;
						""",
					List.of(
						ev("r0", "1"),
						ev("r9", "1")))));
	}

	@Test
	public void testIntCarryMpIntOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(getLanguageID(), """
				temp1:9 = zext(r1) << 8;
				temp2:9 = zext(r2) << 8;
				r0 = carry(temp1, temp2);
				"""),
			List.of(
				new Case("f", """
						r1  =0x8000000000000000; r2  =0x4000000000000000;
						r10l=0x80000000;         r11l=0x40000000;
						""",
					List.of(
						ev("r0", "0"))),
				new Case("t", """
						r1  =0x8000000000000000; r2  =0x8000000000000000;
						r10l=0x80000000;         r11l=0x80000000;
						""",
					List.of(
						ev("r0", "1")))));
	}

	@Test
	public void testIntSCarryOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(getLanguageID(), """
				r0 = scarry(r1, r2);
				r9l = scarry(r10l, r11l);
				"""),
			List.of(
				new Case("f", """
						r1  =0x8000000000000000; r2  =0x4000000000000000;
						r10l=0x80000000;         r11l=0x40000000;
						""",
					List.of(
						ev("r0", "0"),
						ev("r9", "0"))),
				new Case("t", """
						r1  =0x4000000000000000; r2  =0x4000000000000000;
						r10l=0x40000000;         r11l=0x40000000;
						""",
					List.of(
						ev("r0", "1"),
						ev("r9", "1")))));
	}

	@Test
	public void testIntSCarryMpIntOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(getLanguageID(), """
				temp1:9 = zext(r1) << 8;
				temp2:9 = zext(r2) << 8;
				r0 = scarry(temp1, temp2);
				"""),
			List.of(
				new Case("f", """
						r1  =0x8000000000000000; r2  =0x4000000000000000;
						r10l=0x80000000;         r11l=0x40000000;
						""",
					List.of(
						ev("r0", "0"))),
				new Case("t", """
						r1  =0x4000000000000000; r2  =0x4000000000000000;
						r10l=0x40000000;         r11l=0x40000000;
						""",
					List.of(
						ev("r0", "1")))));
	}

	@Test
	public void testIntSBorrowOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(getLanguageID(), """
				r0 = sborrow(r1, r2);
				r9l = sborrow(r10l, r11l);
				"""),
			List.of(
				new Case("t", """
						r1  =0x8000000000000000; r2  =0x4000000000000000;
						r10l=0x80000000;         r11l=0x40000000;
						""",
					List.of(
						ev("r0", "1"),
						ev("r9", "1"))),
				new Case("f", """
						r1  =0xc000000000000000; r2  =0x4000000000000000;
						r10l=0xc0000000;         r11l=0x40000000;
						""",
					List.of(
						ev("r0", "0"),
						ev("r9", "0")))));
	}

	@Test
	public void testIntSBorrowMpIntOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(getLanguageID(), """
				temp1:9 = zext(r1) << 8;
				temp2:9 = zext(r2) << 8;
				r0 = sborrow(temp1, temp2);
				"""),
			List.of(
				new Case("t", """
						r1  =0x8000000000000000; r2  =0x4000000000000000;
						r10l=0x80000000;         r11l=0x40000000;
						""",
					List.of(
						ev("r0", "1"))),
				new Case("f", """
						r1  =0xc000000000000000; r2  =0x4000000000000000;
						r10l=0xc0000000;         r11l=0x40000000;
						""",
					List.of(
						ev("r0", "0")))));
	}

	@Test
	public void testIntLeftOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(getLanguageID(), """
				r0 = r1 << r2;
				r3 = r4 << r5l;
				r6l = r7l << r8;
				r9l = r10l << r11l;
				"""),
			List.of(
				new Case("posLposR", """
						r1  =100; r2  =4;
						r4  =100; r5l =4;
						r7l =100; r8  =4;
						r10l=100; r11l=4;
						""",
					List.of(
						ev("r0", "0x640"),
						ev("r3", "0x640"),
						ev("r6l", "0x640"),
						ev("r9l", "0x640"))),
				new Case("posLbigR", """
						r1  =100; r2  =0x100000004;
						r4  =100; r5l =0x100000004;
						r7l =100; r8  =0x100000004;
						r10l=100; r11l=0x100000004;
						""",
					List.of(
						ev("r0", "0"),
						ev("r3", "0x640"),
						ev("r6l", "0"),
						ev("r9l", "0x640"))),
				new Case("posLnegR", """
						r1  =100; r2  =-4;
						r4  =100; r5l =-4;
						r7l =100; r8  =-4;
						r10l=100; r11l=-4;
						""",
					List.of(
						ev("r0", "0"),
						ev("r3", "0"),
						ev("r6l", "0"),
						ev("r9l", "0"))),
				new Case("negLposR", """
						r1  =-100; r2  =4;
						r4  =-100; r5l =4;
						r7l =-100; r8  =4;
						r10l=-100; r11l=4;
						""",
					List.of(
						ev("r0", "-0x640"),
						ev("r3", "-0x640"),
						ev("r6l", "-0x640"),
						ev("r9l", "-0x640"))),
				new Case("negLnegR", """
						r1  =-100; r2  =-4;
						r4  =-100; r5l =-4;
						r7l =-100; r8  =-4;
						r10l=-100; r11l=-4;
						""",
					List.of(
						ev("r0", "0"),
						ev("r3", "0"),
						ev("r6l", "0"),
						ev("r9l", "0")))));
	}

	@Test
	public void testIntLeftMpIntOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(getLanguageID(), """
				temp1:9 = sext(r1);
				temp2:9 = (zext(r2) << 64) + r3;
				temp0:9 = temp1 << temp2;
				r0 = temp0(0);
				r4 = temp0(1);
				"""),
			List.of(
				new Case("posLposR", """
						r1 = 0x7edcba9876543210;
						r2 = 0;
						r3 = 4;
						""",
					List.of(
						ev("r0", "0xedcba98765432100"),
						ev("r4", "0x07edcba987654321"))),
				new Case("posLmedR", """
						r1 = 0x7edcba9876543210;
						r2 = 0;
						r3 = 36;
						""",
					List.of(
						ev("r0", "0x6543210000000000"),
						ev("r4", "0x8765432100000000"))),
				new Case("posLbigR", """
						r1 = 0x7edcba9876543210;
						r2 = 0x40;
						r3 = 4;
						""",
					List.of(
						ev("r0", "0"),
						ev("r4", "0"))),
				new Case("posLnegR", """
						r1 = 0x7edcba9876543210;
						r2 = -1;
						r3 = -4;
						""",
					List.of(
						ev("r0", "0"),
						ev("r4", "0"))),
				new Case("negLposR", """
						r1 = 0xfedcba9876543210;
						r2 = 0;
						r3 = 4;
						""",
					List.of(
						ev("r0", "0xedcba98765432100"),
						ev("r4", "0xffedcba987654321"))),
				new Case("negLnegR", """
						r1 = 0xfedcba9876543210;
						r2 = -1;
						r3 = -4;
						""",
					List.of(
						ev("r0", "0"),
						ev("r4", "0")))));
	}

	@Test
	public void testIntRightOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(getLanguageID(), """
				r0 = r1 >> r2;
				r3 = r4 >> r5l;
				r6l = r7l >> r8;
				r9l = r10l >> r11l;
				"""),
			List.of(
				new Case("posLposR", """
						r1  =100; r2  =4;
						r4  =100; r5l =4;
						r7l =100; r8  =4;
						r10l=100; r11l=4;
						""",
					List.of(
						ev("r0", "6"),
						ev("r3", "6"),
						ev("r6l", "6"),
						ev("r9l", "6"))),
				new Case("posLbigR", """
						r1  =100; r2  =0x100000004;
						r4  =100; r5l =0x100000004;
						r7l =100; r8  =0x100000004;
						r10l=100; r11l=0x100000004;
						""",
					List.of(
						ev("r0", "0"),
						ev("r3", "6"),
						ev("r6l", "0"),
						ev("r9l", "6"))),
				new Case("posLnegR", """
						r1  =100; r2  =-4;
						r4  =100; r5l =-4;
						r7l =100; r8  =-4;
						r10l=100; r11l=-4;
						""",
					List.of(
						ev("r0", "0"),
						ev("r3", "0"),
						ev("r6l", "0"),
						ev("r9l", "0"))),
				new Case("negLposR", """
						r1  =-100; r2  =4;
						r4  =-100; r5l =4;
						r7l =-100; r8  =4;
						r10l=-100; r11l=4;
						""",
					List.of(
						ev("r0", "0x0ffffffffffffff9"),
						ev("r3", "0x0ffffffffffffff9"),
						ev("r6l", "0x0ffffff9"),
						ev("r9l", "0x0ffffff9"))),
				new Case("negLnegR", """
						r1  =-100; r2  =-4;
						r4  =-100; r5l =-4;
						r7l =-100; r8  =-4;
						r10l=-100; r11l=-4;
						""",
					List.of(
						ev("r0", "0"),
						ev("r3", "0"),
						ev("r6l", "0"),
						ev("r9l", "0")))));
	}

	@Test
	public void testIntRightMpIntOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(getLanguageID(), """
				temp1:9 = sext(r1);
				temp2:9 = (zext(r2) << 64) + r3;
				temp0:9 = temp1 >> temp2;
				r0 = temp0(0);
				r4 = temp0(1);
				"""),
			List.of(
				new Case("posLposR", """
						r1 = 0x7edcba9876543210;
						r2 = 0;
						r3 = 4;
						""",
					List.of(
						ev("r0", "0x07edcba987654321"),
						ev("r4", "0x0007edcba9876543"))),
				new Case("posLmedR", """
						r1 = 0x7edcba9876543210;
						r2 = 0;
						r3 = 36;
						""",
					List.of(
						ev("r0", "0x0000000007edcba9"),
						ev("r4", "0x000000000007edcb"))),
				new Case("posLbigR", """
						r1 = 0x7edcba9876543210;
						r2 = 0x40;
						r3 = 4;
						""",
					List.of(
						ev("r0", "0"),
						ev("r4", "0"))),
				new Case("posLnegR", """
						r1 = 0x7edcba9876543210;
						r2 = -1;
						r3 = -4;
						""",
					List.of(
						ev("r0", "0"),
						ev("r4", "0"))),
				new Case("negLposR", """
						r1 = 0xfedcba9876543210;
						r2 = 0;
						r3 = 4;
						""",
					List.of(
						ev("r0", "0xffedcba987654321"),
						ev("r4", "0x0fffedcba9876543"))),
				new Case("negLmedR", """
						r1 = 0xfedcba9876543210;
						r2 = 0;
						r3 = 36;
						""",
					List.of(
						ev("r0", "0x0000000fffedcba9"),
						ev("r4", "0x000000000fffedcb"))),
				new Case("negLnegR", """
						r1 = 0xfedcba9876543210;
						r2 = -1;
						r3 = -4;
						""",
					List.of(
						ev("r0", "0"),
						ev("r4", "0")))));
	}

	@Test
	public void testIntSRightOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(getLanguageID(), """
				r0 = r1 s>> r2;
				r3 = r4 s>> r5l;
				r6l = r7l s>> r8;
				r9l = r10l s>> r11l;
				"""),
			List.of(
				new Case("posLposR", """
						r1  =100; r2  =4;
						r4  =100; r5l =4;
						r7l =100; r8  =4;
						r10l=100; r11l=4;
						""",
					List.of(
						ev("r0", "6"),
						ev("r3", "6"),
						ev("r6l", "6"),
						ev("r9l", "6"))),
				new Case("posLbigR", """
						r1  =100; r2  =0x100000004;
						r4  =100; r5l =0x100000004;
						r7l =100; r8  =0x100000004;
						r10l=100; r11l=0x100000004;
						""",
					List.of(
						ev("r0", "0"),
						ev("r3", "6"),
						ev("r6l", "0"),
						ev("r9l", "6"))),
				new Case("posLnegR", """
						r1  =100; r2  =-4;
						r4  =100; r5l =-4;
						r7l =100; r8  =-4;
						r10l=100; r11l=-4;
						""",
					List.of(
						ev("r0", "0"),
						ev("r3", "0"),
						ev("r6l", "0"),
						ev("r9l", "0"))),
				new Case("negLposR", """
						r1  =-100; r2  =4;
						r4  =-100; r5l =4;
						r7l =-100; r8  =4;
						r10l=-100; r11l=4;
						""",
					List.of(
						ev("r0", "-7"),
						ev("r3", "-7"),
						ev("r6l", "-7"),
						ev("r9l", "-7"))),
				new Case("negLnegR", """
						r1  =-100; r2  =-4;
						r4  =-100; r5l =-4;
						r7l =-100; r8  =-4;
						r10l=-100; r11l=-4;
						""",
					List.of(
						ev("r0", "-1"),
						ev("r3", "-1"),
						ev("r6l", "-1"),
						ev("r9l", "-1")))));
	}

	@Test
	public void testIntSRight3IntOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(getLanguageID(), """
				temp1:3 = r1(0);
				temp0:3 = temp1 s>> r2;
				r0 = zext(temp0);
				"""),
			List.of(
				new Case("posLposR", """
						r1 = 0xfedcba;
						r2 = 4;
						""",
					List.of(
						ev("r0", "0xffedcb")))));
	}

	@Test
	public void testIntSRightMpIntOpGen() throws Exception {
		runEquivalenceTest(translateSleigh(getLanguageID(), """
				temp1:9 = sext(r1);
				temp2:9 = (zext(r2) << 64) + r3;
				temp0:9 = temp1 s>> temp2;
				r0 = temp0(0);
				r4 = temp0(1);
				"""),
			List.of(
				new Case("posLposR", """
						r1 = 0x7edcba9876543210;
						r2 = 0;
						r3 = 4;
						""",
					List.of(
						ev("r0", "0x07edcba987654321"),
						ev("r4", "0x0007edcba9876543"))),
				new Case("posLmedR", """
						r1 = 0x7edcba9876543210;
						r2 = 0;
						r3 = 36;
						""",
					List.of(
						ev("r0", "0x0000000007edcba9"),
						ev("r4", "0x000000000007edcb"))),
				new Case("posLbigR", """
						r1 = 0x7edcba9876543210;
						r2 = 0x40;
						r3 = 4;
						""",
					List.of(
						ev("r0", "0"),
						ev("r4", "0"))),
				new Case("posLnegR", """
						r1 = 0x7edcba9876543210;
						r2 = -1;
						r3 = -4;
						""",
					List.of(
						ev("r0", "0"),
						ev("r4", "0"))),
				new Case("negLposR", """
						r1 = 0xfedcba9876543210;
						r2 = 0;
						r3 = 4;
						""",
					List.of(
						ev("r0", "0xffedcba987654321"),
						ev("r4", "0xffffedcba9876543"))),
				new Case("negLlegR", """
						r1 = 0xfedcba9876543210;
						r2 = 0;
						r3 = 32;
						""",
					List.of(
						ev("r0", "0xfffffffffedcba98"),
						ev("r4", "0xfffffffffffedcba"))),
				new Case("negLmedR", """
						r1 = 0xfedcba9876543210;
						r2 = 0;
						r3 = 36;
						""",
					List.of(
						ev("r0", "0xffffffffffedcba9"),
						ev("r4", "0xffffffffffffedcb"))),
				new Case("negLnegR", """
						r1 = 0xfedcba9876543210;
						r2 = -1;
						r3 = -4;
						""",
					List.of(
						ev("r0", "-1"),
						ev("r4", "-1")))));
	}

	@Test
	public void testFloatAsOffset() throws Exception {
		int fDot5 = Float.floatToRawIntBits(0.5f);
		int f1Dot0 = Float.floatToRawIntBits(1.0f);
		Translation tr = translateSleigh(getLanguageID(), """
				temp:4 = 0x%x f+ 0x%x;
				temp2:8 = *temp;
				""".formatted(fDot5, fDot5));
		Varnode temp2 = tr.program().getCode().get(1).getOutput();
		assertTrue(temp2.isUnique());
		tr.setLongMemVal(f1Dot0, LONG_CONST, 8);
		tr.runFallthrough();
		assertEquals(LONG_CONST, tr.getLongVnVal(temp2));
	}

	@Test
	public void testDoubleAsOffset() throws Exception {
		long dDot5 = Double.doubleToRawLongBits(0.5);
		long d1Dot0 = Double.doubleToRawLongBits(1.0);
		Translation tr = translateSleigh(getLanguageID(), """
				temp:8 = 0x%x f+ 0x%x;
				temp2:8 = *temp;
				""".formatted(dDot5, dDot5));
		Varnode temp2 = tr.program().getCode().get(1).getOutput();
		assertTrue(temp2.isUnique());
		tr.setLongMemVal(d1Dot0, LONG_CONST, 8);
		tr.runFallthrough();
		assertEquals(LONG_CONST, tr.getLongVnVal(temp2));
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
	public void testDelaySlot() throws Exception {
		Translation tr = translateLang(getLanguageID(), 0x00400000, """
				brds r0
				imm r0, #123
				""", Map.of());
		tr.setLongRegVal("r0", 0x1234);
		assertEquals(0x1234, tr.runClean());
		assertEquals(123, tr.getLongRegVal("r0"));
	}

	@Test
	public void testEmuInjectionCallEmuSwi() throws Exception {
		Translation tr = translateLang(getLanguageID(), 0x00400000, """
				imm r0,#123
				add r0,#7
				""",
			Map.ofEntries(
				Map.entry(0x00400002L, "emu_swi();")));

		tr.runErr(InterruptPcodeExecutionException.class, "Execution hit breakpoint");

		/**
		 * Two reasons we don't reach the add: 1) It's overridden, and there's no deferral to the
		 * decoded instruction. 2) Even if there were, we got interrupted before it executed.
		 */
		assertEquals(123, tr.getLongRegVal("r0"));
	}

	@Test
	public void testEmuInjectionCallEmuExecDecoded() throws Exception {
		Translation tr = translateLang(getLanguageID(), 0x00400000, """
				imm r0,#123
				add r0,#7
				""", Map.ofEntries(
			Map.entry(0x00400002L, """
					r1 = sleigh_userop(r0, 4:8);
					emu_exec_decoded();
					""")));

		tr.runDecodeErr(0x00400004);
		assertEquals(123 + 7, tr.getLongRegVal("r0"));
		assertEquals(123 * 2 + 4, tr.getLongRegVal("r1"));
	}

	@Test
	public void testEmuInjectionCallEmuSkipDecoded() throws Exception {
		Translation tr = translateLang(getLanguageID(), 0x00400000, """
				imm r0,#123
				add r0,#7
				""", Map.ofEntries(
			Map.entry(0x00400002L, """
					r1 = sleigh_userop(r0, 4:8);
					emu_skip_decoded();
					""")));

		tr.runDecodeErr(0x00400004);
		assertEquals(123, tr.getLongRegVal("r0"));
		assertEquals(123 * 2 + 4, tr.getLongRegVal("r1"));
	}

	@Test
	public void testFlagOpsRemoved() throws Exception {
		Translation tr = translateLang(getLanguageID(), 0x00400000, """
				add r0,#6
				add r0,#7
				""", Map.of());

		tr.runDecodeErr(0x00400004);
		assertEquals(13, tr.getLongRegVal("r0"));

		long countSCarrys = Stream.of(tr.run().instructions.toArray()).filter(i -> {
			if (!(i instanceof MethodInsnNode mi)) {
				return false;
			}
			return "sCarryLongRaw".equals(mi.name);
		}).count();
		assertEquals(1, countSCarrys);
	}
}
