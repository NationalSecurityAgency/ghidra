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

import static org.junit.Assert.*;

import java.util.*;
import java.util.Map.Entry;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.stream.Collectors;

import org.apache.commons.collections4.BidiMap;
import org.apache.commons.collections4.bidimap.DualHashBidiMap;
import org.junit.Test;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.app.plugin.processors.sleigh.SleighLanguageHelper;
import ghidra.pcode.emu.jit.AbstractJitTest;
import ghidra.pcode.emu.jit.analysis.JitControlFlowModel.BlockFlow;
import ghidra.pcode.emu.jit.op.*;
import ghidra.pcode.emu.jit.var.*;
import ghidra.pcode.emu.jit.var.JitVal.ValUse;
import ghidra.pcode.exec.*;
import ghidra.program.model.pcode.PcodeOp;
import junit.framework.AssertionFailedError;

public class JitDataFlowModelTest extends AbstractJitTest {

	private Predicate<JitOp> opType(Class<? extends JitOp> cls) {
		return cls::isInstance;
	}

	private Function<JitCallOtherOpIf, JitVal> otherArg(int i) {
		return op -> op.args().get(i);
	}

	record ExpectedOp<T extends JitOp>(int e, Class<T> cls) {
		private static int nextE = 0;

		public ExpectedOp(Class<T> cls) {
			this(nextE++, cls);
		}
	}

	record ExpectedVal<T extends JitVal>(int e, Class<T> cls, String str, int size) {

		private static int nextE = 0;

		public ExpectedVal(Class<T> cls, String str, int size) {
			this(nextE++, cls, str, size);
		}
	}

	enum Dir {
		IN, OUT
	}

	record ExpectedEdge<OT extends JitOp, VT extends JitVal>(Dir dir, ExpectedOp<OT> op,
			Function<? super OT, JitVal> valGetter, Function<VT, JitOp> opGetter,
			ExpectedVal<VT> v) {

		public static <OT extends JitOp, VT extends JitVal> ExpectedEdge<OT, VT> in(
				ExpectedOp<OT> op, Function<? super OT, JitVal> valGetter,
				Predicate<JitOp> opPredicate, ExpectedVal<VT> v) {

			return new ExpectedEdge<>(Dir.IN, op, valGetter, val -> {
				for (ValUse use : val.uses()) {
					if (opPredicate.test(use.op())) {
						return use.op();
					}
				}
				throw new NoSuchElementException();
			}, v);
		}

		public static <VT extends JitOutVar, OT extends JitDefOp> ExpectedEdge<OT, VT> out(
				ExpectedVal<VT> v, ExpectedOp<OT> op) {

			return new ExpectedEdge<>(Dir.OUT, op, JitDefOp::out, JitOutVar::definition, v);
		}

		public static <VT extends JitVal> ExpectedEdge<JitPhiOp, VT> phi(ExpectedOp<JitPhiOp> op,
				Predicate<BlockFlow> flowPredicate, ExpectedVal<VT> v) {

			return in(op, phi -> {
				for (Entry<BlockFlow, JitVal> ent : phi.options().entrySet()) {
					if (flowPredicate.test(ent.getKey())) {
						return ent.getValue();
					}
				}
				throw new NoSuchElementException();
			}, jitOp -> jitOp instanceof JitPhiOp, v);
		}

		public VT getActualVal(JitOp jitOp) {
			try {
				return Objects.requireNonNull(v.cls.cast(valGetter.apply(op.cls.cast(jitOp))));
			}
			catch (Exception e) {
				throw new AssertionError(
					"Could not get actual value for " + this + " where op=" + jitOp, e);
			}
		}

		public OT getActualOp(JitVal jitVal) {
			try {
				return Objects.requireNonNull(op.cls.cast(opGetter.apply(v.cls.cast(jitVal))));
			}
			catch (Exception e) {
				throw new AssertionError(
					"Could not get actual op for " + this + " where value=" + jitVal, e);
			}
		}
	}

	record OpMatch(ExpectedOp<?> eOp, JitOp aOp) {}

	record ValMatch(ExpectedVal<?> eVal, JitVal aVal) {}

	public static class ExpectationsAsserter {
		private final List<ExpectedOp<?>> eOps;
		private final Set<ExpectedVal<?>> eVals;
		private final Set<ExpectedEdge<?, ?>> eEdges;
		private final JitDataFlowModel dfm;

		private final SleighLanguage language;

		private final Deque<OpMatch> opQueue = new LinkedList<>();
		private final Deque<ValMatch> valQueue = new LinkedList<>();
		private final BidiMap<JitOp, ExpectedOp<?>> opsMap = new DualHashBidiMap<>();
		private final BidiMap<JitVal, ExpectedVal<?>> valsMap = new DualHashBidiMap<>();
		private final Set<ExpectedEdge<?, ?>> edgesVisitedO2V = new HashSet<>();
		private final Set<ExpectedEdge<?, ?>> edgesVisitedV2O = new HashSet<>();
		private final Map<ExpectedOp<?>, Set<ExpectedEdge<?, ?>>> edgesO2V = new HashMap<>();
		private final Map<ExpectedVal<?>, Set<ExpectedEdge<?, ?>>> edgesV2O = new HashMap<>();

		public ExpectationsAsserter(List<ExpectedOp<?>> eOps, Set<ExpectedVal<?>> eVals,
				Set<ExpectedEdge<?, ?>> eEdges, JitAnalysisContext context, JitDataFlowModel dfm) {
			this.eOps = eOps;
			this.eEdges = eEdges;
			this.eVals = eVals;
			this.dfm = dfm;

			this.language = context.getLanguage();

			// Queue only those matching the listing
			// synthetic ones should be at end of list, but must be included
			List<PcodeOp> ops = context.getPassage().getCode();
			for (int i = 0; i < ops.size(); i++) {
				JitOp aOp = dfm.getJitOp(ops.get(i));
				ExpectedOp<?> eOp = eOps.get(i);
				opQueue.add(new OpMatch(eOp, aOp));
			}

			for (ExpectedEdge<?, ?> ee : eEdges) {
				edgesO2V.computeIfAbsent(ee.op, e -> new HashSet<>()).add(ee);
				edgesV2O.computeIfAbsent(ee.v, e -> new HashSet<>()).add(ee);
			}
		}

		public void assertOpMatch(OpMatch match) {
			ExpectedOp<?> ePrior = opsMap.get(match.aOp);
			JitOp aPrior = opsMap.getKey(match.eOp);
			if (ePrior != null || aPrior != null) {
				assertSame(ePrior, match.eOp);
				assertSame(aPrior, match.aOp);
				return;
			}

			assertTrue("Expected op of type %s but got %s".formatted(match.eOp.cls, match.aOp),
				match.eOp.cls.isInstance(match.aOp));
			opsMap.put(match.aOp, match.eOp);

			Set<JitVal> aAllIn = Set.copyOf(match.aOp.inputs());
			Set<JitVal> aAllOut =
				match.aOp instanceof JitDefOp defOp ? Set.of(defOp.out()) : Set.of();
			Set<JitVal> eAllIn = new HashSet<>();
			Set<JitVal> eAllOut = new HashSet<>();
			for (ExpectedEdge<?, ?> ee : edgesO2V.getOrDefault(match.eOp, Set.of())) {
				edgesVisitedO2V.add(ee);
				JitVal aVal = ee.getActualVal(match.aOp);
				valQueue.add(new ValMatch(ee.v, aVal));
				(switch (ee.dir) {
					case IN -> eAllIn;
					case OUT -> eAllOut;
				}).add(aVal);
			}
			assertEquals("Values input to %s do not match".formatted(match.aOp), eAllIn, aAllIn);
			assertEquals("Value output from %s does not match".formatted(match.aOp),
				eAllOut, aAllOut);
		}

		private String varnodeToString(JitVarnodeVar vv) {
			if (vv.varnode().isUnique()) {
				return "$U";
			}
			return vv.varnode().toString(language);
		}

		public void assertValMatch(ValMatch match) {
			ExpectedVal<?> ePrior = valsMap.get(match.aVal);
			JitVal aPrior = valsMap.getKey(match.eVal);
			if (ePrior != null || aPrior != null) {
				assertSame(ePrior, match.eVal);
				assertSame(aPrior, match.aVal);
				return;
			}

			assertTrue(match.eVal.cls.isInstance(match.aVal));
			valsMap.put(match.aVal, match.eVal);

			assertEquals(match.eVal.size, match.aVal.size());
			switch (match.aVal) {
				case JitConstVal cv -> assertEquals(match.eVal.str, cv.value().toString(16));
				case JitVarnodeVar vv -> assertEquals(match.eVal.str, varnodeToString(vv));
				default -> throw new AssertionFailedError("Unrecognized val type: " + match.aVal);
			}

			Set<JitOp> aAllUses =
				match.aVal.uses().stream().map(ValUse::op).collect(Collectors.toSet());
			Set<JitOp> aAllDefs =
				match.aVal instanceof JitOutVar out ? Set.of(out.definition()) : Set.of();
			Set<JitOp> eAllUses = new HashSet<>();
			Set<JitOp> eAllDefs = new HashSet<>();
			for (ExpectedEdge<?, ?> ee : edgesV2O.getOrDefault(match.eVal, Set.of())) {
				edgesVisitedV2O.add(ee);
				JitOp aOp = ee.getActualOp(match.aVal);
				opQueue.add(new OpMatch(ee.op, aOp));
				(switch (ee.dir) {
					case IN -> eAllUses;
					case OUT -> eAllDefs;
				}).add(aOp);
			}
			assertEquals("Ops using %s do not match".formatted(match.aVal), eAllUses, aAllUses);
			assertEquals("Op defining %s does not match".formatted(match.aVal), eAllDefs, aAllDefs);
		}

		public void processQueues() {
			while (!opQueue.isEmpty() || !valQueue.isEmpty()) {
				while (!opQueue.isEmpty()) {
					assertOpMatch(opQueue.poll());
				}
				while (!valQueue.isEmpty()) {
					assertValMatch(valQueue.poll());
				}
			}
		}

		public void assertEquivalence() {
			processQueues();

			assertEquals(opsMap.keySet(), dfm.allOps());
			assertEquals(valsMap.keySet(), dfm.allValues());

			assertEquals("Not all expected ops were found.", Set.copyOf(eOps),
				Set.copyOf(opsMap.values()));
			assertEquals("Not all expected values were found.", eVals,
				Set.copyOf(valsMap.values()));

			assertEquals(eEdges, edgesVisitedO2V);
			assertEquals(eEdges, edgesVisitedV2O);
		}
	}

	public static void assertDfmExpectations(List<ExpectedOp<?>> eOps, Set<ExpectedVal<?>> eVals,
			Set<ExpectedEdge<?, ?>> eEdges, JitAnalysisContext context, JitDataFlowModel dfm) {
		new ExpectationsAsserter(eOps, eVals, eEdges, context, dfm).assertEquivalence();
	}

	@Test
	public void testOnlyConstant() throws Exception {
		SleighLanguage language = SleighLanguageHelper.getMockBE64Language();

		PcodeProgram program = SleighProgramCompiler.compileProgram(language, "test", """
				r0 = 0x5678;
				goto 0x1234;
				""", PcodeUseropLibrary.NIL);
		JitAnalysisContext context = makeContext(program);
		JitControlFlowModel cfm = new JitControlFlowModel(context);
		JitDataFlowModel dfm = new JitDataFlowModel(context, cfm);

		ExpectedOp<JitCopyOp> eCopy = new ExpectedOp<>(JitCopyOp.class);
		ExpectedOp<JitBranchOp> eBranch = new ExpectedOp<>(JitBranchOp.class);
		ExpectedVal<JitConstVal> e5678 = new ExpectedVal<>(JitConstVal.class, "5678", 8);
		ExpectedVal<JitOutVar> eR0 = new ExpectedVal<>(JitOutVar.class, "r0", 8);
		assertDfmExpectations(
			List.of(
				eCopy,
				eBranch),
			Set.of(e5678, eR0),
			Set.of(
				ExpectedEdge.in(eCopy, JitCopyOp::u, op -> true, e5678),
				ExpectedEdge.out(eR0, eCopy)),
			context, dfm);
	}

	@Test
	public void testInput() throws Exception {
		SleighLanguage language = SleighLanguageHelper.getMockBE64Language();

		PcodeProgram program = SleighProgramCompiler.compileProgram(language, "test", """
				r0 = r1;
				goto 0x1234;
				""", PcodeUseropLibrary.NIL);
		JitAnalysisContext context = makeContext(program);
		JitControlFlowModel cfm = new JitControlFlowModel(context);
		JitDataFlowModel dfm = new JitDataFlowModel(context, cfm);

		ExpectedOp<JitCopyOp> eCopy = new ExpectedOp<>(JitCopyOp.class);
		ExpectedOp<JitBranchOp> eBranch = new ExpectedOp<>(JitBranchOp.class);
		ExpectedOp<JitPhiOp> ePhi = new ExpectedOp<>(JitPhiOp.class);
		ExpectedVal<JitOutVar> eR0 = new ExpectedVal<>(JitOutVar.class, "r0", 8);
		ExpectedVal<JitOutVar> eR1 = new ExpectedVal<>(JitOutVar.class, "r1", 8);
		ExpectedVal<JitInputVar> eR1In = new ExpectedVal<>(JitInputVar.class, "r1", 8);
		assertDfmExpectations(
			List.of(
				eCopy,
				eBranch,
				ePhi),
			Set.of(eR1In, eR1, eR0),
			Set.of(
				ExpectedEdge.phi(ePhi, flow -> true, eR1In),
				ExpectedEdge.out(eR1, ePhi),
				ExpectedEdge.in(eCopy, JitCopyOp::u, op -> true, eR1),
				ExpectedEdge.out(eR0, eCopy)),
			context, dfm);
	}

	@Test
	public void testThroughReg() throws Exception {
		SleighLanguage language = SleighLanguageHelper.getMockBE64Language();

		PcodeProgram program = SleighProgramCompiler.compileProgram(language, "test", """
				r1 = 0x5678;
				r0 = r1;
				goto 0x1234;
				""", PcodeUseropLibrary.NIL);
		JitAnalysisContext context = makeContext(program);
		JitControlFlowModel cfm = new JitControlFlowModel(context);
		JitDataFlowModel dfm = new JitDataFlowModel(context, cfm);

		// Just checking that the r1 used is the same as the r1 defined above
		ExpectedOp<JitCopyOp> eCopy1 = new ExpectedOp<>(JitCopyOp.class);
		ExpectedOp<JitCopyOp> eCopy2 = new ExpectedOp<>(JitCopyOp.class);
		ExpectedOp<JitBranchOp> eBranch = new ExpectedOp<>(JitBranchOp.class);
		ExpectedVal<JitConstVal> e5678 = new ExpectedVal<>(JitConstVal.class, "5678", 8);
		ExpectedVal<JitOutVar> eR1 = new ExpectedVal<>(JitOutVar.class, "r1", 8);
		ExpectedVal<JitOutVar> eR0 = new ExpectedVal<>(JitOutVar.class, "r0", 8);
		assertDfmExpectations(
			List.of(eCopy1,
				eCopy2,
				eBranch),
			Set.of(e5678, eR1, eR0),
			Set.of(
				ExpectedEdge.in(eCopy1, JitCopyOp::u, op -> true, e5678),
				ExpectedEdge.out(eR1, eCopy1),
				ExpectedEdge.in(eCopy2, JitCopyOp::u, op -> true, eR1),
				ExpectedEdge.out(eR0, eCopy2)),
			context, dfm);
	}

	@Test
	public void testThroughUnique() throws Exception {
		SleighLanguage language = SleighLanguageHelper.getMockBE64Language();

		PcodeProgram program = SleighProgramCompiler.compileProgram(language, "test", """
				temp:8 = 0x5678;
				r0 = temp;
				goto 0x1234;
				""", PcodeUseropLibrary.NIL);
		JitAnalysisContext context = makeContext(program);
		JitControlFlowModel cfm = new JitControlFlowModel(context);
		JitDataFlowModel dfm = new JitDataFlowModel(context, cfm);

		ExpectedOp<JitCopyOp> eCopy1 = new ExpectedOp<>(JitCopyOp.class);
		ExpectedOp<JitCopyOp> eCopy2 = new ExpectedOp<>(JitCopyOp.class);
		ExpectedOp<JitBranchOp> eBranch = new ExpectedOp<>(JitBranchOp.class);
		ExpectedVal<JitConstVal> e5678 = new ExpectedVal<>(JitConstVal.class, "5678", 8);
		ExpectedVal<JitOutVar> eTemp = new ExpectedVal<>(JitOutVar.class, "$U", 8);
		ExpectedVal<JitOutVar> eR0 = new ExpectedVal<>(JitOutVar.class, "r0", 8);
		assertDfmExpectations(
			List.of(eCopy1,
				eCopy2,
				eBranch),
			Set.of(e5678, eTemp, eR0),
			Set.of(
				ExpectedEdge.in(eCopy1, JitCopyOp::u, op -> true, e5678),
				ExpectedEdge.out(eTemp, eCopy1),
				ExpectedEdge.in(eCopy2, JitCopyOp::u, op -> true, eTemp),
				ExpectedEdge.out(eR0, eCopy2)),
			context, dfm);
	}

	@Test
	public void testInputLoop() throws Exception {
		SleighLanguage language = SleighLanguageHelper.getMockBE64Language();

		PcodeProgram program = SleighProgramCompiler.compileProgram(language, "test", """
				<loop>
				r0 = r1;
				goto <loop>;
				""", PcodeUseropLibrary.NIL);
		JitAnalysisContext context = makeContext(program);
		JitControlFlowModel cfm = new JitControlFlowModel(context);
		JitDataFlowModel dfm = new JitDataFlowModel(context, cfm);

		ExpectedOp<JitCopyOp> eCopy = new ExpectedOp<>(JitCopyOp.class);
		ExpectedOp<JitBranchOp> eBranch = new ExpectedOp<>(JitBranchOp.class);
		ExpectedOp<JitPhiOp> ePhi = new ExpectedOp<>(JitPhiOp.class);
		ExpectedVal<JitOutVar> eR0 = new ExpectedVal<>(JitOutVar.class, "r0", 8);
		ExpectedVal<JitOutVar> eR1 = new ExpectedVal<>(JitOutVar.class, "r1", 8);
		ExpectedVal<JitInputVar> eR1In = new ExpectedVal<>(JitInputVar.class, "r1", 8);
		assertDfmExpectations(
			List.of(
				eCopy,
				eBranch,
				ePhi),
			Set.of(eR1In, eR1, eR0),
			Set.of(
				ExpectedEdge.phi(ePhi, flow -> flow.from() == null, eR1In),
				ExpectedEdge.phi(ePhi, flow -> flow.from() != null, eR1),
				ExpectedEdge.out(eR1, ePhi),
				ExpectedEdge.in(eCopy, JitCopyOp::u, opType(JitCopyOp.class), eR1),
				ExpectedEdge.out(eR0, eCopy)),
			context, dfm);
	}

	@Test
	public void testOnlyConstLoop() throws Exception {
		SleighLanguage language = SleighLanguageHelper.getMockBE64Language();

		PcodeProgram program = SleighProgramCompiler.compileProgram(language, "test", """
				r1 = 0x5678;
				<loop>
				r0 = r1;
				goto <loop>;
				""", PcodeUseropLibrary.NIL);
		JitAnalysisContext context = makeContext(program);
		JitControlFlowModel cfm = new JitControlFlowModel(context);
		JitDataFlowModel dfm = new JitDataFlowModel(context, cfm);

		ExpectedOp<JitCopyOp> eCopy1 = new ExpectedOp<>(JitCopyOp.class);
		ExpectedOp<JitCopyOp> eCopy2 = new ExpectedOp<>(JitCopyOp.class);
		ExpectedOp<JitBranchOp> eBranch = new ExpectedOp<>(JitBranchOp.class);
		ExpectedOp<JitPhiOp> ePhi = new ExpectedOp<>(JitPhiOp.class);
		ExpectedVal<JitConstVal> e5678 = new ExpectedVal<>(JitConstVal.class, "5678", 8);
		ExpectedVal<JitOutVar> eR1_1 = new ExpectedVal<>(JitOutVar.class, "r1", 8);
		ExpectedVal<JitOutVar> eR1_2 = new ExpectedVal<>(JitOutVar.class, "r1", 8);
		ExpectedVal<JitOutVar> eR0 = new ExpectedVal<>(JitOutVar.class, "r0", 8);
		assertDfmExpectations(
			List.of(
				eCopy1,
				eCopy2,
				eBranch,
				ePhi),
			Set.of(e5678, eR1_1, eR1_2, eR0),
			Set.of(
				ExpectedEdge.in(eCopy1, JitCopyOp::u, opType(JitCopyOp.class), e5678),
				ExpectedEdge.out(eR1_1, eCopy1),
				ExpectedEdge.phi(ePhi, flow -> flow.from().start().getTime() == 0, eR1_1),
				ExpectedEdge.phi(ePhi, flow -> flow.from().start().getTime() == 1, eR1_2),
				ExpectedEdge.out(eR1_2, ePhi),
				ExpectedEdge.in(eCopy2, JitCopyOp::u, opType(JitCopyOp.class), eR1_2),
				ExpectedEdge.out(eR0, eCopy2)),
			context, dfm);
	}

	@Test
	public void testForLoop() throws Exception {
		SleighLanguage language = SleighLanguageHelper.getMockBE64Language();

		// Want to see r0 as input or as previous iteration's value
		PcodeProgram program = SleighProgramCompiler.compileProgram(language, "test", """
				<loop>
				r0 = r0 - 1;
				if r0 > 0 goto <loop>;
				goto 0x1234;
				""", PcodeUseropLibrary.NIL);
		JitAnalysisContext context = makeContext(program);
		JitControlFlowModel cfm = new JitControlFlowModel(context);
		JitDataFlowModel dfm = new JitDataFlowModel(context, cfm);

		ExpectedOp<JitPhiOp> ePhi = new ExpectedOp<>(JitPhiOp.class);
		ExpectedOp<JitIntSubOp> eIntSub = new ExpectedOp<>(JitIntSubOp.class);
		ExpectedOp<JitIntLessOp> eIntLess = new ExpectedOp<>(JitIntLessOp.class);
		ExpectedOp<JitCBranchOp> eCBranch = new ExpectedOp<>(JitCBranchOp.class);
		ExpectedOp<JitBranchOp> eBranch = new ExpectedOp<>(JitBranchOp.class);
		ExpectedVal<JitConstVal> e1 = new ExpectedVal<>(JitConstVal.class, "1", 8);
		ExpectedVal<JitOutVar> eR0_1 = new ExpectedVal<>(JitOutVar.class, "r0", 8);
		ExpectedVal<JitInputVar> eR0In = new ExpectedVal<>(JitInputVar.class, "r0", 8);
		ExpectedVal<JitOutVar> eU = new ExpectedVal<>(JitOutVar.class, "$U", 1);
		ExpectedVal<JitOutVar> eR0_2 = new ExpectedVal<>(JitOutVar.class, "r0", 8);
		ExpectedVal<JitConstVal> e0 = new ExpectedVal<>(JitConstVal.class, "0", 8);
		assertDfmExpectations(
			List.of(
				eIntSub,
				eIntLess,
				eCBranch,
				eBranch,
				ePhi),
			Set.of(e1, eR0_1, eR0In, eU, eR0_2, e0),
			Set.of(
				ExpectedEdge.phi(ePhi, flow -> flow.from() == null, eR0In),
				ExpectedEdge.phi(ePhi, flow -> flow.from() != null, eR0_2),
				ExpectedEdge.out(eR0_1, ePhi),
				ExpectedEdge.in(eIntSub, JitIntSubOp::l, opType(JitIntSubOp.class), eR0_1),
				ExpectedEdge.in(eIntSub, JitIntSubOp::r, opType(JitIntSubOp.class), e1),
				ExpectedEdge.out(eR0_2, eIntSub),
				ExpectedEdge.in(eIntLess, JitIntLessOp::l, opType(JitIntLessOp.class), e0),
				ExpectedEdge.in(eIntLess, JitIntLessOp::r, opType(JitIntLessOp.class), eR0_2),
				ExpectedEdge.out(eU, eIntLess),
				ExpectedEdge.in(eCBranch, JitCBranchOp::cond, opType(JitCBranchOp.class), eU)),
			context, dfm);
	}

	public static class MyLibrary extends AnnotatedPcodeUseropLibrary<Object> {
		@PcodeUserop(functional = true)
		public void v_op0() {
		}

		@PcodeUserop(functional = true)
		public void v_op1(long p1) {
		}

		@PcodeUserop(functional = true)
		public long l_op0() {
			return 0;
		}

		@PcodeUserop(functional = true)
		public long l_op1(long p1) {
			return p1;
		}
	}

	public static final PcodeUseropLibrary<?> MY_LIB = new MyLibrary();

	@Test
	public void testCallOtherVoidOp0() throws Exception {
		SleighLanguage language = SleighLanguageHelper.getMockBE64Language();

		JitAnalysisContext context = makeContext(language, """
				v_op0();
				goto 0x1234;
				""", MY_LIB);
		JitControlFlowModel cfm = new JitControlFlowModel(context);
		JitDataFlowModel dfm = new JitDataFlowModel(context, cfm);
		ExpectedOp<JitCallOtherOp> eCallOther = new ExpectedOp<>(JitCallOtherOp.class);
		ExpectedOp<JitBranchOp> eBranch = new ExpectedOp<>(JitBranchOp.class);
		assertDfmExpectations(
			List.of(
				eCallOther,
				eBranch),
			Set.of(),
			Set.of(),
			context, dfm);
	}

	@Test
	public void testCallOtherVoidOp1() throws Exception {
		SleighLanguage language = SleighLanguageHelper.getMockBE64Language();

		JitAnalysisContext context = makeContext(language, """
				v_op1(r0);
				goto 0x1234;
				""", MY_LIB);
		JitControlFlowModel cfm = new JitControlFlowModel(context);
		JitDataFlowModel dfm = new JitDataFlowModel(context, cfm);
		ExpectedOp<JitCallOtherOp> eCallOther = new ExpectedOp<>(JitCallOtherOp.class);
		ExpectedOp<JitBranchOp> eBranch = new ExpectedOp<>(JitBranchOp.class);
		ExpectedOp<JitPhiOp> ePhi = new ExpectedOp<>(JitPhiOp.class);
		ExpectedVal<JitInputVar> eR0In = new ExpectedVal<>(JitInputVar.class, "r0", 8);
		ExpectedVal<JitOutVar> eR0 = new ExpectedVal<>(JitOutVar.class, "r0", 8);
		assertDfmExpectations(
			List.of(
				eCallOther,
				eBranch,
				ePhi),
			Set.of(eR0In, eR0),
			Set.of(
				ExpectedEdge.phi(ePhi, flow -> true, eR0In),
				ExpectedEdge.out(eR0, ePhi),
				ExpectedEdge.in(eCallOther, otherArg(0), opType(JitCallOtherOp.class), eR0)),
			context, dfm);
	}

	@Test
	public void testCallOtherLongOp0() throws Exception {
		SleighLanguage language = SleighLanguageHelper.getMockBE64Language();

		JitAnalysisContext context = makeContext(language, """
				r1 = l_op0();
				goto 0x1234;
				""", MY_LIB);
		JitControlFlowModel cfm = new JitControlFlowModel(context);
		JitDataFlowModel dfm = new JitDataFlowModel(context, cfm);
		ExpectedOp<JitCallOtherDefOp> eCallOther = new ExpectedOp<>(JitCallOtherDefOp.class);
		ExpectedOp<JitBranchOp> eBranch = new ExpectedOp<>(JitBranchOp.class);
		ExpectedVal<JitOutVar> eR1 = new ExpectedVal<>(JitOutVar.class, "r1", 8);
		assertDfmExpectations(
			List.of(
				eCallOther,
				eBranch),
			Set.of(eR1),
			Set.of(
				ExpectedEdge.out(eR1, eCallOther)),
			context, dfm);
	}

	@Test
	public void testCallOtherLongOp1() throws Exception {
		SleighLanguage language = SleighLanguageHelper.getMockBE64Language();

		JitAnalysisContext context = makeContext(language, """
				r1 = l_op1(r0);
				goto 0x1234;
				""", MY_LIB);
		JitControlFlowModel cfm = new JitControlFlowModel(context);
		JitDataFlowModel dfm = new JitDataFlowModel(context, cfm);
		ExpectedOp<JitCallOtherDefOp> eCallOther = new ExpectedOp<>(JitCallOtherDefOp.class);
		ExpectedOp<JitBranchOp> eBranch = new ExpectedOp<>(JitBranchOp.class);
		ExpectedOp<JitPhiOp> ePhi = new ExpectedOp<>(JitPhiOp.class);
		ExpectedVal<JitInputVar> eR0In = new ExpectedVal<>(JitInputVar.class, "r0", 8);
		ExpectedVal<JitOutVar> eR0 = new ExpectedVal<>(JitOutVar.class, "r0", 8);
		ExpectedVal<JitOutVar> eR1 = new ExpectedVal<>(JitOutVar.class, "r1", 8);
		assertDfmExpectations(
			List.of(
				eCallOther,
				eBranch,
				ePhi),
			Set.of(eR0In, eR0, eR1),
			Set.of(
				ExpectedEdge.phi(ePhi, flow -> true, eR0In),
				ExpectedEdge.out(eR0, ePhi),
				ExpectedEdge.in(eCallOther, otherArg(0), opType(JitCallOtherDefOp.class), eR0),
				ExpectedEdge.out(eR1, eCallOther)),
			context, dfm);
	}

	/**
	 * NOTE: cat, subpiece, etc., do not currrently have much meaning except to indicate a
	 * dependence. At one point these "synthetic" ops were meant to be translated into JVM bytecode,
	 * but instead, variable accesses are coalesced during allocation/assignment, and then
	 * sub-accesses are encoded as such.
	 */
}
