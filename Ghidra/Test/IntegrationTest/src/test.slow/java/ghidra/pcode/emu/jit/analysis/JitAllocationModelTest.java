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

import static org.junit.Assert.assertEquals;

import java.util.Comparator;
import java.util.List;
import java.util.stream.Stream;

import org.junit.Test;

import generic.Unique;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.app.plugin.processors.sleigh.SleighLanguageHelper;
import ghidra.pcode.emu.jit.AbstractJitTest;
import ghidra.pcode.emu.jit.analysis.JitAllocationModel.MultiLocalVarHandler;
import ghidra.pcode.emu.jit.analysis.JitType.DoubleJitType;
import ghidra.pcode.emu.jit.var.JitVar;
import ghidra.pcode.emu.jit.var.JitVarnodeVar;
import ghidra.pcode.exec.*;
import junit.framework.AssertionFailedError;

public class JitAllocationModelTest extends AbstractJitTest {
	public static <T> Stream<T> filterByType(Stream<?> in, Class<T> cls) {
		return in.<T> mapMulti((e, d) -> {
			if (cls.isInstance(e)) {
				d.accept(cls.cast(e));
			}
		});
	}

	public static Stream<JitVarnodeVar> varnodeVars(JitDataFlowModel dfm) {
		return filterByType(dfm.allValues().stream(), JitVarnodeVar.class);
	}

	@Test
	public void testMultiPrecisionInt() throws Exception {
		SleighLanguage language = SleighLanguageHelper.getMockBE64Language();

		PcodeProgram program = SleighProgramCompiler.compileProgram(language, "test", """
				temp:32 = zext(0x1234:2);
				goto 0x1234;
				""", PcodeUseropLibrary.NIL);

		JitAnalysisContext context = makeContext(program);
		JitControlFlowModel cfm = new JitControlFlowModel(context);
		JitDataFlowModel dfm = new JitDataFlowModel(context, cfm);
		JitVarScopeModel vsm = new JitVarScopeModel(cfm, dfm);
		JitTypeModel tm = new JitTypeModel(dfm);
		JitAllocationModel am = new JitAllocationModel(context, dfm, vsm, tm);

		JitVarnodeVar tempVar = Unique.assertOne(varnodeVars(dfm)
				.filter(v -> v.varnode().isUnique()));

		if (!(am.getHandler(tempVar) instanceof MultiLocalVarHandler handler)) {
			throw new AssertionFailedError();
		}

		/**
		 * TODO: Might like to assert more details, but this mp-int aspect of the JIT-based emulator
		 * is still a work in progress.
		 */
		assertEquals(8, handler.parts().size());
	}

	@Test
	public void testVarnodeReuse() throws Exception {
		SleighLanguage language = SleighLanguageHelper.getMockBE64Language();

		PcodeProgram program = SleighProgramCompiler.compileProgram(language, "test", """
				r0 = r1 + r2;
				r0 = r0 f+ r2;
				r0 = r0 f+ r2;
				goto 0x1234;
				""", PcodeUseropLibrary.NIL);

		JitAnalysisContext context = makeContext(program);
		JitControlFlowModel cfm = new JitControlFlowModel(context);
		JitDataFlowModel dfm = new JitDataFlowModel(context, cfm);
		JitVarScopeModel vsm = new JitVarScopeModel(cfm, dfm);
		JitTypeModel tm = new JitTypeModel(dfm);
		JitAllocationModel am = new JitAllocationModel(context, dfm, vsm, tm);

		List<JitVarnodeVar> r0Vars = varnodeVars(dfm)
				.filter(v -> v.varnode().toString(language).equals("r0"))
				.sorted(Comparator.comparing(JitVar::id))
				.toList();

		/**
		 * NOTE: Variables are coalesced by varnode, so all of these will receive the same handler,
		 * and so will all have the same type. There being two float ops will cause the type and
		 * allocation models to choose F8 for that handler.
		 */
		assertEquals(List.of(DoubleJitType.F8, DoubleJitType.F8, DoubleJitType.F8),
			r0Vars.stream().map(v -> am.getHandler(v).type()).toList());
	}
}
