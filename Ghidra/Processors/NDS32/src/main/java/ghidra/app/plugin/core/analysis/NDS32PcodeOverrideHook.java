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
package ghidra.app.plugin.core.analysis;

import ghidra.app.decompiler.inline.IfcDialect;
import ghidra.app.decompiler.inline.IfcPropertyMapPcodeOverrideHook;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.listing.Program;

/**
 * Decompile-time pcode-override hook for NDS32 IFC.  Combines the
 * generic {@link IfcPropertyMapPcodeOverrideHook} dispatch logic with
 * the NDS32 dialect (mnemonics, register names).  Discovered by
 * {@link ghidra.util.classfinder.ClassSearcher}; no manual
 * registration needed.
 */
public class NDS32PcodeOverrideHook extends IfcPropertyMapPcodeOverrideHook {

	private static final IfcDialect DIALECT = IfcDialect.builder()
			.ifretMnemonics("ifret", "ifret16")
			.ifcallMnemonics("ifcall", "ifcall9")
			.ex9DispatchMnemonics("ex9.it", "ex9.it5")
			.passiveTerminalMnemonics("pop25", "ret", "jr")
			.ifcOnRegister("IFC_ON")
			.ifcLpRegister("ifc_lp")
			.maxBodyInsns(600)
			.build();

	private static final Processor NDS32 =
		Processor.findOrPossiblyCreateProcessor("NDS32");

	@Override
	protected IfcDialect getDialect() {
		return DIALECT;
	}

	@Override
	protected boolean isApplicableProcessor(Program program) {
		return program.getLanguage().getProcessor().equals(NDS32);
	}
}
