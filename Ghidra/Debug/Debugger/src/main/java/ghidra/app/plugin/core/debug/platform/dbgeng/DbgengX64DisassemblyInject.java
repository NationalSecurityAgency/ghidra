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
package ghidra.app.plugin.core.debug.platform.dbgeng;

import java.math.BigInteger;

import ghidra.app.plugin.core.debug.disassemble.*;
import ghidra.app.plugin.core.debug.disassemble.DisassemblyInjectInfo.PlatformInfo;
import ghidra.app.plugin.core.debug.platform.dbgeng.DbgengDebuggerPlatformOpinion.Mode;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.*;
import ghidra.program.util.ProgramContextImpl;
import ghidra.trace.model.Trace;
import ghidra.trace.model.guest.TracePlatform;
import ghidra.trace.model.thread.TraceThread;

@DisassemblyInjectInfo(
	platforms = {
		@PlatformInfo(langID = "x86:LE:64:default", compilerID = "windows"),
		@PlatformInfo(langID = "x86:LE:64:default", compilerID = "clangwindows"),
	})
public class DbgengX64DisassemblyInject implements DisassemblyInject {
	@Override
	public void pre(PluginTool tool, TraceDisassembleCommand command, TracePlatform platform,
			long snap, TraceThread thread, AddressSetView startSet, AddressSetView restricted) {
		AddressRange first = startSet.getFirstRange();
		if (first == null) {
			return;
		}
		Trace trace = platform.getTrace();

		Mode mode = Mode.computeFor(tool, trace, first.getMinAddress(), snap);
		if (mode == Mode.UNK) {
			return;
		}

		Language language = platform.getLanguage();
		Register longModeReg = language.getRegister("longMode");
		Register addrsizeReg = language.getRegister("addrsize");
		Register opsizeReg = language.getRegister("opsize");
		ProgramContextImpl context = new ProgramContextImpl(language);
		language.applyContextSettings(context);
		RegisterValue ctxVal = context.getDisassemblyContext(first.getMinAddress());
		command.setInitialContext(switch (mode) {
			case X64 -> ctxVal
					.assign(longModeReg, BigInteger.ONE)
					.assign(addrsizeReg, BigInteger.TWO)
					.assign(opsizeReg, BigInteger.ONE);
			case X86 -> ctxVal
					.assign(longModeReg, BigInteger.ZERO)
					.assign(addrsizeReg, BigInteger.ONE)
					.assign(opsizeReg, BigInteger.ONE);
			default -> throw new AssertionError();
		});
	}
}
