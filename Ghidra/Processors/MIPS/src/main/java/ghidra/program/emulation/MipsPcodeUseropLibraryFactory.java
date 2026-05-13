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
package ghidra.program.emulation;

import java.math.BigInteger;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.pcode.emu.DefaultPcodeThread.PcodeThreadExecutor;
import ghidra.pcode.exec.*;
import ghidra.pcode.exec.PcodeUseropLibraryFactory.UseropLibrary;
import ghidra.program.model.lang.*;

@UseropLibrary("mips")
public class MipsPcodeUseropLibraryFactory implements PcodeUseropLibraryFactory {
	@Override
	public <T> PcodeUseropLibrary<T> create(SleighLanguage language,
			PcodeArithmetic<T> arithmetic) {
		return new MipsPcodeUseropLibrary<>(language);
	}

	public static class MipsPcodeUseropLibrary<T> extends AnnotatedPcodeUseropLibrary<T> {
		private final RegisterValue mode0;
		private final RegisterValue mode1;

		public MipsPcodeUseropLibrary(Language language) {
			Register isaModeReg = language.getRegister("ISA_MODE");
			if (isaModeReg != null) {
				mode0 = new RegisterValue(isaModeReg, BigInteger.ZERO);
				mode1 = new RegisterValue(isaModeReg, BigInteger.ONE);
			}
			else {
				mode0 = null;
				mode1 = null;
			}
		}

		@PcodeUserop(modifiesContext = true)
		public void setISAMode(@OpExecutor PcodeExecutor<T> exec, boolean mode) {
			if (!(exec instanceof PcodeThreadExecutor<T> tExec)) {
				return;
			}
			tExec.getThread().overrideContext(mode ? mode1 : mode0);
		}
	}
}
