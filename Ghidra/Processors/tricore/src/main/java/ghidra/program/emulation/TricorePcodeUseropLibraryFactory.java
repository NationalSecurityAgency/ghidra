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

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.pcode.exec.*;
import ghidra.pcode.exec.PcodeUseropLibraryFactory.UseropLibrary;

@UseropLibrary("tricore")
public class TricorePcodeUseropLibraryFactory implements PcodeUseropLibraryFactory {
	@Override
	public <T> PcodeUseropLibrary<T> create(SleighLanguage language,
			PcodeArithmetic<T> arithmetic) {
		return new TricorePcodeUseropLibrary<>(language);
	}

	public static class TricorePcodeUseropLibrary<T> extends AnnotatedPcodeUseropLibrary<T> {
		public TricorePcodeUseropLibrary(SleighLanguage language) {
			SleighPcodeUseropDefinition.Factory factory =
				new SleighPcodeUseropDefinition.Factory(language);

			putOp(factory.define("saveCallerState")
					.params("_fcx", "_lcx", "_pcxi")
					.body(args -> """
							local ea:4 = ((FCX & 0xffff0000) << 12) | ((FCX & 0xffff) << 6);
							local new_fcx:4 = * ea;
							if (new_fcx != 0) goto <skip_init>;
							  new_fcx = FCX + 1;
							<skip_init>
							*  ea       = PCXI;
							* (ea +  4) = PSW;
							* (ea +  8) = a10;
							* (ea + 12) = a11;
							* (ea + 16) = d8;
							* (ea + 20) = d9;
							* (ea + 24) = d10;
							* (ea + 28) = d11;
							* (ea + 32) = a12;
							* (ea + 36) = a13;
							* (ea + 40) = a14;
							* (ea + 44) = a15;
							* (ea + 48) = d12;
							* (ea + 52) = d13;
							* (ea + 56) = d14;
							* (ea + 60) = d15;
							PCXI = (PCXI & 0xfff00000) | (    FCX & 0x000fffff);
							FCX =  (FCX  & 0xfff00000) | (new_fcx & 0x000fffff);
							""")
					.build());
			putOp(factory.define("restoreCallerState")
					.params("_fcx", "_lcx", "_pcxi")
					.body(args -> """
							local ea:4 = ((PCXI & 0xffff0000) << 12) | ((PCXI & 0x0000ffff) << 6);
							local savePCXI = PCXI;
							PCXI = *  ea;
							PSW  = * (ea +  4);
							a10  = * (ea +  8);
							a11  = * (ea + 12);
							d8   = * (ea + 16);
							d9   = * (ea + 20);
							d10  = * (ea + 24);
							d11  = * (ea + 28);
							a12  = * (ea + 32);
							a13  = * (ea + 36);
							a14  = * (ea + 40);
							a15  = * (ea + 44);
							d12  = * (ea + 48);
							d13  = * (ea + 52);
							d14  = * (ea + 56);
							d15  = * (ea + 60);
							* ea = FCX;
							FCX = (FCX & 0xfff00000) | (savePCXI & 0x000fffff);
							""")
					.build());
		}
	}
}
