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
import ghidra.pcode.exec.SleighPcodeUseropDefinition.BuilderStage1;

@UseropLibrary(id = "ppc")
public class PpcPcodeUseropLibraryFactory implements PcodeUseropLibraryFactory {
	@Override
	public <T> PcodeUseropLibrary<T> create(SleighLanguage language,
			PcodeArithmetic<T> arithmetic) {
		return new PpcPcodeUseropLibrary<>();
	}

	public static class PpcPcodeUseropLibrary<T> extends AnnotatedPcodeUseropLibrary<T> {

		protected String genIndex() {
			StringBuilder buf = new StringBuilder();
			for (int i = 0; i < 16; i++) {
				buf.append("idx%d:1 = 0x1f - (p(%d) & 0x1f);\n".formatted(i, i));
				buf.append("tmp%d:1 = table(idx%d);\n".formatted(i, i));
				buf.append("result[%d,8] = tmp%d;\n".formatted(8 * i, i));
			}
			return buf.toString();
		}

		@PcodeUserop
		public SleighPcodeUseropDefinition vectorPermute(BuilderStage1 builder) {
			return builder.params("s1", "s2", "p").body(_ -> """
					local table:32;
					local result:16;
					table[128,128] = s1;
					table[0,128] = s2;
					""" + genIndex() + """
					__op_output = result;
					""").build();
		}
	}
}
