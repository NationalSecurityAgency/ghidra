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
import ghidra.program.model.pcode.Varnode;

/**
 * The userop library for AARCH64.
 * 
 * For the TBL and TBX instructions, see
 * https://developer.arm.com/documentation/ddi0602/2024-12/SIMD-FP-Instructions/TBL--Table-vector-lookup-
 */
@UseropLibrary("aarch64")
public class AARCH64PcodeUseropLibraryFactory implements PcodeUseropLibraryFactory {
	@Override
	public <T> PcodeUseropLibrary<T> create(SleighLanguage language,
			PcodeArithmetic<T> arithmetic) {
		return new AARCH64PcodeUseropLibrary<>(language);
	}

	public static class AARCH64PcodeUseropLibrary<T> extends DefaultPcodeUseropLibrary<T> {
		public AARCH64PcodeUseropLibrary(SleighLanguage language) {
			SleighPcodeUseropDefinition.Factory factory =
				new SleighPcodeUseropDefinition.Factory(language);

			putOp(factory.define("MP_INT_ABS").params("n").body(args -> """
					if (n >= 0) goto <pos>;
					  __op_output = -n;
					goto <done>;
					<pos>:
					  __op_output = n;
					<done>:
					""").build());

			putOp(factory.define("SIMD_PIECE").params("simdBytes", "offset").body(args -> """
					__op_output = simdBytes(%d*offset);
					""".formatted(args.get(1).getSize())).build());

			putOp(factory.define("a64_TBL").params("init", "n1", "m").body(args -> {
				return genA64_TBL(args.get(0), "n1");
			}).overload().params("init", "n1", "n2", "m").body(args -> {
				return genA64_TBL(args.get(0), "n1", "n2");
			}).overload().params("init", "n1", "n2", "n3", "m").body(args -> {
				return genA64_TBL(args.get(0), "n1", "n2", "n3");
			}).overload().params("init", "n1", "n2", "n3", "n4", "m").body(args -> {
				return genA64_TBL(args.get(0), "n1", "n2", "n3", "n4");
			}).build());
		}

		protected String genA64_TBL(Varnode out, String... regs) {
			int size = out.getSize();
			String body = genBuildTable(regs) + genIndex(size, regs.length);
			return body;
		}

		protected String genBuildTable(String... regs) {
			if (regs.length == 1) {
				return "local table:16 = %s;\n".formatted(regs[0]);
			}
			int size = 16; // Table is always made up of 16-byte (128-bit) regs
			StringBuffer buf = new StringBuffer();
			buf.append("local table:%d;\n".formatted(size * regs.length));
			for (int i = 0; i < regs.length; i++) {
				buf.append("table[%d,%d] = %s;\n".formatted(8 * size * i, 8 * size, regs[i]));
			}
			return buf.toString();
		}

		protected String genIndex(int size, int regCount) {
			int tableSize = 16 * regCount;
			StringBuffer buf = new StringBuffer();
			buf.append("local indicies:%d = m;\n".formatted(size));
			buf.append("local result:%d = init;\n".formatted(size));
			for (int i = 0; i < size; i++) {
				/**
				 * TODO: Measure JIT performance with different uses of variables
				 * 
				 * TODO: It might be nice to have a separate a64_TLX, so we don't have to put this
				 * blasted conditional in here.
				 */
				buf.append("local idx%d:1 = indicies[%d,8];\n".formatted(i, 8 * i));
				buf.append("if (idx%d >= %d) goto <skip%d>;\n".formatted(i, tableSize, i));
				buf.append("  tmp%d:1 = table(idx%d);\n".formatted(i, i));
				buf.append("  result[%d,8] = tmp%d;\n".formatted(8 * i, i));
				buf.append("<skip%d>\n".formatted(i));
			}
			buf.append("__op_output = result;");
			return buf.toString();
		}
	}
}
