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
import ghidra.pcode.exec.AnnotatedPcodeUseropLibrary;
import ghidra.pcode.exec.PcodeArithmetic;
import ghidra.pcode.exec.PcodeUserop;
import ghidra.pcode.exec.PcodeUseropLibraryFactory;
import ghidra.pcode.exec.SleighPcodeUseropDefinition;
import ghidra.pcode.exec.PcodeUseropLibraryFactory.UseropLibrary;
import ghidra.program.model.lang.Register;

/**
 * Creates the p-code user operation library for TILE processors.
 * Registers TILEGX-specific extended instructions including multiply, convert,
 * multi-register read/write, system register access, and control operations.
 */
@UseropLibrary("tile")
public class TILEPcodeUseropLibraryFactory implements PcodeUseropLibraryFactory {

	@Override
	public <T> PcodeUseropLibrary<T> create(SleighLanguage language,
			PcodeArithmetic<T> arithmetic) {
		return new TILEPcodeUseropLibrary<>(language);
	}

	public static class TILEPcodeUseropLibrary<T> extends AnnotatedPcodeUseropLibrary<T> {
		private final Register gpReg;
		private final Register cpReg;
		private final Register csrReg;
		private final Register spReg;
		private final Register r0Reg;

		public TILEPcodeUseropLibrary(SleighLanguage language) {
			gpReg = language.getRegister("gp");
			cpReg = language.getRegister("cp");
			csrReg = language.getRegister("csr");
			spReg = language.getRegister("sp");
			r0Reg = language.getRegister("r0");

			SleighPcodeUseropDefinition.Factory factory =
					new SleighPcodeUseropDefinition.Factory(language);

			// --- Extended multiply operations (TILEGX PMUL variants) ---

			// mul3: 16-bit signed * 16-bit signed -> 32-bit result, full 64-bit register
			putOp(factory.define("mul3")
					.params("rd", "rs1", "rs2")
					.body(args -> """
							local a16:2 = %s[0,16];
							local b16:2 = %s[0,16];
							local prod:4 = (a16 s* b16);
							%s[0,32] = prod;
							""".formatted(args.get(0), args.get(1), args.get(2)))
					.build());

			// mulif: 32-bit signed * 32-bit signed -> 64-bit result
			putOp(factory.define("mulif")
					.params("rd", "rs1", "rs2")
					.body(args -> """
							local a32:4 = %s[0,32];
							local b32:4 = %s[0,32];
							local prod:8 = (a32 s* b32);
							%s = prod;
							""".formatted(args.get(0), args.get(1), args.get(2)))
					.build());

			// mulim: 16-bit signed * 16-bit signed with 16-bit immediate -> 32-bit result
			putOp(factory.define("mulim")
					.params("rd", "rs1", "imm")
					.body(args -> """
							local a16:2 = %s[0,16];
							local b16:2 = %s;
							local prod:4 = (a16 s* b16);
							%s[0,32] = prod;
							""".formatted(args.get(0), args.get(1), args.get(2)))
					.build());

			// mulf: 32-bit unsigned * 32-bit unsigned -> 64-bit result (full register)
			putOp(factory.define("mulf")
					.params("rd", "rs1", "rs2")
					.body(args -> """
							local a32u:4 = %s[0,32];
							local b32u:4 = %s[0,32];
							local prod:8 = (a32u * b32u);
							%s = prod;
							""".formatted(args.get(0), args.get(1), args.get(2)))
					.build());

			// mull: 32-bit signed * 32-bit signed -> 64-bit result (full register)
			putOp(factory.define("mull")
					.params("rd", "rs1", "rs2")
					.body(args -> """
							local a32s:4 = %s[0,32];
							local b32s:4 = %s[0,32];
							local prod:8 = (a32s s* b32s);
							%s = prod;
							""".formatted(args.get(0), args.get(1), args.get(2)))
					.build());

			// mulli: 32-bit signed * 16-bit immediate -> 64-bit result (full register)
			putOp(factory.define("mulli")
					.params("rd", "rs1", "imm")
					.body(args -> """
							local a32s:4 = %s[0,32];
							local b16s:2 = %s;
							local prod:8 = (a32s s* b16s);
							%s = prod;
							""".formatted(args.get(0), args.get(1), args.get(2)))
					.build());

			// --- Floating-point divide ---

			// divfp: 64-bit IEEE 754 float / 64-bit IEEE 754 float -> 64-bit result
			putOp(factory.define("divfp")
					.params("rd", "rs1", "rs2")
					.body(args -> """
							local a_fp:8 = %s;
							local b_fp:8 = %s;
							%s = __divfp(a_fp, b_fp);
							""".formatted(args.get(0), args.get(1), args.get(2)))
					.build());

			// --- Integer/floating-point conversions ---

			// cvtif: signed 64-bit integer -> IEEE 754 double (as bit pattern)
			putOp(factory.define("cvtif")
					.params("rd", "rs1")
					.body(args -> """
							local i64:8 = %s;
							%s = __cvtsi2fp(i64);
							""".formatted(args.get(0), args.get(1)))
					.build());

			// cvtfi: IEEE 754 double (bit pattern) -> signed 64-bit integer
			putOp(factory.define("cvtfi")
					.params("rd", "rs1")
					.body(args -> """
							local fp64:8 = %s;
							%s = __cvtfp2si(fp64);
							""".formatted(args.get(0), args.get(1)))
					.build());

			// --- Multi-register read/write operations (MR/MT family) ---

			// mr6: Read 6 registers (48 bytes total) from memory, write to rd registers r[rd]..r[rd+5]
			putOp(factory.define("mr6")
					.params("r0", "r1", "r2", "r3", "r4", "r5", "addr")
					.body(args -> """
							local tmp:8;
							tmp = %s;
							%s = tmp;
							tmp = tmp[%d,64];
							%s = tmp;
							tmp = tmp[%d,64];
							%s = tmp;
							tmp = tmp[%d,64];
							%s = tmp;
							tmp = tmp[%d,64];
							%s = tmp;
							tmp = tmp[%d,64];
							%s = tmp;
							""".formatted(args.get(6), args.get(0), 8 * 1, args.get(1), 8 * 2,
									args.get(2), 8 * 3, args.get(3), 8 * 4, args.get(4),
									8 * 5, args.get(5)))
					.build());

			// mt6: Write 6 registers (48 bytes total) to memory from r[rd]..r[rd+5]
			putOp(factory.define("mt6")
					.params("addr", "r0", "r1", "r2", "r3", "r4", "r5")
					.body(args -> """
							local tmp:8 = %s;
							tmp[%d,64] = %s;
							tmp = tmp[0,64];
							tmp[%d,64] = %s;
							tmp = tmp[0,64];
							tmp[%d,64] = %s;
							tmp = tmp[0,64];
							tmp[%d,64] = %s;
							tmp = tmp[0,64];
							tmp[%d,64] = %s;
							%s = tmp;
							""".formatted(args.get(1), 8 * 1, args.get(2), 8 * 2, args.get(3),
									8 * 3, args.get(4), 8 * 4, args.get(5), 8 * 5, args.get(6),
									args.get(0)))
					.build());

			// mr12: Read 12 registers (96 bytes total) from memory into r[rd]..r[rd+11]
			putOp(factory.define("mr12")
					.params("r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9",
							"r10", "r11", "addr")
					.body(args -> genMR12Read(args))
					.build());

			// mt12: Write 12 registers (96 bytes total) to memory from r[rd]..r[rd+11]
			putOp(factory.define("mt12")
					.params("addr", "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8",
							"r9", "r10", "r11")
					.body(args -> genMR12Write(args))
					.build());

			// --- System register access (32-bit) ---

			// mtsr32: Write 32-bit value to system register sr[rs1] (lower half)
			putOp(factory.define("mtsr32")
					.params("rs1", "rs2")
					.body(args -> """
							local addr:8 = %s + (%s * 8);
							addr[0,32] = %s;
							""".formatted(cpReg, args.get(0), args.get(1)))
					.build());

			// mfsr32: Read 32-bit value from system register sr[rs1] (lower half) into r0
			putOp(factory.define("mfsr32")
					.params("rs1", "rd")
					.body(args -> """
							local addr:8 = %s + (%s * 8);
							%s = addr[0,32];
							""".formatted(cpReg, args.get(0), args.get(1)))
					.build());

			// mtcr32: Write 32-bit value to control register c[rs1] (lower half)
			putOp(factory.define("mtcr32")
					.params("rs1", "rs2")
					.body(args -> """
							local addr:8 = %s + (%s * 8);
							addr[0,32] = %s;
							""".formatted(csrReg, args.get(0), args.get(1)))
					.build());

			// mfcr32: Read 32-bit value from control register c[rs1] (lower half) into r0
			putOp(factory.define("mfcr32")
					.params("rs1", "rd")
					.body(args -> """
							local addr:8 = %s + (%s * 8);
							%s = addr[0,32];
							""".formatted(csrReg, args.get(0), args.get(1)))
					.build());

			// --- System control operations ---

			// rfe: Return from exception (restore context from stack)
			putOp(factory.define("rfe")
					.params()
					.body(args -> """
							local sp_val:8 = %s;
							pc = *(sp_val);
							sp_val = sp_val + 8;
							%s = sp_val;
							""".formatted(spReg, spReg))
					.build());

			// wfi: Wait for interrupt (enters low-power state)
			putOp(factory.define("wfi")
					.params()
					.body(args -> """
							__wfi();
							""".formatted())
					.build());

			// halt: Halt the processor core
			putOp(factory.define("halt")
					.params()
					.body(args -> """
							__halt();
							""".formatted())
					.build());

			// yield: Yield execution to other threads (for TILEGX multithreading)
			putOp(factory.define("yield")
					.params()
					.body(args -> """
							__yield();
							""".formatted())
					.build());

			// barrier: Thread synchronization barrier
			putOp(factory.define("barrier")
					.params()
					.body(args -> """
							__barrier();
							""".formatted())
					.build());

			// flush: Flush cache / TLB entries
			putOp(factory.define("flush")
					.params("rs1", "rs2")
					.body(args -> """
							local start:8 = %s;
							local count:8 = %s;
							for (local i:4 = 0; i < count[0,32]; ++i) {
								__flush_line(start + (i * 64));
							}
							""".formatted(args.get(0), args.get(1)))
					.build());
		}

		private String genMR12Read(SleighPcodeUseropDefinition.Args[] args) {
			StringBuilder sb = new StringBuilder();
			sb.append("local tmp:8;\n");
			sb.append("tmp = ").append(args[12]).append(";\n");
			for (int i = 0; i < 12; ++i) {
				sb.append(args[i]).append(" = tmp;\n");
				if (i < 11) {
					sb.append("tmp = tmp[").append(8 * (i + 1)).append(",64];\n");
				}
			}
			return sb.toString();
		}

		private String genMR12Write(SleighPcodeUseropDefinition.Args[] args) {
			StringBuilder sb = new StringBuilder();
			sb.append("local tmp:8;\n");
			for (int i = 0; i < 6; ++i) {
				sb.append("tmp[").append(8 * (i + 1)).append(",64] = ").append(args[i + 1]).append(";\n");
				sb.append("tmp = tmp[0,64];\n");
			}
			for (int i = 6; i < 12; ++i) {
				sb.append("tmp[").append(8 * (i - 5)).append(",64] = ").append(args[i + 1]).append(";\n");
				if (i < 11) {
					sb.append("tmp = tmp[0,64];\n");
				}
			}
			sb.append(args.get(0)).append(" = tmp;");
			return sb.toString();
		}

		@PcodeUserop(functional = true)
		public static double __divfp(double a, double b) {
			if (b == 0.0) {
				return Double.POSITIVE_INFINITY;
			}
			return a / b;
		}

		@PcodeUserop(functional = true)
		public static long __cvtsi2si(long src) {
			return src; // Sign-extend 32-bit to 64-bit (identity for 64-bit input)
		}

		@PcodeUserop(functional = true)
		public static double __cvtsi2fp(long val) {
			return (double) val;
		}

		@PcodeUserop(functional = true)
		public static long __cvtfp2si(double fp) {
			return (long) fp;
		}
	}
}
