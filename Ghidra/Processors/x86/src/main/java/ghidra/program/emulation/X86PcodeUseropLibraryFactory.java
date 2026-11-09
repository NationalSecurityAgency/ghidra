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

import java.nio.*;
import java.nio.charset.Charset;
import java.nio.charset.CoderResult;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.pcode.exec.*;
import ghidra.pcode.exec.PcodeUseropLibraryFactory.UseropLibrary;
import ghidra.pcode.exec.SleighPcodeUseropDefinition.BuilderStage1;

@UseropLibrary(id = "x86")
public class X86PcodeUseropLibraryFactory implements PcodeUseropLibraryFactory {

	record CpuidResponse(int eax, int ebx, int edx, int ecx) {
		public CpuidResponse(int eax, String others) {
			ByteBuffer buf = ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN);
			buf.putInt(eax);
			CoderResult result =
				Charset.forName("utf8").newEncoder().encode(CharBuffer.wrap(others), buf, true);
			if (result.isError() || result.isOverflow()) {
				throw new AssertionError(result);
			}
			buf.flip();
			this(buf.getInt(), buf.getInt(), buf.getInt(), buf.getInt());
		}

		public long p0_64() {
			return (Integer.toUnsignedLong(ebx) << 32) | Integer.toUnsignedLong(eax);
		}

		public long p64_64() {
			return (Integer.toUnsignedLong(ecx) << 32) | Integer.toUnsignedLong(edx);
		}
	}

	static final String MANUFACTURER_ID_INTEL = "GenuineIntel";
	static final String MANUFACTURER_ID_AMD = "AuthenticAMD";
	static final String DEFAULT_MANUFACTURER_ID = MANUFACTURER_ID_AMD;
	static final int HIGHEST_FUNCTION_PARAMETER = 0x10;

	@Override
	public <T> PcodeUseropLibrary<T> create(SleighLanguage language,
			PcodeArithmetic<T> arithmetic) {
		int size = language.getLanguageDescription().getSize();
		return switch (size) {
			// TODO: Non-size specific?
			case 32 -> new X86_32PcodeUseropLibrary<>(DEFAULT_MANUFACTURER_ID);
			case 64 -> new X86_64PcodeUseropLibrary<T>(DEFAULT_MANUFACTURER_ID);
			default -> throw new IllegalArgumentException("Unknown x86 size: %d".formatted(size));
		};
	}

	public static abstract class AbstractX86PcodeUseropLibrary<T>
			extends AnnotatedPcodeUseropLibrary<T> {
		protected final String manufacturerId;
		protected final CpuidResponse cpuidEax0;

		public AbstractX86PcodeUseropLibrary(String manufacturerId) {
			this.manufacturerId = manufacturerId;
			cpuidEax0 = new CpuidResponse(HIGHEST_FUNCTION_PARAMETER, manufacturerId);
			super();
		}

		/**
		 * LATER: For petri-dish emulation, this is perfect. However, for multi-threaded and
		 * systems-level stuff, we'll probably need an actual mutex of some sort. We'll also want to
		 * make sure the behavior is accurate in the face of errors and interrupts.
		 */
		@PcodeUserop(canInline = true)
		public void LOCK() {
		}

		@PcodeUserop(canInline = true)
		public void UNLOCK() {
		}

		@PcodeUserop(canInline = true)
		public SleighPcodeUseropDefinition segment(BuilderStage1 builder) {
			// LATER: Either read a table from memory, or accept some Map in a custom constructor?
			return builder.body(_ -> """
					__op_output = (zext(base) << 4) + zext(inner);
					""").build();
		}

		@PcodeUserop(canInline = true)
		public SleighPcodeUseropDefinition rdtsc(BuilderStage1 builder) {
			return builder.body(_ -> """
					__op_output = 0;
					""").build();
		}

		/**
		 * For this and all the cpuid userops, do not write to EAX,EBX,EDX,ECX directly. Instead,
		 * write to __op_output. If EDX:ECX is meant to be zero, then it's sufficient to just set
		 * __op_output once. If those need setting, then you'll run into the max integer size thing,
		 * so set __op_output[0,64] then __op_output[64,64]. They're little endian, so 0,64 is
		 * EBX:EAX; 64,64 is ECX:EDX.
		 * 
		 * @param builder the builder
		 * @return the definition
		 */
		@PcodeUserop(canInline = true) // eax=0x0
		public SleighPcodeUseropDefinition cpuid_basic_info(BuilderStage1 builder) {
			return builder.params("leaf").body(_ -> """
					emu_probe(leaf);
					__op_output[0, 64] = 0x%x;
					__op_output[64,64] = 0x%x;
					""".formatted(cpuidEax0.p0_64(), cpuidEax0.p64_64())).build();
		}

		protected static final CpuidResponse CPUID_EAX1 =
			new CpuidResponse(0x00a10f11, 0x060808000, 0x178bfbff, 0xfefa320b);

		@PcodeUserop(canInline = true) // eax=0x1
		public SleighPcodeUseropDefinition cpuid_Version_info(BuilderStage1 builder) {
			return builder.params("leaf").body(_ -> """
					emu_probe(leaf);
					__op_output[0, 64] = 0x%x;
					__op_output[64,64] = 0x%x;
					""".formatted(CPUID_EAX1.p0_64(), CPUID_EAX1.p64_64())).build();
		}

		@PcodeUserop(canInline = true) // eax=0x2
		public SleighPcodeUseropDefinition cpuid_cache_tlb_info(BuilderStage1 builder) {
			return builder.params("leaf").body(_ -> """
					emu_swi();
					""").build();
		}

		@PcodeUserop(canInline = true) // eax=0x4
		public SleighPcodeUseropDefinition
				cpuid_Deterministic_Cache_Parameters_info(BuilderStage1 builder) {
			// Eh. Just say no caches?
			return builder.params("leaf").body(_ -> """
					emu_swi();
					""").build();
		}

		protected static final CpuidResponse CPUID_EAX7_ECX0 =
			new CpuidResponse(0x00000001, 0xf1bf05a9, 0x10000000, 0x00405f5a);
		protected static final CpuidResponse CPUID_EAX7_ECX1 =
			new CpuidResponse(0x00000020, 0x00000000, 0x00000000, 0x00000000);

		@PcodeUserop(canInline = true) // eax=0x7
		public SleighPcodeUseropDefinition
				cpuid_Extended_Feature_Enumeration_info(BuilderStage1 builder) {
			// Oof. Just support nothing for now.
			return builder.params("leaf")
					.body(_ -> """
							emu_probe(leaf);
							emu_probe(ECX);
							if (ECX == 0) goto <cpuid_Extended_Features_0>;
							if (ECX == 1) goto <cpuid_Extended_Features_1>;
							emu_swi();
							goto <finish>;
							<cpuid_Extended_Features_0>
							__op_output[0, 64] = 0x%x;
							__op_output[64,64] = 0x%x;
							goto <finish>;
							<cpuid_Extended_Features_1>
							__op_output[0, 64] = 0x%x;
							__op_output[64,64] = 0x%x;
							<finish>
							""".formatted(
						CPUID_EAX7_ECX0.p0_64(), CPUID_EAX7_ECX0.p64_64(),
						CPUID_EAX7_ECX1.p0_64(), CPUID_EAX7_ECX1.p64_64()))
					.build();
		}

		protected static final CpuidResponse CPUID_EAXd_ECX0 =
			new CpuidResponse(0x000002e7, 0x00000988, 0x00000000, 0x00000988);
		protected static final CpuidResponse CPUID_EAXd_ECX1 =
			new CpuidResponse(0x0000000f, 0x00000988, 0x00000000, 0x00000000);
		protected static final CpuidResponse CPUID_EAXd_ECX2 =
			new CpuidResponse(0x00000100, 0x00000240, 0x00000000, 0x00000000);
		protected static final CpuidResponse CPUID_EAXd_ECX3 =
			new CpuidResponse(0x00000000, 0x00000000, 0x00000000, 0x00000000);
		protected static final CpuidResponse CPUID_EAXd_ECX5 =
			new CpuidResponse(0x00000040, 0x00000340, 0x00000000, 0x00000000);
		protected static final CpuidResponse CPUID_EAXd_ECX6 =
			new CpuidResponse(0x00000200, 0x00000000, 0x00000000, 0x00000000);
		protected static final CpuidResponse CPUID_EAXd_ECX7 =
			new CpuidResponse(0x00000400, 0x00000580, 0x00000000, 0x00000000);
		protected static final CpuidResponse CPUID_EAXd_ECX13 =
			new CpuidResponse(0x00000000, 0x00000000, 0x00000000, 0x00000000);

		@PcodeUserop(canInline = true) // eax=0xd
		public SleighPcodeUseropDefinition
				cpuid_Processor_Extended_States_info(BuilderStage1 builder) {
			return builder.params("leaf")
					.body(_ -> """
							emu_probe(leaf);
							emu_probe(ECX);
							if (ECX == 0) goto <cpuid_Extended_States_0>;
							if (ECX == 1) goto <cpuid_Extended_States_1>;
							if (ECX == 2) goto <cpuid_Extended_States_2>;
							if (ECX == 3) goto <cpuid_Extended_States_3>;
							if (ECX == 5) goto <cpuid_Extended_States_5>;
							if (ECX == 6) goto <cpuid_Extended_States_6>;
							if (ECX == 7) goto <cpuid_Extended_States_7>;
							if (ECX == 0x13) goto <cpuid_Extended_States_13>;
							emu_swi();
							goto <finish>;
							<cpuid_Extended_States_0>
							__op_output[0, 64] = 0x%x;
							__op_output[64,64] = 0x%x;
							goto <finish>;
							<cpuid_Extended_States_1>
							__op_output[0, 64] = 0x%x;
							__op_output[64,64] = 0x%x;
							goto <finish>;
							<cpuid_Extended_States_2>
							__op_output[0, 64] = 0x%x;
							__op_output[64,64] = 0x%x;
							goto <finish>;
							<cpuid_Extended_States_3>
							__op_output[0, 64] = 0x%x;
							__op_output[64,64] = 0x%x;
							goto <finish>;
							<cpuid_Extended_States_5>
							__op_output[0, 64] = 0x%x;
							__op_output[64,64] = 0x%x;
							goto <finish>;
							<cpuid_Extended_States_6>
							__op_output[0, 64] = 0x%x;
							__op_output[64,64] = 0x%x;
							goto <finish>;
							<cpuid_Extended_States_7>
							__op_output[0, 64] = 0x%x;
							__op_output[64,64] = 0x%x;
							goto <finish>;
							<cpuid_Extended_States_13>
							__op_output[0, 64] = 0x%x;
							__op_output[64,64] = 0x%x;
							<finish>
							""".formatted(
						CPUID_EAXd_ECX0.p0_64(), CPUID_EAXd_ECX0.p64_64(),
						CPUID_EAXd_ECX1.p0_64(), CPUID_EAXd_ECX1.p64_64(),
						CPUID_EAXd_ECX2.p0_64(), CPUID_EAXd_ECX2.p64_64(),
						CPUID_EAXd_ECX3.p0_64(), CPUID_EAXd_ECX3.p64_64(),
						CPUID_EAXd_ECX5.p0_64(), CPUID_EAXd_ECX5.p64_64(),
						CPUID_EAXd_ECX6.p0_64(), CPUID_EAXd_ECX6.p64_64(),
						CPUID_EAXd_ECX7.p0_64(), CPUID_EAXd_ECX7.p64_64(),
						CPUID_EAXd_ECX13.p0_64(), CPUID_EAXd_ECX13.p64_64()))
					.build();
		}

		// Observed values in GDB: (all in 0x)
		// CPUID(EAX=0):              EAX=00000010, EBX=68747541, EDX=69746e65, ECX=444d4163
		// CPUID(EAX=1):              EAX=00a10f11, EBX=06080800, EDX=178bfbff, ECX=fefa320b
		// CPUID(EAX=7,ECX=0):        EAX=00000001, EBX=f1bf05a9, EDX=10000000, ECX=00405f5a
		// CPUID(EAX=7,ECX=1):        EAX=00000020, EBX=00000000, EDX=00000000, ECX=00000000
		// CPUID(EAX=d,ECX=1):        EAX=0000000f, EBX=00000988, EDX=00000000, ECX=00000000
		// CPUID(EAX=80000000):       EAX=80000028, EBX=68747541, EDX=69746e65, ECX=444d4163
		// CPUID(EAX=80000001):       EAX=00a10f11, EBX=40000000, EDX=2fd3fbff, ECX=00c001f3
		// CPUID(EAX=80000007):       EAX=00000000, EBX=00000000, EDX=00000100, ECX=00000000
		// CPUID(EAX=80000008):       EAX=00003030, EBX=311ed215, EDX=00010007, ECX=0000305f
		// CPUID(EAX=d,ECX=0):        EAX=000002e7, EBX=00000988, EDX=00000000, ECX=00000988
		// CPUID(EAX=d,ECX=2):        EAX=00000100, EBX=00000240, EDX=00000000, ECX=00000000
		// CPUID(EAX=d,ECX=3):        EAX=00000000, EBX=00000000, EDX=00000000, ECX=00000000
		// CPUID(EAX=d,ECX=5):        EAX=00000040, EBX=00000340, EDX=00000000, ECX=00000000
		// CPUID(EAX=d,ECX=6):        EAX=00000200, EBX=00000000, EDX=00000000, ECX=00000000
		// CPUID(EAX=d,ECX=7):        EAX=00000400, EBX=00000580, EDX=00000000, ECX=00000000
		// CPUID(EAX=d,ECX=13):       EAX=00000000, EBX=00000000, EDX=00000000, ECX=00000000
		// CPUID(EAX=8000001d,RCX=0): EAX=00000121, EBX=01c0003f, EDX=00000000, ECX=0000003f
		// CPUID(EAX=8000001d,RCX=3): EAX=0001c163, EBX=03c0003f, EDX=00000001, ECX=00007fff
		// CPUID(EAX=8000001d,RCX=1): EAX=00000122, EBX=01c0003f, EDX=00000000, ECX=0000003f
		// CPUID(EAX=8000001d,RCX=2): EAX=00000143, EBX=01c0003f, EDX=00000002, ECX=000007ff

		// XGETBV(ECX=0): EAX=000002e7, EDX=00000000
		protected static final CpuidResponse CPUID_EAX80000000 =
			new CpuidResponse(0x80000028, DEFAULT_MANUFACTURER_ID); // LATER: Move to instance field
		protected static final CpuidResponse CPUID_EAX80000001 =
			new CpuidResponse(0x00a10f11, 0x40000000, 0x2fd3fbff, 0x00c001f3);
		protected static final CpuidResponse CPUID_EAX80000007 =
			new CpuidResponse(0x00000000, 0x00000000, 0x00000100, 0x00000000);
		protected static final CpuidResponse CPUID_EAX80000008 =
			new CpuidResponse(0x00003030, 0x311ed215, 0x00010007, 0x0000305f);
		protected static final CpuidResponse CPUID_EAX8000001d_ECX0 =
			new CpuidResponse(0x00000121, 0x01c0003f, 0x00000000, 0x0000003f);
		protected static final CpuidResponse CPUID_EAX8000001d_ECX1 =
			new CpuidResponse(0x00000122, 0x01c0003f, 0x00000000, 0x0000003f);
		protected static final CpuidResponse CPUID_EAX8000001d_ECX2 =
			new CpuidResponse(0x00000143, 0x01c0003f, 0x00000002, 0x000007ff);
		protected static final CpuidResponse CPUID_EAX8000001d_ECX3 =
			new CpuidResponse(0x0001c163, 0x03c0003f, 0x00000001, 0x00007fff);

		@PcodeUserop(canInline = true)
		public SleighPcodeUseropDefinition cpuid(BuilderStage1 builder) {
			return builder.params("leaf")
					.body(_ -> """
							emu_probe(leaf);
							if (leaf == 0x80000000) goto <cpuid_Highest_Extended_Function>;
							if (leaf == 0x80000001) goto <cpuid_Extended_Processor_Info>;
							if (leaf == 0x80000007) goto <cpuid_Extended_Unk7>;
							if (leaf == 0x80000008) goto <cpuid_Extended_Unk8>;
							if (leaf == 0x8000001d) goto <cpuid_Extended_Unk1d>;
							emu_swi();
							goto <finish>;
							<cpuid_Highest_Extended_Function>
							__op_output[0, 64] = 0x%x;
							__op_output[64,64] = 0x%x;
							goto <finish>;
							<cpuid_Extended_Processor_Info>
							__op_output[0, 64] = 0x%x;
							__op_output[64,64] = 0x%x;
							goto <finish>;
							<cpuid_Extended_Unk7>
							__op_output[0, 64] = 0x%x;
							__op_output[64,64] = 0x%x;
							goto <finish>;
							<cpuid_Extended_Unk8>
							__op_output[0, 64] = 0x%x;
							__op_output[64,64] = 0x%x;
							goto <finish>;
							<cpuid_Extended_Unk1d>
							if (ECX == 0) goto <cpuid_Ext1d_0>;
							if (ECX == 1) goto <cpuid_Ext1d_1>;
							if (ECX == 2) goto <cpuid_Ext1d_2>;
							if (ECX == 3) goto <cpuid_Ext1d_3>;
							emu_swi();
							goto <finish>;
							<cpuid_Ext1d_0>
							__op_output[0, 64] = 0x%x;
							__op_output[64,64] = 0x%x;
							goto <finish>;
							<cpuid_Ext1d_1>
							__op_output[0, 64] = 0x%x;
							__op_output[64,64] = 0x%x;
							goto <finish>;
							<cpuid_Ext1d_2>
							__op_output[0, 64] = 0x%x;
							__op_output[64,64] = 0x%x;
							goto <finish>;
							<cpuid_Ext1d_3>
							__op_output[0, 64] = 0x%x;
							__op_output[64,64] = 0x%x;
							<finish>
							""".formatted(
						CPUID_EAX80000000.p0_64(), CPUID_EAX80000000.p64_64(),
						CPUID_EAX80000001.p0_64(), CPUID_EAX80000001.p64_64(),
						CPUID_EAX80000007.p0_64(), CPUID_EAX80000007.p64_64(),
						CPUID_EAX80000008.p0_64(), CPUID_EAX80000008.p64_64(),
						CPUID_EAX8000001d_ECX0.p0_64(), CPUID_EAX8000001d_ECX0.p64_64(),
						CPUID_EAX8000001d_ECX1.p0_64(), CPUID_EAX8000001d_ECX1.p64_64(),
						CPUID_EAX8000001d_ECX2.p0_64(), CPUID_EAX8000001d_ECX2.p64_64(),
						CPUID_EAX8000001d_ECX3.p0_64(), CPUID_EAX8000001d_ECX3.p64_64()))
					.build();
		}

		@PcodeUserop(canInline = true)
		public SleighPcodeUseropDefinition xinuse(BuilderStage1 builder) {
			// LATER: I don't really understand what this does, yet.
			return builder.params("ecxIs1").body(_ -> """
					emu_probe(ecxIs1);
					__op_output = 0;
					""").build();
		}
	}

	public static class X86_32PcodeUseropLibrary<T> extends AbstractX86PcodeUseropLibrary<T> {
		public X86_32PcodeUseropLibrary(String manufacturerId) {
			super(manufacturerId);
		}
	}

	public static class X86_64PcodeUseropLibrary<T> extends AbstractX86PcodeUseropLibrary<T> {
		public X86_64PcodeUseropLibrary(String manufacturerId) {
			super(manufacturerId);
		}
	}
}
