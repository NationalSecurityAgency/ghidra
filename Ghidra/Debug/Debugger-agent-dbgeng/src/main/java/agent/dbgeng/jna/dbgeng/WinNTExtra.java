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
package agent.dbgeng.jna.dbgeng;

import java.util.List;

import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import com.sun.jna.platform.win32.BaseTSD.ULONG_PTR;
import com.sun.jna.platform.win32.WinDef.*;

public class WinNTExtra {
	public static enum Machine {
		IMAGE_FILE_MACHINE_UNKNOWN(0, "Unknown"), //
		IMAGE_FILE_MACHINE_I386(0x014c, "x86"), //
		IMAGE_FILE_MACHINE_ARM(0x01c0, "ARM"), //
		IMAGE_FILE_MACHINE_IA64(0x0200, "Itanium"), //
		IMAGE_FILE_MACHINE_AMD64(0x8664, "AMD64 (K8)"), //
		IMAGE_FILE_MACHINE_EBC(0x0EBC, "EFI"), //
		;

		public static Machine getByNumber(int val) {
			for (Machine m : Machine.values()) {
				if (m.val == val) {
					return m;
				}
			}
			return null;
		}

		Machine(int val, String description) {
			this.val = val;
			this.description = description;
		}

		public final int val;
		public final String description;
	}

	public static class M128A extends Structure {
		public static class ByReference extends M128A implements Structure.ByReference {
		}

		public static final List<String> FIELDS = createFieldsOrder("Low", "High");

		public ULONGLONG Low;
		public LONGLONG High;

		@Override
		protected List<String> getFieldOrder() {
			return FIELDS;
		}
	}

	public static class CONTEXT_AMD64 extends Structure {
		public static class ByReference extends CONTEXT_AMD64 implements Structure.ByReference {
		}

		public static final List<String> FIELDS = createFieldsOrder(

			"P1Home", "P2Home", "P3Home", "P4Home", "P5Home", "P6Home",

			"ContextFlags", "MxCsr",

			"SegCs", "SegDs", "SegEs", "SegFs", "SegGs", "SegSs", "EFlags",

			"Dr0", "Dr1", "Dr2", "Dr3", "Dr6", "Dr7",

			"Rax", "Rcx", "Rdx", "Rbx", "Rsp", "Rbp", "Rsi", "Rdi", "R8", "R9", "R10", "R11", "R12",
			"R13", "R14", "R15",

			"Rip",

			"Header", "Legacy", "Xmm0", "Xmm1", "Xmm2", "Xmm3", "Xmm4", "Xmm5", "Xmm6", "Xmm7",
			"Xmm8", "Xmm9", "Xmm10", "Xmm11", "Xmm12", "Xmm13", "Xmm14", "Xmm15",

			"VectorRegister", "VectorControl",

			"DebugControl", "LastBranchToRip", "LastBranchFromRip", "LastExceptionToRip",
			"LastExceptionFromRip");

		public DWORDLONG P1Home;
		public DWORDLONG P2Home;
		public DWORDLONG P3Home;
		public DWORDLONG P4Home;
		public DWORDLONG P5Home;
		public DWORDLONG P6Home;

		public DWORD ContextFlags;
		public DWORD MxCsr;

		public WORD SegCs;
		public WORD SegDs;
		public WORD SegEs;
		public WORD SegFs;
		public WORD SegGs;
		public WORD SegSs;
		public DWORD EFlags;

		public DWORDLONG Dr0;
		public DWORDLONG Dr1;
		public DWORDLONG Dr2;
		public DWORDLONG Dr3;
		public DWORDLONG Dr6;
		public DWORDLONG Dr7;

		public DWORDLONG Rax;
		public DWORDLONG Rcx;
		public DWORDLONG Rdx;
		public DWORDLONG Rbx;
		public DWORDLONG Rsp;
		public DWORDLONG Rbp;
		public DWORDLONG Rsi;
		public DWORDLONG Rdi;
		public DWORDLONG R8;
		public DWORDLONG R9;
		public DWORDLONG R10;
		public DWORDLONG R11;
		public DWORDLONG R12;
		public DWORDLONG R13;
		public DWORDLONG R14;
		public DWORDLONG R15;

		public DWORDLONG Rip;

		public M128A[] Header = new M128A[2];
		public M128A[] Legacy = new M128A[8];
		public M128A Xmm0;
		public M128A Xmm1;
		public M128A Xmm2;
		public M128A Xmm3;
		public M128A Xmm4;
		public M128A Xmm5;
		public M128A Xmm6;
		public M128A Xmm7;
		public M128A Xmm8;
		public M128A Xmm9;
		public M128A Xmm10;
		public M128A Xmm11;
		public M128A Xmm12;
		public M128A Xmm13;
		public M128A Xmm14;
		public M128A Xmm15;

		public M128A[] VectorRegister = new M128A[26];
		public DWORDLONG VectorControl;

		public DWORDLONG DebugControl;
		public DWORDLONG LastBranchToRip;
		public DWORDLONG LastBranchFromRip;
		public DWORDLONG LastExceptionToRip;
		public DWORDLONG LastExceptionFromRip;

		@Override
		protected List<String> getFieldOrder() {
			return FIELDS;
		}
	}

	public static class EXCEPTION_RECORD extends Structure {
		public static class ByReference extends EXCEPTION_RECORD implements Structure.ByReference {
		}

		public static final List<String> FIELDS = createFieldsOrder("ExceptionCode",
			"ExceptionFlags", "ExceptionRecord", "ExceptionAddress", "NumberParameters",
			"__unusedAlignment", "ExceptionInformation");

		public DWORD ExceptionCode;
		public DWORD ExceptionFlags;
		public EXCEPTION_RECORD.ByReference ExceptionRecord;
		public Pointer ExceptionAddress;
		public DWORD NumberParameters;
		public ULONG_PTR ExceptionInformation[] = new ULONG_PTR[15];

		@Override
		protected List<String> getFieldOrder() {
			return FIELDS;
		}
	}

	public static class EXCEPTION_RECORD32 extends Structure {
		public static class ByReference extends EXCEPTION_RECORD64
				implements Structure.ByReference {
		}

		public static final List<String> FIELDS = createFieldsOrder("ExceptionCode",
			"ExceptionFlags", "ExceptionRecord", "ExceptionAddress", "NumberParameters",
			"__unusedAlignment", "ExceptionInformation");

		public DWORD ExceptionCode;
		public DWORD ExceptionFlags;
		public DWORD ExceptionRecord;
		public DWORD ExceptionAddress;
		public DWORD NumberParameters;
		public DWORD __unusedAlignment;
		public DWORD ExceptionInformation[] = new DWORD[15];

		@Override
		protected List<String> getFieldOrder() {
			return FIELDS;
		}
	}

	public static class EXCEPTION_RECORD64 extends Structure {
		public static class ByReference extends EXCEPTION_RECORD64
				implements Structure.ByReference {
		}

		public static final List<String> FIELDS = createFieldsOrder("ExceptionCode",
			"ExceptionFlags", "ExceptionRecord", "ExceptionAddress", "NumberParameters",
			"__unusedAlignment", "ExceptionInformation");

		public DWORD ExceptionCode;
		public DWORD ExceptionFlags;
		public DWORDLONG ExceptionRecord;
		public DWORDLONG ExceptionAddress;
		public DWORD NumberParameters;
		public DWORD __unusedAlignment;
		public DWORDLONG ExceptionInformation[] = new DWORDLONG[15];

		@Override
		protected List<String> getFieldOrder() {
			return FIELDS;
		}
	}

	public static class EXCEPTION_POINTERS extends Structure {
		public static class ByReference extends EXCEPTION_POINTERS
				implements Structure.ByReference {
		}

		public static final List<String> FIELDS =
			createFieldsOrder("ExceptionRecord", "ContextRecord");

		public EXCEPTION_RECORD.ByReference ExceptionRecord;
		public CONTEXT_AMD64.ByReference ContextRecord; // TODO: This should be fine for now

		@Override
		protected List<String> getFieldOrder() {
			return FIELDS;
		}
	}

	public static class MEMORY_BASIC_INFORMATION64 extends Structure {
		public static class ByReference extends MEMORY_BASIC_INFORMATION64
				implements Structure.ByReference {
		}

		public static final List<String> FIELDS =
			createFieldsOrder("BaseAddress", "AllocationBase", "AllocationProtect", "__alignment1",
				"RegionSize", "State", "Protect", "Type", "__alignment2");

		public ULONGLONG BaseAddress;
		public ULONGLONG AllocationBase;
		public DWORD AllocationProtect;
		public DWORD __alignment1;
		public ULONGLONG RegionSize;
		public DWORD State;
		public DWORD Protect;
		public DWORD Type;
		public DWORD __alignment2;

		@Override
		protected List<String> getFieldOrder() {
			return FIELDS;
		}
	}
}
