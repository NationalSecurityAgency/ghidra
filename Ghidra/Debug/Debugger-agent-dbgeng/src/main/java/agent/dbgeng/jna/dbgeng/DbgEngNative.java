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

import com.sun.jna.*;
import com.sun.jna.platform.win32.Guid.REFIID;
import com.sun.jna.platform.win32.WinDef.*;
import com.sun.jna.platform.win32.WinNT.HRESULT;
import com.sun.jna.ptr.PointerByReference;
import com.sun.jna.win32.StdCallLibrary;

import agent.dbgeng.dbgeng.DebugValue;
import agent.dbgeng.dbgeng.DebugValue.*;

public interface DbgEngNative extends StdCallLibrary {
	//DbgEngNative INSTANCE = Native.loadLibrary("dbgeng", DbgEngNative.class);
	DbgEngNative INSTANCE = Native.load("dbgeng.dll", DbgEngNative.class);

	HRESULT DebugConnect(String RemoteOptions, REFIID InterfaceId, PointerByReference Interface);

	HRESULT DebugConnectWide(WString RemoteOptions, REFIID InterfaceId,
			PointerByReference Interface);

	HRESULT DebugCreate(REFIID InterfaceId, PointerByReference Interface);

	HRESULT DebugCreateEx(REFIID InterfaceId, DWORD DbgEngOptions, PointerByReference Interface);

	public static class DEBUG_BREAKPOINT_PARAMETERS extends Structure {
		public static class ByReference extends DEBUG_BREAKPOINT_PARAMETERS
				implements Structure.ByReference {
		}

		public static final List<String> FIELDS = createFieldsOrder("Offset", "Id", "BreakType",
			"ProcType", "Flags", "DataSize", "DataAccessType", "PassCount", "CurrentPassCount",
			"MatchThread", "CommandSize", "OffsetExpressionSize");

		public ULONGLONG Offset;
		public ULONG Id;
		public ULONG BreakType;
		public ULONG ProcType;
		public ULONG Flags;
		public ULONG DataSize;
		public ULONG DataAccessType;
		public ULONG PassCount;
		public ULONG CurrentPassCount;
		public ULONG MatchThread;
		public ULONG CommandSize;
		public ULONG OffsetExpressionSize;

		@Override
		protected List<String> getFieldOrder() {
			return FIELDS;
		}
	}

	public static class DEBUG_REGISTER_DESCRIPTION extends Structure {
		public static class ByReference extends DEBUG_REGISTER_DESCRIPTION
				implements Structure.ByReference {
		}

		public static final List<String> FIELDS = createFieldsOrder("Type", "Flags", "SubregMaster",
			"SubregLength", "SubregMask", "SubregShift", "Reserved0");

		public ULONG Type;
		public ULONG Flags;

		public ULONG SubregMaster;
		public ULONG SubregLength;
		public ULONGLONG SubregMask;
		public ULONG SubregShift;

		public ULONG Reserved0;

		@Override
		protected List<String> getFieldOrder() {
			return FIELDS;
		}
	}

	public static class DEBUG_VALUE extends Structure {
		public static class ByReference extends DEBUG_VALUE implements Structure.ByReference {
		}

		public static final List<String> FIELDS = createFieldsOrder("u", "TailOfRawBytes", "Type");

		public static class UNION extends Union {
			public static class ByReference extends UNION implements Structure.ByReference {
			}

			public static class INTEGER64 extends Structure {
				public static class ByReference extends UNION implements Structure.ByReference {
				}

				@SuppressWarnings("hiding")
				public static final List<String> FIELDS = createFieldsOrder("I64", "Nat");

				public ULONGLONG I64;
				public BOOL Nat; // Always false for non-Itanium

				@Override
				protected List<String> getFieldOrder() {
					return FIELDS;
				}
			}

			public static class I64Parts32 extends Structure {
				public static class ByReference extends UNION implements Structure.ByReference {
				}

				@SuppressWarnings("hiding")
				public static final List<String> FIELDS = createFieldsOrder("LowPart", "HighPart");

				public ULONG LowPart;
				public ULONG HighPart;

				@Override
				protected List<String> getFieldOrder() {
					return FIELDS;
				}
			}

			public static class F128Parts64 extends Structure {
				public static class ByReference extends UNION implements Structure.ByReference {
				}

				@SuppressWarnings("hiding")
				public static final List<String> FIELDS = createFieldsOrder("LowPart", "HighPart");

				public ULONGLONG LowPart;
				public LONGLONG HighPart;

				@Override
				protected List<String> getFieldOrder() {
					return FIELDS;
				}
			}

			public UCHAR I8;
			public USHORT I16;
			public ULONG I32;
			public INTEGER64 I64;
			public float F32;
			public double F64;
			public byte[] F80Bytes = new byte[10];
			public byte[] F82Bytes = new byte[11];
			public byte[] F128Bytes = new byte[16];

			public byte[] VI8 = new byte[16];
			public short[] VI16 = new short[8];
			public int[] VI32 = new int[4];
			public long[] VI64 = new long[2];

			public float[] VF32 = new float[4];
			public double[] VF64 = new double[2];

			public I64Parts32 I64Parts32;
			public F128Parts64 F128Parts64;

			public byte[] RawBytes = new byte[24];
		}

		public UNION u;
		public ULONG TailOfRawBytes;
		public ULONG Type;

		@Override
		protected List<String> getFieldOrder() {
			return FIELDS;
		}

		protected void doUSetType() {
			switch (DebugValueType.values()[Type.intValue()]) {
				case INVALID:
					u.setType("RawBytes");
					break;
				case INT8:
					u.setType("I8");
					break;
				case INT16:
					u.setType("I16");
					break;
				case INT32:
					u.setType("I32");
					break;
				case INT64:
					u.setType("I64");
					break;
				case FLOAT32:
					u.setType("F32");
					break;
				case FLOAT64:
					u.setType("F64");
					break;
				case FLOAT80:
					u.setType("F80Bytes");
					break;
				case FLOAT82:
					u.setType("F82Bytes");
					break;
				case FLOAT128:
					u.setType("F128Bytes");
					break;
				case VECTOR64:
					u.setType("VI8");
					break;
				case VECTOR128:
					u.setType("VI8");
					break; // TODO: Can I activate multiple types?
			}
		}

		@Override
		public void read() {
			super.read();
			doUSetType();
			u.read();
		}

		@Override
		public void write() {
			super.write();
			doUSetType();
			u.write();
		}

		@SuppressWarnings("unchecked")
		public <T extends DebugValue> T convertTo(Class<T> desiredType) {
			if (desiredType != null && desiredType != DebugValue.class &&
				DebugValueType.getDebugValueTypeForClass(desiredType).ordinal() != Type
						.intValue()) {
				// TODO: Display value in exception
				throw new ClassCastException("debug value is not of the desired type");
			}
			switch (DebugValueType.values()[Type.intValue()]) {
				case INVALID:
					return null; // TODO: Some DebugInvalidWrapper class?
				case INT8:
					return (T) new DebugInt8Value(u.I8.byteValue());
				case INT16:
					return (T) new DebugInt16Value(u.I16.shortValue());
				case INT32:
					return (T) new DebugInt32Value(u.I32.intValue());
				case INT64:
					return (T) new DebugInt64Value(u.I64.I64.longValue());
				case FLOAT32:
					return (T) new DebugFloat32Value(u.F32);
				case FLOAT64:
					return (T) new DebugFloat64Value(u.F64);
				case FLOAT80:
					return (T) new DebugFloat80Value(u.F80Bytes);
				case FLOAT82:
					return (T) new DebugFloat82Value(u.F82Bytes);
				case FLOAT128:
					return (T) new DebugFloat128Value(u.F128Bytes);
				case VECTOR64:
					return (T) new DebugVector128Value(u.VI8);
				case VECTOR128:
					return (T) new DebugVector128Value(u.VI8);
			}
			throw new AssertionError("INTERNAL: Shouldn't be here");
		}

		public static DEBUG_VALUE fromDebugValue(DebugValue value) {
			DEBUG_VALUE result = new DEBUG_VALUE();
			fromDebugValue(result, value);
			return result;
		}

		public static void fromDebugValue(DEBUG_VALUE into, DebugValue value) {
			DebugValueType type = DebugValueType.getDebugValueTypeForClass(value.getClass());
			into.Type = new ULONG(type.ordinal());
			switch (type) {
				case INVALID:
					break;
				case INT8:
					DebugInt8Value int8 = (DebugInt8Value) value;
					into.u.I8 = new UCHAR(int8.byteValue());
					break;
				case INT16:
					DebugInt16Value int16 = (DebugInt16Value) value;
					into.u.I16 = new USHORT(int16.shortValue());
					break;
				case INT32:
					DebugInt32Value int32 = (DebugInt32Value) value;
					into.u.I32 = new ULONG(int32.intValue());
					break;
				case INT64:
					DebugInt64Value int64 = (DebugInt64Value) value;
					into.u.I64.I64 = new ULONGLONG(int64.longValue());
					break;
				case FLOAT32:
					DebugFloat32Value float32 = (DebugFloat32Value) value;
					into.u.F32 = float32.floatValue();
					break;
				case FLOAT64:
					DebugFloat64Value float64 = (DebugFloat64Value) value;
					into.u.F64 = float64.doubleValue();
					break;
				case FLOAT80:
					DebugFloat80Value float80 = (DebugFloat80Value) value;
					into.u.F80Bytes = float80.bytes();
					break;
				case FLOAT82:
					DebugFloat82Value float82 = (DebugFloat82Value) value;
					into.u.F82Bytes = float82.bytes();
					break;
				case FLOAT128:
					DebugFloat128Value float128 = (DebugFloat128Value) value;
					into.u.F128Bytes = float128.bytes();
					break;
				case VECTOR64:
					DebugVector64Value vector64 = (DebugVector64Value) value;
					into.u.VI8 = vector64.vi4(); // TODO: Copy Into?
					break;
				case VECTOR128:
					DebugVector128Value vector128 = (DebugVector128Value) value;
					into.u.VI8 = vector128.vi8(); // TODO: Copy Into?
					break;
				default:
					throw new AssertionError("INTERNAL: Shouldn't be here");
			}
		}
	}

	public class DEBUG_MODULE_AND_ID extends Structure {
		public static class ByReference extends DEBUG_MODULE_AND_ID
				implements Structure.ByReference {
		}

		public static final List<String> FIELDS = createFieldsOrder("ModuleBase", "Id");

		public ULONGLONG ModuleBase;
		public ULONGLONG Id;

		@Override
		protected List<String> getFieldOrder() {
			return FIELDS;
		}
	}

	public class DEBUG_MODULE_PARAMETERS extends Structure {
		public static class ByReference extends DEBUG_MODULE_PARAMETERS
				implements Structure.ByReference {
		}

		public static final List<String> FIELDS =
			createFieldsOrder("Base", "Size", "TimeDateStamp", "Checksum", "Flags", "SymbolType",
				"ImageNameSize", "ModuleNameSize", "LoadedImageNameSize", "SymbolFileNameSize",
				"MappedImageNameSize", "Reserved0", "Reserved1");

		public ULONGLONG Base;
		public ULONG Size;
		public ULONG TimeDateStamp;
		public ULONG Checksum;
		public ULONG Flags;
		public ULONG SymbolType;
		public ULONG ImageNameSize;
		public ULONG ModuleNameSize;
		public ULONG LoadedImageNameSize;
		public ULONG SymbolFileNameSize;
		public ULONG MappedImageNameSize;
		public ULONGLONG Reserved0;
		public ULONGLONG Reserved1;

		@Override
		protected List<String> getFieldOrder() {
			return FIELDS;
		}
	}

	public class DEBUG_SYMBOL_ENTRY extends Structure {
		public static class ByReference extends DEBUG_SYMBOL_ENTRY
				implements Structure.ByReference {
		}

		public static final List<String> FIELDS = createFieldsOrder("ModuleBase", "Offset", "Id",
			"Arg64", "Size", "Flags", "TypeId", "NameSize", "Token", "Tag", "Arg32", "Reserved");

		public ULONGLONG ModuleBase;
		public ULONGLONG Offset;
		public ULONGLONG Id;
		public ULONGLONG Arg64;
		public ULONG Size;
		public ULONG Flags;
		public ULONG TypeId;
		public ULONG NameSize;
		public ULONG Token;
		public ULONG Tag;
		public ULONG Arg32;
		public ULONG Reserved;

		@Override
		protected List<String> getFieldOrder() {
			return FIELDS;
		}
	}

	public class DEBUG_THREAD_BASIC_INFORMATION extends Structure {
		public static class ByReference extends DEBUG_THREAD_BASIC_INFORMATION
				implements Structure.ByReference {
		}

		public static final List<String> FIELDS =
			createFieldsOrder("Valid", "ExitStatus", "PriorityClass", "Priority", "CreateTime",
				"ExitTime", "KernelTime", "UserTime", "StartOffset", "Affinity");

		public ULONG Valid;
		public ULONG ExitStatus;
		public ULONG PriorityClass;
		public ULONG Priority;
		public ULONGLONG CreateTime;
		public ULONGLONG ExitTime;
		public ULONGLONG KernelTime;
		public ULONGLONG UserTime;
		public ULONGLONG StartOffset;
		public ULONGLONG Affinity;

		@Override
		protected List<String> getFieldOrder() {
			return FIELDS;
		}
	}

	public class DEBUG_STACK_FRAME extends Structure {
		public static class ByReference extends DEBUG_STACK_FRAME implements Structure.ByReference {
		}

		public static final List<String> FIELDS =
			createFieldsOrder("InstructionOffset", "ReturnOffset", "FrameOffset", "StackOffset",
				"FuncTableEntry", "Params", "Reserved", "Virtual", "FrameNumber");

		public ULONGLONG InstructionOffset;
		public ULONGLONG ReturnOffset;
		public ULONGLONG FrameOffset;
		public ULONGLONG StackOffset;
		public ULONGLONG FuncTableEntry;
		public ULONGLONG[] Params = new ULONGLONG[4];
		public ULONGLONG[] Reserved = new ULONGLONG[6];
		public BOOL Virtual;
		public ULONG FrameNumber;

		@Override
		protected List<String> getFieldOrder() {
			return FIELDS;
		}
	}

	public class DEBUG_SPECIFIC_FILTER_PARAMETERS extends Structure {
		public static class ByReference extends DEBUG_SPECIFIC_FILTER_PARAMETERS
				implements Structure.ByReference {
		}

		public static final List<String> FIELDS =
			createFieldsOrder("ExecutionOption", "ContinueOption", "TextSize", "CommandSize",
				"ArgumentSize");

		public ULONG ExecutionOption;
		public ULONG ContinueOption;
		public ULONG TextSize;
		public ULONG CommandSize;
		public ULONG ArgumentSize;

		@Override
		protected List<String> getFieldOrder() {
			return FIELDS;
		}
	}

	public class DEBUG_EXCEPTION_FILTER_PARAMETERS extends Structure {
		public static class ByReference extends DEBUG_EXCEPTION_FILTER_PARAMETERS
				implements Structure.ByReference {
		}

		public static final List<String> FIELDS =
			createFieldsOrder("ExecutionOption", "ContinueOption", "TextSize", "CommandSize",
				"SecondCommandSize", "ExceptionCode");

		public ULONG ExecutionOption;
		public ULONG ContinueOption;
		public ULONG TextSize;
		public ULONG CommandSize;
		public ULONG SecondCommandSize;
		public ULONG ExceptionCode;

		@Override
		protected List<String> getFieldOrder() {
			return FIELDS;
		}
	}

}
