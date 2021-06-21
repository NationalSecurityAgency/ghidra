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
package agent.dbgmodel.jna.dbgmodel;

import java.util.List;

import com.sun.jna.*;
import com.sun.jna.platform.win32.Guid.REFIID;
import com.sun.jna.platform.win32.WinDef.DWORD;
import com.sun.jna.platform.win32.WinDef.ULONGLONG;
import com.sun.jna.platform.win32.WinNT.HRESULT;
import com.sun.jna.ptr.PointerByReference;
import com.sun.jna.win32.StdCallLibrary;

public interface DbgModelNative extends StdCallLibrary {
	DbgModelNative INSTANCE = Native.load("dbgmodel.dll", DbgModelNative.class);

	HRESULT DebugConnect(String RemoteOptions, REFIID InterfaceId, PointerByReference Interface);

	HRESULT DebugConnectWide(WString RemoteOptions, REFIID InterfaceId,
			PointerByReference Interface);

	HRESULT DebugCreate(REFIID InterfaceId, PointerByReference Interface);

	HRESULT DebugCreateEx(REFIID InterfaceId, DWORD DbgEngOptions, PointerByReference Interface);

	public static enum ModelObjectKind {
		OBJECT_PROPERTY_ACCESSOR,
		OBJECT_CONTEXT,
		OBJECT_TARGET_OBJECT,
		OBJECT_TARGET_OBJECT_REFERENCE,
		OBJECT_SYNTHETIC,
		OBJECT_NO_VALUE,
		OBJECT_ERROR,
		OBJECT_INTRINSIC,
		OBJECT_METHOD,
		OBJECT_KEY_REFERENCE;
	}

	public static enum SymbolKind {
		SYMBOL,
		SYMBOL_MODULE,
		SYMBOL_TYPE,
		SYMBOL_FIELD,
		SYMBOL_CONSTANT,
		SYMBOL_DATA,
		SYMBOL_BASE_CLASS,
		SYMBOL_PUBLIC,
		SYMBOL_FUNCTION;
	}

	public static enum TypeKind {
		TYPE_UDT,
		TYPE_POINTER,
		TYPE_MEMBER_POINTER,
		TYPE_ARRAY,
		TYPE_FUNCTION,
		TYPE_TYPEDEF,
		TYPE_ENUM,
		TYPE_INTRINSIC;
	}

	public static enum IntrinsicKind {
		INTRINSIC_VOID,
		INTRINSIC_BOOL,
		INTRINSIC_CHAR,
		INTRINSIC_WCHAR,
		INTRINSIC_INT,
		INTRINSIC_UINT,
		INTRINSIC_LONG,
		INTRINSIC_ULONG,
		INTRINSIC_FLOAT,
		INTRINSIC_HRESULT,
		INTRINSIC_CHAR16,
		INTRINSIC_CHAR32;
	}

	public static enum PointerKind {
		POINTER_STANDARD, POINTER_REFERENCE, POINTER_VALUE_REFERENCE, POINTER_CX_HAT;
	}

	public static enum CallingConventionKind {
		CALLING_CONVENTION_UNKNOWN,
		CALLING_CONVENTION_CDECL,
		CALLING_CONVENTION_FASTCALL,
		CALLING_CONVENTION_STDCALL,
		CALLING_CONVENTION_SYSCALL,
		CALLING_CONVENTION_THISCALL;
	}

	public static enum LocationKind {
		LOCATION_MEMBER, LOCATION_STATIC, LOCATION_CONSTANT, LOCATION_NONE;
	}

	public static enum PreferredFormat {
		FORMAT_NONE,
		FORMAT_SINGLE_CHARACTER,
		FORMAT_QUOTED_STRING,
		FORMAT_STRING,
		FORMAT_QUOTED_UNICODE_STRING,
		FORMAT_UNICODE_STRING,
		FORMAT_QUOTED_UTF8_STRING,
		FORMAT_UTF8_STRING,
		FORMAT_BSTR_STRING,
		FORMAT_QUOTED_HSTRING,
		FORMAT_HSTRING,
		FORMAT_RAW,
		FORMAT_ENUM_NAME_ONLY,
		FORMAT_ESCAPED_STRING_WITH_QUOTE,
		FORMAT_UTF32_STRING,
		FORMAT_QUOTED_UTF32_STRING;
	}

	public static class LOCATION extends Structure {
		public static class ByReference extends LOCATION
				implements Structure.ByReference {
		}

		public LOCATION() {
			this.HostDefined = new ULONGLONG(0);
			this.Offset = new ULONGLONG(0);
		}

		public LOCATION(ULONGLONG virtualAddress) {
			this.HostDefined = new ULONGLONG(0);
			this.Offset = virtualAddress;
		}

		public LOCATION(ByReference pLocation) {
			this.HostDefined = pLocation.HostDefined;
			this.Offset = pLocation.Offset;
		}

		public static final List<String> FIELDS = createFieldsOrder("HostDefined", "Offset");

		public ULONGLONG HostDefined;
		public ULONGLONG Offset;

		@Override
		protected List<String> getFieldOrder() {
			return FIELDS;
		}
	}

	public static class ARRAY_DIMENSION extends Structure {
		public static class ByReference extends ARRAY_DIMENSION
				implements Structure.ByReference {

			public ByReference() {
				super();
				// TODO Auto-generated constructor stub
			}
		}

		public ARRAY_DIMENSION() {
			// TODO Auto-generated constructor stub
		}

		public ARRAY_DIMENSION(ByReference pLocation) {
			// TODO Auto-generated constructor stub
		}

		@Override
		protected List<String> getFieldOrder() {
			// TODO Auto-generated method stub
			return null;
		}
	}

}
