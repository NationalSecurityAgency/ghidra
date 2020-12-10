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
package agent.dbgmodel.jna.dbgmodel.debughost;

import com.sun.jna.platform.win32.Guid.IID;
import com.sun.jna.platform.win32.WTypes.VARTYPEByReference;
import com.sun.jna.platform.win32.WinDef.*;
import com.sun.jna.platform.win32.WinNT.HRESULT;
import com.sun.jna.ptr.PointerByReference;

import agent.dbgmodel.jna.dbgmodel.DbgModelNative.ARRAY_DIMENSION.ByReference;
import agent.dbgmodel.jna.dbgmodel.UnknownWithUtils.VTableIndex;

public interface IDebugHostType1 extends IDebugHostBaseClass {
	final IID IID_IDEBUG_HOST_TYPE = new IID("3AADC353-2B14-4abb-9893-5E03458E07EE");

	enum VTIndices1 implements VTableIndex {
		GET_TYPE_KIND, //
		GET_SIZE, //
		GET_BASE_TYPE, //
		GET_HASH_CODE, //
		GET_INTRINSIC_TYPE, //
		GET_BIT_FIELD, //
		GET_POINTER_KIND, //
		GET_MEMBER_TYPE, //
		CREATE_POINTER_TO, //
		GET_ARRAY_DIMENSIONALITY, //
		GET_ARRAY_DIMENSIONS, //
		CREATE_ARRAY_OF, //
		GET_FUNCTION_CALLING_CONVENTION, //
		GET_FUNCTION_RETURN_TYPE, //
		GET_FUNCTION_PARAMETER_TYPE_COUNT, //
		GET_FUNCTION_PARAMETER_TYPE_AT, //
		IS_GENERIC, //
		GET_GENERIC_ARGUMENT_COUNT, //
		GET_GENERIC_ARGUMENT_AT, //
		;

		public int start = VTableIndex.follow(VTIndices.class);

		@Override
		public int getIndex() {
			return this.ordinal() + start;
		}
	}

	HRESULT GetTypeKind(ULONGByReference kind);  // TypeKind*

	HRESULT GetSize(ULONGLONGByReference pulSize);

	HRESULT GetBaseType(PointerByReference baseType);

	HRESULT GetHashCode(ULONGByReference hashCode);

	HRESULT GetIntrinsicType(ULONGByReference pulIntrinsicKind, VARTYPEByReference pCarrierType);

	HRESULT GetBitField(ULONGByReference lsbOfField, ULONGByReference lengthOfField);

	HRESULT GetPointerKind(ULONGByReference pointerKind);  // PointerKind*

	HRESULT GetMemberType(PointerByReference memberType);

	HRESULT CreatePointerTo(ULONG kind, PointerByReference newType);  // PointerKind

	HRESULT GetArrayDimensionality(ULONGLONGByReference pulArrayDimensionality);

	HRESULT GetArrayDimensions(ULONGLONG pDimensions, ByReference ppDimensions);

	HRESULT CreateArrayOf(ULONGLONG ulDimensions, ByReference pDimensions,
			PointerByReference newType);

	HRESULT GetFunctionCallingConvention(ULONGByReference conventionKind);  // ConventionKind*

	HRESULT GetFunctionReturnType(PointerByReference returnType);

	HRESULT GetFunctionParameterTypeCount(ULONGByReference count);

	HRESULT GetFunctionParameterTypeAt(ULONG i, PointerByReference parameterType);

	HRESULT IsGeneric(BOOLByReference isGeneric);

	HRESULT GetGenericArgumentCount(ULONGLONGByReference pulArgCount);

	HRESULT GetGenericArgumentAt(ULONG i, PointerByReference argument);

}
