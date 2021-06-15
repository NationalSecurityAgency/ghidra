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

import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import com.sun.jna.platform.win32.WTypes.VARTYPEByReference;
import com.sun.jna.platform.win32.WinDef.*;
import com.sun.jna.platform.win32.WinNT.HRESULT;
import com.sun.jna.ptr.PointerByReference;

import agent.dbgmodel.jna.dbgmodel.DbgModelNative.ARRAY_DIMENSION;

public class WrapIDebugHostType1 extends WrapIDebugHostBaseClass implements IDebugHostType1 {
	public static class ByReference extends WrapIDebugHostType1 implements Structure.ByReference {
	}

	public WrapIDebugHostType1() {
	}

	public WrapIDebugHostType1(Pointer pvInstance) {
		super(pvInstance);
	}

	@Override
	public HRESULT GetTypeKind(ULONGByReference kind) {
		return _invokeHR(VTIndices1.GET_TYPE_KIND, getPointer(), kind);
	}  // TypeKind*

	@Override
	public HRESULT GetSize(ULONGLONGByReference size) {
		return _invokeHR(VTIndices1.GET_SIZE, getPointer(), size);
	}

	@Override
	public HRESULT GetBaseType(PointerByReference baseType) {
		return _invokeHR(VTIndices1.GET_BASE_TYPE, getPointer(), baseType);
	}

	@Override
	public HRESULT GetHashCode(ULONGByReference hashCode) {
		return _invokeHR(VTIndices1.GET_HASH_CODE, getPointer(), hashCode);
	}

	@Override
	public HRESULT GetIntrinsicType(ULONGByReference intrinsicKind,
			VARTYPEByReference carrierType) {
		return _invokeHR(VTIndices1.GET_INTRINSIC_TYPE, getPointer(), intrinsicKind, carrierType);
	}

	@Override
	public HRESULT GetBitField(ULONGByReference lsbOfField, ULONGByReference lengthOfField) {
		return _invokeHR(VTIndices1.GET_BIT_FIELD, getPointer(), lsbOfField, lengthOfField);
	}

	@Override
	public HRESULT GetPointerKind(ULONGByReference pointerKind) {
		return _invokeHR(VTIndices1.GET_POINTER_KIND, getPointer(), pointerKind);
	}  // PointerKind*

	@Override
	public HRESULT GetMemberType(PointerByReference memberType) {
		return _invokeHR(VTIndices1.GET_MEMBER_TYPE, getPointer(), memberType);
	}

	@Override
	public HRESULT CreatePointerTo(ULONG kind, PointerByReference newType) {
		return _invokeHR(VTIndices1.CREATE_POINTER_TO, getPointer(), kind, newType);
	}  // PointerKind

	@Override
	public HRESULT GetArrayDimensionality(ULONGLONGByReference arrayDimensionality) {
		return _invokeHR(VTIndices1.GET_ARRAY_DIMENSIONALITY, getPointer(), arrayDimensionality);
	}

	@Override
	public HRESULT GetArrayDimensions(ULONGLONG dimensions,
			ARRAY_DIMENSION.ByReference pDimensions) {
		return _invokeHR(VTIndices1.GET_ARRAY_DIMENSIONS, getPointer(), dimensions, pDimensions);
	}

	@Override
	public HRESULT CreateArrayOf(ULONGLONG dimensions, ARRAY_DIMENSION.ByReference pDimensions,
			PointerByReference newType) {
		return _invokeHR(VTIndices1.CREATE_ARRAY_OF, getPointer(), dimensions, pDimensions,
			newType);
	}

	@Override
	public HRESULT GetFunctionCallingConvention(ULONGByReference conventionKind) {
		return _invokeHR(VTIndices1.GET_FUNCTION_CALLING_CONVENTION, getPointer(), conventionKind);
	}  // ConventionKind*

	@Override
	public HRESULT GetFunctionReturnType(PointerByReference returnType) {
		return _invokeHR(VTIndices1.GET_FUNCTION_RETURN_TYPE, getPointer(), returnType);
	}

	@Override
	public HRESULT GetFunctionParameterTypeCount(ULONGByReference count) {
		return _invokeHR(VTIndices1.GET_FUNCTION_PARAMETER_TYPE_COUNT, getPointer(), count);
	}

	@Override
	public HRESULT GetFunctionParameterTypeAt(ULONG i, PointerByReference parameterType) {
		return _invokeHR(VTIndices1.GET_FUNCTION_PARAMETER_TYPE_AT, getPointer(), i, parameterType);
	}

	@Override
	public HRESULT IsGeneric(BOOLByReference isGeneric) {
		return _invokeHR(VTIndices1.IS_GENERIC, getPointer(), isGeneric);
	}

	@Override
	public HRESULT GetGenericArgumentCount(ULONGLONGByReference argCount) {
		return _invokeHR(VTIndices1.GET_GENERIC_ARGUMENT_COUNT, getPointer(), argCount);
	}

	@Override
	public HRESULT GetGenericArgumentAt(ULONG i, PointerByReference argument) {
		return _invokeHR(VTIndices1.GET_GENERIC_ARGUMENT_AT, getPointer(), i, argument);
	}
}
