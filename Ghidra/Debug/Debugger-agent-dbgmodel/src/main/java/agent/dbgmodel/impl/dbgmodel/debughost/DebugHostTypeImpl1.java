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
package agent.dbgmodel.impl.dbgmodel.debughost;

import com.sun.jna.Pointer;
import com.sun.jna.platform.win32.WTypes.VARTYPE;
import com.sun.jna.platform.win32.WTypes.VARTYPEByReference;
import com.sun.jna.platform.win32.WinDef.*;
import com.sun.jna.platform.win32.WinNT.HRESULT;
import com.sun.jna.platform.win32.COM.COMUtils;
import com.sun.jna.ptr.PointerByReference;

import agent.dbgmodel.dbgmodel.COMUtilsExtra;
import agent.dbgmodel.dbgmodel.debughost.DebugHostSymbol1;
import agent.dbgmodel.dbgmodel.debughost.DebugHostType1;
import agent.dbgmodel.jna.dbgmodel.DbgModelNative.*;
import agent.dbgmodel.jna.dbgmodel.debughost.*;

public class DebugHostTypeImpl1 extends DebugHostBaseClassImpl implements DebugHostTypeInternal {
	@SuppressWarnings("unused")
	private final IDebugHostType1 jnaData;

	private ULONG intrinsicKind;
	private VARTYPE carrierType;
	private ULONG lsbOfField;
	private ULONG lengthOfField;

	public DebugHostTypeImpl1(IDebugHostType1 jnaData) {
		super(jnaData);
		this.jnaData = jnaData;
	}

	@Override
	public Pointer getPointer() {
		return jnaData.getPointer();
	}

	@Override
	public TypeKind getTypeKind() {
		ULONGByReference pulKind = new ULONGByReference();
		COMUtils.checkRC(jnaData.GetTypeKind(pulKind));
		return TypeKind.values()[pulKind.getValue().intValue()];
	}

	@Override
	public long getSize() {
		ULONGLONGByReference pulSize = new ULONGLONGByReference();
		COMUtils.checkRC(jnaData.GetSize(pulSize));
		return pulSize.getValue().longValue();
	}

	@Override
	public DebugHostType1 getBaseType() {
		PointerByReference ppBaseType = new PointerByReference();
		HRESULT hr = jnaData.GetBaseType(ppBaseType);
		if (hr.equals(COMUtilsExtra.E_FAIL)) {
			return null;
		}
		COMUtils.checkRC(hr);

		WrapIDebugHostType1 wrap = new WrapIDebugHostType1(ppBaseType.getValue());
		try {
			return DebugHostTypeInternal.tryPreferredInterfaces(wrap::QueryInterface);
		}
		finally {
			wrap.Release();
		}
	}

	@Override
	public int getHashCode() {
		ULONGByReference pulHashCode = new ULONGByReference();
		COMUtils.checkRC(jnaData.GetHashCode(pulHashCode));
		return pulHashCode.getValue().intValue();
	}

	@Override
	public IntrinsicKind getIntrinsicType() {
		ULONGByReference pulIntrinsicKind = new ULONGByReference();
		VARTYPEByReference pCarrierType = new VARTYPEByReference();
		HRESULT hr = jnaData.GetIntrinsicType(pulIntrinsicKind, pCarrierType);
		if (hr.equals(COMUtilsExtra.E_FAIL)) {
			return null;
		}
		COMUtils.checkRC(hr);

		carrierType = pCarrierType.getValue();
		int intValue = pulIntrinsicKind.getValue().intValue();
		return IntrinsicKind.values()[intValue];
	}

	@Override
	public void getBitField() {
		ULONGByReference pulLsbOfField = new ULONGByReference();
		ULONGByReference pulLengthOfField = new ULONGByReference();
		COMUtils.checkRC(jnaData.GetBitField(pulLsbOfField, pulLengthOfField));
		lsbOfField = pulLsbOfField.getValue();
		lengthOfField = pulLengthOfField.getValue();
	}

	@Override
	public PointerKind getPointerKind() {
		ULONGByReference pulPointerKind = new ULONGByReference();
		HRESULT hr = jnaData.GetPointerKind(pulPointerKind);
		if (hr.equals(COMUtilsExtra.E_FAIL)) {
			return null;
		}
		COMUtils.checkRC(hr);
		return PointerKind.values()[pulPointerKind.getValue().intValue()];
	}

	@Override
	public DebugHostType1 getMemberType() {
		PointerByReference ppMemberType = new PointerByReference();
		COMUtils.checkRC(jnaData.GetMemberType(ppMemberType));

		WrapIDebugHostType1 wrap = new WrapIDebugHostType1(ppMemberType.getValue());
		try {
			return DebugHostTypeInternal.tryPreferredInterfaces(wrap::QueryInterface);
		}
		finally {
			wrap.Release();
		}
	}

	@Override
	public DebugHostType1 createPointerTo(int kind) {
		ULONG ulKind = new ULONG(kind);
		PointerByReference ppMemberType = new PointerByReference();
		COMUtils.checkRC(jnaData.CreatePointerTo(ulKind, ppMemberType));

		WrapIDebugHostType1 wrap = new WrapIDebugHostType1(ppMemberType.getValue());
		try {
			return DebugHostTypeInternal.tryPreferredInterfaces(wrap::QueryInterface);
		}
		finally {
			wrap.Release();
		}
	}

	@Override
	public long getArrayDimensionality() {
		ULONGLONGByReference pulArrayDimensionality = new ULONGLONGByReference();
		COMUtils.checkRC(jnaData.GetArrayDimensionality(pulArrayDimensionality));
		return pulArrayDimensionality.getValue().longValue();
	}

	@Override
	public ARRAY_DIMENSION getArrayDimensions(long dimensions) {
		ULONGLONG pDimensions = new ULONGLONG(dimensions);
		ARRAY_DIMENSION.ByReference ppDimensions = new ARRAY_DIMENSION.ByReference();
		COMUtils.checkRC(jnaData.GetArrayDimensions(pDimensions, ppDimensions));
		return new ARRAY_DIMENSION(ppDimensions);
	}

	@Override
	public DebugHostType1 createArrayOf(long dimensions, ARRAY_DIMENSION.ByReference pDimensions) {
		ULONGLONG ulDimensions = new ULONGLONG(dimensions);
		PointerByReference ppNewType = new PointerByReference();
		COMUtils.checkRC(jnaData.CreateArrayOf(ulDimensions, pDimensions, ppNewType));

		WrapIDebugHostType1 wrap = new WrapIDebugHostType1(ppNewType.getValue());
		try {
			return DebugHostTypeInternal.tryPreferredInterfaces(wrap::QueryInterface);
		}
		finally {
			wrap.Release();
		}
	}

	@Override
	public int getFunctionCallingConvention() {
		ULONGByReference pulConventionKind = new ULONGByReference();
		COMUtils.checkRC(jnaData.GetFunctionCallingConvention(pulConventionKind));
		return pulConventionKind.getValue().intValue();
	}

	@Override
	public DebugHostType1 getFunctionReturnType() {
		PointerByReference ppReturnType = new PointerByReference();
		COMUtils.checkRC(jnaData.GetFunctionReturnType(ppReturnType));

		WrapIDebugHostType1 wrap = new WrapIDebugHostType1(ppReturnType.getValue());
		try {
			return DebugHostTypeInternal.tryPreferredInterfaces(wrap::QueryInterface);
		}
		finally {
			wrap.Release();
		}
	}

	@Override
	public DebugHostType1 getFunctionParameterTypeAt(int i) {
		ULONG ulI = new ULONG(i);
		PointerByReference ppReturnType = new PointerByReference();
		COMUtils.checkRC(jnaData.GetFunctionParameterTypeAt(ulI, ppReturnType));

		WrapIDebugHostType1 wrap = new WrapIDebugHostType1(ppReturnType.getValue());
		try {
			return DebugHostTypeInternal.tryPreferredInterfaces(wrap::QueryInterface);
		}
		finally {
			wrap.Release();
		}
	}

	@Override
	public boolean isGeneric() {
		BOOLByReference bIsGeneric = new BOOLByReference();
		COMUtils.checkRC(jnaData.IsGeneric(bIsGeneric));
		return bIsGeneric.getValue().booleanValue();
	}

	@Override
	public long getGenericArgumentCount() {
		ULONGLONGByReference pulArgCount = new ULONGLONGByReference();
		COMUtils.checkRC(jnaData.GetGenericArgumentCount(pulArgCount));
		return pulArgCount.getValue().longValue();
	}

	@Override
	public DebugHostSymbol1 getGenericArgumentAt(int i) {
		ULONG ulI = new ULONG(i);
		PointerByReference ppArgument = new PointerByReference();
		COMUtils.checkRC(jnaData.GetGenericArgumentAt(ulI, ppArgument));

		WrapIDebugHostSymbol1 wrap = new WrapIDebugHostSymbol1(ppArgument.getValue());
		try {
			return DebugHostSymbolInternal.tryPreferredInterfaces(wrap::QueryInterface);
		}
		finally {
			wrap.Release();
		}
	}

	public ULONG getIntrinsicKind() {
		return intrinsicKind;
	}

	public VARTYPE getCarrierType() {
		return carrierType;
	}

	public ULONG getLsbOfField() {
		return lsbOfField;
	}

	public ULONG getLengthOfField() {
		return lengthOfField;
	}

}
