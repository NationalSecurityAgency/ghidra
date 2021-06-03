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
import com.sun.jna.platform.win32.Variant.VARIANT;
import com.sun.jna.platform.win32.WinDef.ULONGByReference;
import com.sun.jna.platform.win32.WinDef.ULONGLONGByReference;

import agent.dbgmodel.jna.dbgmodel.DbgModelNative.LOCATION;
import agent.dbgmodel.jna.dbgmodel.debughost.IDebugHostField;

import com.sun.jna.platform.win32.COM.COMUtils;

public class DebugHostFieldImpl extends DebugHostBaseClassImpl implements DebugHostFieldInternal {
	@SuppressWarnings("unused")
	private final IDebugHostField jnaData;

	public DebugHostFieldImpl(IDebugHostField jnaData) {
		super(jnaData);
		this.jnaData = jnaData;
	}

	@Override
	public Pointer getPointer() {
		return jnaData.getPointer();
	}

	@Override
	public int getLocationKind() {
		ULONGByReference pulLocationKind = new ULONGByReference();
		COMUtils.checkRC(jnaData.GetLocationKind(pulLocationKind));
		return pulLocationKind.getValue().intValue();
	}

	@Override
	public long getOffset() {
		ULONGLONGByReference ppOffset = new ULONGLONGByReference();
		COMUtils.checkRC(jnaData.GetOffset(ppOffset));
		return ppOffset.getValue().longValue();
	}

	@Override
	public LOCATION getLocation() {
		LOCATION.ByReference pLocation = new LOCATION.ByReference();
		COMUtils.checkRC(jnaData.GetLocation(pLocation));
		return new LOCATION(pLocation);
	}

	@Override
	public VARIANT getValue() {
		VARIANT.ByReference pValue = new VARIANT.ByReference();
		COMUtils.checkRC(jnaData.GetValue(pValue));
		return (VARIANT) pValue.getValue();
	}

}
