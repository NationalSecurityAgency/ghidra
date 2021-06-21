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
import com.sun.jna.platform.win32.WinDef.BOOLByReference;
import com.sun.jna.platform.win32.WinDef.ULONGByReference;
import com.sun.jna.platform.win32.COM.COMUtils;
import com.sun.jna.ptr.PointerByReference;

import agent.dbgmodel.dbgmodel.DbgModel;
import agent.dbgmodel.dbgmodel.DbgModel.OpaqueCleanable;
import agent.dbgmodel.dbgmodel.debughost.DebugHostType1;
import agent.dbgmodel.dbgmodel.debughost.DebugHostTypeSignature;
import agent.dbgmodel.jna.dbgmodel.debughost.IDebugHostTypeSignature;
import agent.dbgmodel.jna.dbgmodel.main.WrapIModelObject;

public class DebugHostTypeSignatureImpl implements DebugHostTypeSignatureInternal {
	@SuppressWarnings("unused")
	private final OpaqueCleanable cleanable;
	private final IDebugHostTypeSignature jnaData;

	private DebugHostSymbolEnumeratorInternal wildcardMatches;

	public DebugHostTypeSignatureImpl(IDebugHostTypeSignature jnaData) {
		this.cleanable = DbgModel.releaseWhenPhantom(this, jnaData);
		this.jnaData = jnaData;
	}

	@Override
	public Pointer getPointer() {
		return jnaData.getPointer();
	}

	@Override
	public int getHashCode() {
		ULONGByReference pulHashCode = new ULONGByReference();
		COMUtils.checkRC(jnaData.GetHashCode(pulHashCode));
		return pulHashCode.getValue().intValue();
	}

	@Override
	public boolean isMatch(DebugHostType1 type) {
		Pointer pType = type.getPointer();
		BOOLByReference pIsMatch = new BOOLByReference();
		PointerByReference ppWildcardMatches = new PointerByReference();
		COMUtils.checkRC(jnaData.IsMatch(pType, pIsMatch, ppWildcardMatches));

		WrapIModelObject wrap1 = new WrapIModelObject(ppWildcardMatches.getValue());
		try {
			wildcardMatches =
				DebugHostSymbolEnumeratorInternal.tryPreferredInterfaces(wrap1::QueryInterface);
		}
		finally {
			wrap1.Release();
		}

		return pIsMatch.getValue().booleanValue();
	}

	@Override
	public int compareAgainst(DebugHostTypeSignature typeSignature) {
		Pointer pTypeSignature = typeSignature.getPointer();
		ULONGByReference pResult = new ULONGByReference();
		COMUtils.checkRC(jnaData.CompareAgainst(pTypeSignature, pResult));
		return pResult.getValue().intValue();
	}

	public DebugHostSymbolEnumeratorInternal getWildcardMatches() {
		return wildcardMatches;
	}
}
