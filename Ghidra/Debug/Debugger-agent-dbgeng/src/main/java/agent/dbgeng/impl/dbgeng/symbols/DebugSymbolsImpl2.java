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
package agent.dbgeng.impl.dbgeng.symbols;

import com.sun.jna.Native;
import com.sun.jna.platform.win32.WinDef.*;

import agent.dbgeng.dbgeng.DebugModule;
import agent.dbgeng.dbgeng.DebugModule.DebugModuleName;
import agent.dbgeng.impl.dbgeng.DbgEngUtil;
import agent.dbgeng.jna.dbgeng.symbols.IDebugSymbols2;

import com.sun.jna.platform.win32.COM.COMUtils;

public class DebugSymbolsImpl2 extends DebugSymbolsImpl1 {
	private final IDebugSymbols2 jnaSymbols;

	public DebugSymbolsImpl2(IDebugSymbols2 jnaSymbols) {
		super(jnaSymbols);
		this.jnaSymbols = jnaSymbols;
	}

	@Override
	public String getModuleName(DebugModuleName which, DebugModule module) {
		ULONG ulWhich = new ULONG(which.ordinal());
		ULONGLONG ullBase = new ULONGLONG(module.getBase());
		ULONGByReference pulNameSize = new ULONGByReference();
		COMUtils.checkRC(jnaSymbols.GetModuleNameString(ulWhich, DbgEngUtil.DEBUG_ANY_ID, ullBase,
			null, new ULONG(0), pulNameSize));
		byte[] aBuffer = new byte[pulNameSize.getValue().intValue()];
		COMUtils.checkRC(jnaSymbols.GetModuleNameString(ulWhich, DbgEngUtil.DEBUG_ANY_ID, ullBase,
			aBuffer, pulNameSize.getValue(), null));
		return Native.toString(aBuffer);
	}
}
