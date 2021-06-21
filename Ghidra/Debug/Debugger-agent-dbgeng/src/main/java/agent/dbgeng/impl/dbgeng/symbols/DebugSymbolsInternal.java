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

import java.util.Map;

import com.google.common.collect.ImmutableMap;
import com.sun.jna.Pointer;
import com.sun.jna.platform.win32.Guid.REFIID;

import agent.dbgeng.dbgeng.*;
import agent.dbgeng.dbgeng.DebugModule.DebugModuleName;
import agent.dbgeng.impl.dbgeng.DbgEngUtil;
import agent.dbgeng.impl.dbgeng.DbgEngUtil.InterfaceSupplier;
import agent.dbgeng.jna.dbgeng.symbols.*;
import ghidra.util.datastruct.WeakValueHashMap;

public interface DebugSymbolsInternal extends DebugSymbols {
	final Map<Pointer, DebugSymbolsInternal> CACHE = new WeakValueHashMap<>();

	static DebugSymbolsInternal instanceFor(WrapIDebugSymbols symbols) {
		return DbgEngUtil.lazyWeakCache(CACHE, symbols, DebugSymbolsImpl1::new);
	}

	static DebugSymbolsInternal instanceFor(WrapIDebugSymbols2 symbols) {
		return DbgEngUtil.lazyWeakCache(CACHE, symbols, DebugSymbolsImpl2::new);
	}

	static DebugSymbolsInternal instanceFor(WrapIDebugSymbols3 symbols) {
		return DbgEngUtil.lazyWeakCache(CACHE, symbols, DebugSymbolsImpl3::new);
	}

	static DebugSymbolsInternal instanceFor(WrapIDebugSymbols4 symbols) {
		return DbgEngUtil.lazyWeakCache(CACHE, symbols, DebugSymbolsImpl4::new);
	}

	static DebugSymbolsInternal instanceFor(WrapIDebugSymbols5 symbols) {
		return DbgEngUtil.lazyWeakCache(CACHE, symbols, DebugSymbolsImpl5::new);
	}

	ImmutableMap.Builder<REFIID, Class<? extends WrapIDebugSymbols>> PREFERRED_SYMBOLS_IIDS_BUILDER =
		ImmutableMap.builder();
	Map<REFIID, Class<? extends WrapIDebugSymbols>> PREFFERED_SYMBOLS_IIDS =
		PREFERRED_SYMBOLS_IIDS_BUILDER //
				.put(new REFIID(IDebugSymbols5.IID_IDEBUG_SYMBOLS5), WrapIDebugSymbols5.class) //
				.put(new REFIID(IDebugSymbols4.IID_IDEBUG_SYMBOLS4), WrapIDebugSymbols4.class) //
				.put(new REFIID(IDebugSymbols3.IID_IDEBUG_SYMBOLS3), WrapIDebugSymbols3.class) //
				.put(new REFIID(IDebugSymbols2.IID_IDEBUG_SYMBOLS2), WrapIDebugSymbols2.class) //
				.put(new REFIID(IDebugSymbols.IID_IDEBUG_SYMBOLS), WrapIDebugSymbols.class) //
				.build();

	static DebugSymbolsInternal tryPreferredInterfaces(InterfaceSupplier supplier) {
		return DbgEngUtil.tryPreferredInterfaces(DebugSymbolsInternal.class, PREFFERED_SYMBOLS_IIDS,
			supplier);
	}

	String getModuleName(DebugModuleName which, DebugModule module);

	DebugModuleInfo getModuleParameters(int count, int startIndex);

}
