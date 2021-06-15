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
package agent.dbgeng.impl.dbgeng.advanced;

import java.util.Map;

import com.google.common.collect.ImmutableMap;
import com.sun.jna.Pointer;
import com.sun.jna.platform.win32.Guid.REFIID;

import agent.dbgeng.dbgeng.DebugAdvanced;
import agent.dbgeng.impl.dbgeng.DbgEngUtil;
import agent.dbgeng.impl.dbgeng.DbgEngUtil.InterfaceSupplier;
import agent.dbgeng.jna.dbgeng.advanced.*;
import ghidra.comm.util.BitmaskUniverse;
import ghidra.util.datastruct.WeakValueHashMap;

public interface DebugAdvancedInternal extends DebugAdvanced {
	Map<Pointer, DebugAdvancedInternal> CACHE = new WeakValueHashMap<>();

	static DebugAdvancedInternal instanceFor(WrapIDebugAdvanced advanced) {
		return DbgEngUtil.lazyWeakCache(CACHE, advanced, DebugAdvancedImpl1::new);
	}

	static DebugAdvancedInternal instanceFor(WrapIDebugAdvanced2 advanced) {
		return DbgEngUtil.lazyWeakCache(CACHE, advanced, DebugAdvancedImpl2::new);
	}

	static DebugAdvancedInternal instanceFor(WrapIDebugAdvanced3 advanced) {
		return DbgEngUtil.lazyWeakCache(CACHE, advanced, DebugAdvancedImpl3::new);
	}

	ImmutableMap.Builder<REFIID, Class<? extends WrapIDebugAdvanced>> PREFERRED_ADVANCED_IIDS_BUILDER =
		ImmutableMap.builder();
	Map<REFIID, Class<? extends WrapIDebugAdvanced>> PREFERRED_ADVANCED_IIDS =
		PREFERRED_ADVANCED_IIDS_BUILDER //
				.put(new REFIID(IDebugAdvanced3.IID_IDEBUG_ADVANCED3), WrapIDebugAdvanced3.class) //
				.put(new REFIID(IDebugAdvanced2.IID_IDEBUG_ADVANCED2), WrapIDebugAdvanced2.class) //
				.put(new REFIID(IDebugAdvanced.IID_IDEBUG_ADVANCED), WrapIDebugAdvanced.class) //
				.build();

	static DebugAdvancedInternal tryPreferredInterfaces(InterfaceSupplier supplier) {
		return DbgEngUtil.tryPreferredInterfaces(DebugAdvancedInternal.class,
			PREFERRED_ADVANCED_IIDS, supplier);
	}

	public enum WhichSystemObjectInformation {
		THREAD_BASIC_INFORMATION, //
		THREAD_NAME_WIDE, //
		CURRENT_PROCESS_COOKIE, //
		;
	}

	public enum ThreadBasicInformationValidBits implements BitmaskUniverse {
		EXIT_STATUS(1 << 0), //
		PRIORITY_CLASS(1 << 1), //
		PRIORITY(1 << 2), //
		TIMES(1 << 3), //
		START_OFFSET(1 << 4), //
		AFFINITY(1 << 5), //
		ALL(0x3f);
		;

		ThreadBasicInformationValidBits(int mask) {
			this.mask = mask;
		}

		int mask;

		@Override
		public long getMask() {
			return mask;
		}
	}
}
