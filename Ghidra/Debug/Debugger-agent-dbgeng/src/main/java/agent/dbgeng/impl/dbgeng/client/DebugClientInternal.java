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
package agent.dbgeng.impl.dbgeng.client;

import java.util.Map;

import com.google.common.collect.ImmutableMap;
import com.sun.jna.Pointer;
import com.sun.jna.platform.win32.Guid.REFIID;

import agent.dbgeng.dbgeng.DebugClient;
import agent.dbgeng.impl.dbgeng.DbgEngUtil;
import agent.dbgeng.impl.dbgeng.DbgEngUtil.InterfaceSupplier;
import agent.dbgeng.impl.dbgeng.control.DebugControlInternal;
import agent.dbgeng.jna.dbgeng.client.*;
import ghidra.util.datastruct.WeakValueHashMap;

public interface DebugClientInternal extends DebugClient {
	Map<Pointer, DebugClientInternal> CACHE = new WeakValueHashMap<>();

	enum DebugClass {
		UNINITIALIZED, //
		KERNEL, //
		USER_WINDOWS, //
		IMAGE_FILE, //
		;
	}

	static DebugClientInternal instanceFor(WrapIDebugClient client) {
		return DbgEngUtil.lazyWeakCache(CACHE, client, DebugClientImpl1::new);
	}

	static DebugClientInternal instanceFor(WrapIDebugClient2 client) {
		return DbgEngUtil.lazyWeakCache(CACHE, client, DebugClientImpl2::new);
	}

	static DebugClientInternal instanceFor(WrapIDebugClient3 client) {
		return DbgEngUtil.lazyWeakCache(CACHE, client, DebugClientImpl3::new);
	}

	static DebugClientInternal instanceFor(WrapIDebugClient4 client) {
		return DbgEngUtil.lazyWeakCache(CACHE, client, DebugClientImpl4::new);
	}

	static DebugClientInternal instanceFor(WrapIDebugClient5 client) {
		return DbgEngUtil.lazyWeakCache(CACHE, client, DebugClientImpl5::new);
	}

	static DebugClientInternal instanceFor(WrapIDebugClient6 client) {
		return DbgEngUtil.lazyWeakCache(CACHE, client, DebugClientImpl6::new);
	}

	static DebugClientInternal instanceFor(WrapIDebugClient7 client) {
		return DbgEngUtil.lazyWeakCache(CACHE, client, DebugClientImpl7::new);
	}

	ImmutableMap.Builder<REFIID, Class<? extends WrapIDebugClient>> PREFERRED_CLIENT_IIDS_BUILDER =
		ImmutableMap.builder();
	Map<REFIID, Class<? extends WrapIDebugClient>> PREFERRED_CLIENT_IIDS =
		PREFERRED_CLIENT_IIDS_BUILDER //
				.put(new REFIID(IDebugClient7.IID_IDEBUG_CLIENT7), WrapIDebugClient7.class) //
				.put(new REFIID(IDebugClient6.IID_IDEBUG_CLIENT6), WrapIDebugClient6.class) //
				.put(new REFIID(IDebugClient5.IID_IDEBUG_CLIENT5), WrapIDebugClient5.class) //
				.put(new REFIID(IDebugClient4.IID_IDEBUG_CLIENT4), WrapIDebugClient4.class) //
				.put(new REFIID(IDebugClient3.IID_IDEBUG_CLIENT3), WrapIDebugClient3.class) //
				.put(new REFIID(IDebugClient2.IID_IDEBUG_CLIENT2), WrapIDebugClient2.class) //
				.put(new REFIID(IDebugClient.IID_IDEBUG_CLIENT), WrapIDebugClient.class) //
				.build();

	static DebugClientInternal tryPreferredInterfaces(InterfaceSupplier supplier) {
		return DbgEngUtil.tryPreferredInterfaces(DebugClientInternal.class, PREFERRED_CLIENT_IIDS,
			supplier);
	}

	IDebugClient getJNAClient();

	DebugControlInternal getControlInternal();

	@Override
	default void endSessionReentrant() {
		endSession(DebugEndSessionFlags.DEBUG_END_REENTRANT);
	}
}
