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
package agent.dbgmodel.impl.dbgmodel;

import java.lang.reflect.Method;
import java.util.Map;
import java.util.function.Function;

import com.sun.jna.Pointer;
import com.sun.jna.platform.win32.Guid.REFIID;
import com.sun.jna.platform.win32.WinDef.ULONG;
import com.sun.jna.platform.win32.WinNT.HRESULT;
import com.sun.jna.platform.win32.COM.*;
import com.sun.jna.ptr.PointerByReference;

import agent.dbgmodel.dbgmodel.err.DbgModelRuntimeException;
import ghidra.util.Msg;

public abstract class DbgModelUtil {
	public static final ULONG DEBUG_ANY_ID = new ULONG(-1);

	private DbgModelUtil() {
	}

	public static interface InterfaceSupplier {
		HRESULT get(REFIID refiid, PointerByReference pClient);
	}

	@SuppressWarnings("unchecked")
	public static <I> I tryPreferredInterfaces(Class<I> cls,
			Map<REFIID, ? extends Class<?>> preferred, InterfaceSupplier supplier) {
		PointerByReference ppClient = new PointerByReference();
		for (Map.Entry<REFIID, ? extends Class<?>> ent : preferred.entrySet()) {
			try {
				COMUtils.checkRC(supplier.get(ent.getKey(), ppClient));
				if (ppClient.getValue() == null) {
					continue;
				}
				Object impl =
					ent.getValue().getConstructor(Pointer.class).newInstance(ppClient.getValue());
				Method instanceFor = cls.getMethod("instanceFor", ent.getValue());
				Object instance = instanceFor.invoke(null, impl);
				return (I) instance;
			}
			catch (COMException e) {
				Msg.debug(DbgModelUtil.class, e + " (" + ent.getValue() + ")");
				// TODO: Only try next on E_NOINTERFACE?
				// Try next
			}
			catch (Exception e) {
				throw new AssertionError("INTERNAL: Unexpected exception", e);
			}
		}
		throw new DbgModelRuntimeException("None of the preferred interfaces are supported");
	}

	public static <T extends Unknown, U> U lazyWeakCache(Map<Pointer, U> cache, T unk,
			Function<T, U> forNew) {
		synchronized (cache) {
			U present = cache.get(unk.getPointer());
			if (present != null) {
				unk.Release();
				return present;
			}
			U absent = forNew.apply(unk);
			cache.put(unk.getPointer(), absent);
			return absent;
		}
	}

	public static void dbgline() {
		System.out.println(new Exception().getStackTrace()[1]);
		System.out.flush();
	}
}
