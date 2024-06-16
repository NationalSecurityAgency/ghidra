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
package agent.dbgeng.impl.dbgeng;

import java.lang.reflect.Method;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

import com.sun.jna.Pointer;
import com.sun.jna.platform.win32.Guid.IID;
import com.sun.jna.platform.win32.Guid.REFIID;
import com.sun.jna.platform.win32.WinDef.ULONG;
import com.sun.jna.platform.win32.WinNT.HRESULT;
import com.sun.jna.platform.win32.COM.*;
import com.sun.jna.ptr.PointerByReference;

import agent.dbgeng.dbgeng.err.DbgEngRuntimeException;
import ghidra.util.Msg;

public abstract class DbgEngUtil {
	public static final ULONG DEBUG_ANY_ID = new ULONG(-1);

	private DbgEngUtil() {
	}

	public record Preferred<T> (REFIID refiid, Class<? extends T> cls) {
		public Preferred(IID iid, Class<? extends T> cls) {
			this(new REFIID(iid), cls);
		}
	}

	public static interface InterfaceSupplier {
		HRESULT get(REFIID refiid, PointerByReference pClient);
	}

	@SuppressWarnings("unchecked")
	public static <I, T> I tryPreferredInterfaces(Class<I> cls, List<Preferred<T>> preferred,
			InterfaceSupplier supplier) {
		PointerByReference ppClient = new PointerByReference();
		for (Preferred<T> pref : preferred) {
			try {
				COMUtils.checkRC(supplier.get(pref.refiid, ppClient));
				if (ppClient.getValue() == null) {
					continue;
				}
				T impl = pref.cls.getConstructor(Pointer.class).newInstance(ppClient.getValue());
				Method instanceFor = cls.getMethod("instanceFor", pref.cls);
				Object instance = instanceFor.invoke(null, impl);
				return (I) instance;
			}
			catch (COMException e) {
				Msg.debug(DbgEngUtil.class, e + " (" + pref.cls + ")");
				// TODO: Only try next on E_NOINTERFACE?
				// Try next
			}
			catch (Exception e) {
				throw new AssertionError("INTERNAL: Unexpected exception", e);
			}
		}
		throw new DbgEngRuntimeException("None of the preferred interfaces are supported");
	}

	public static <T extends Unknown, U> U lazyWeakCache(Map<Pointer, U> cache, T unk,
			Function<T, U> forNew) {
		U present = cache.get(unk.getPointer());
		if (present != null) {
			unk.Release();
			return present;
		}
		U absent = forNew.apply(unk);
		cache.put(unk.getPointer(), absent);
		return absent;
	}

	public static void dbgline() {
		System.out.println(new Exception().getStackTrace()[1]);
		System.out.flush();
	}
}
