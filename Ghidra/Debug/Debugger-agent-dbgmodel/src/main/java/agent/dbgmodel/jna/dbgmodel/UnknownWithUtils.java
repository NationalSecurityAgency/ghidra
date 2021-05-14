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
package agent.dbgmodel.jna.dbgmodel;

import java.io.*;
import java.util.*;

import com.sun.jna.Pointer;
import com.sun.jna.platform.win32.Guid.REFIID;
import com.sun.jna.platform.win32.WinNT.HRESULT;
import com.sun.jna.platform.win32.COM.Unknown;
import com.sun.jna.ptr.PointerByReference;

import ghidra.util.Msg;

public class UnknownWithUtils extends Unknown {
	public static void pause() {
		try {
			new BufferedReader(new InputStreamReader(System.in)).readLine();
		}
		catch (IOException e) {
			throw new AssertionError(e);
		}
	}

	public static void error(String message) {
		Msg.error(UnknownWithUtils.class, message, new Throwable());
		//pause();
	}

	public interface RefAnalyzer {
		default void observeCall(Pointer ptr, UnknownWithUtils wrapper, String name) {
		}

		default void observeCall(UnknownWithUtils wrapper, String name) {
		}

		default void observedAddRefViaResult(Pointer ptr, UnknownWithUtils wrapper) {
		}

		default void observedQueryInterface(REFIID riid, PointerByReference ppvObject, HRESULT hr,
				UnknownWithUtils wrapper) {
		}

		default void observedAddRef(int count, UnknownWithUtils wrapper) {
		}

		default void observedRelease(int count, UnknownWithUtils wrapper) {
		}

		default void checkLeaks() {
		}
	}

	public static class RefAnalyzerEntry {
		public final Pointer ptr;

		public long myCount = 0; // presume 1 elsewhere
		public Thread thread;

		public RefAnalyzerEntry(Pointer ptr) {
			this.ptr = ptr;
		}

		public void verifyValid(long actual, UnknownWithUtils wrapper, String name) {
			if (this.myCount < 0 || actual < 0) {
				error(
					"COM mine or actual ref-count below 0 in " + name +
						" wrapper=" + wrapper +
						", ptr=" + ptr +
						", myCount=" + this.myCount +
						", actual=" + actual);
			}
		}

		public int verifyCount(UnknownWithUtils wrapper, String name) {
			int actual = wrapper.getRefCount();
			verifyValid(actual, wrapper, name);
			return actual;
		}

		public void verifyThread() {
			Thread current = Thread.currentThread();
			if (this.thread == null) {
				this.thread = current;
			}
			if (this.thread != current) {
				// TODO: This could actually cause a problem
				// But right now, it's just distracting
				if (current.getName().contains("Cleaner")) {
					return;
				}
				//error("COM use by distinct threads ptr=" + ptr +
				//	", first=" + thread +
				//	", current=" + current);
			}
		}
	}

	public static class DisabledRefAnalyzer implements RefAnalyzer {
	}

	public static class EnabledRefAnalyzer implements RefAnalyzer {
		public static final Map<Long, RefAnalyzerEntry> REFS = new HashMap<>();
		public static final List<Long> QIS = new ArrayList<>();

		protected RefAnalyzerEntry getEntry(Pointer ptr) {
			synchronized (REFS) {
				return REFS.get(Pointer.nativeValue(ptr));
			}
		}

		protected RefAnalyzerEntry getEntryOrCreate(Pointer ptr) {
			synchronized (REFS) {
				return REFS.computeIfAbsent(Pointer.nativeValue(ptr),
					addr -> new RefAnalyzerEntry(ptr));
			}
		}

		protected RefAnalyzerEntry removeEntry(Pointer ptr) {
			synchronized (REFS) {
				return REFS.remove(Pointer.nativeValue(ptr));
			}
		}

		protected void expectWrapper(Pointer ptr) {
			synchronized (REFS) {
				QIS.add(Pointer.nativeValue(ptr));
			}
		}

		protected void unexpectWrapper(Pointer ptr) {
			synchronized (REFS) {
				QIS.remove(Pointer.nativeValue(ptr));
			}
		}

		@Override
		public void observeCall(Pointer ptr, UnknownWithUtils wrapper, String name) {
			synchronized (REFS) {
				RefAnalyzerEntry entry = getEntryOrCreate(ptr);
				long actual = entry.verifyCount(wrapper, name);
				entry.verifyValid(actual, wrapper, name);
				entry.verifyThread();
			}
		}

		@Override
		public void observeCall(UnknownWithUtils wrapper, String name) {
			observeCall(wrapper.getPointer(), wrapper, name);
		}

		@Override
		public void observedAddRefViaResult(Pointer ptr, UnknownWithUtils wrapper) {
			Msg.debug(this, "COM Presumed AddRef: " + ptr + ", wrapper=" + wrapper);
			synchronized (REFS) {
				unexpectWrapper(ptr);
				RefAnalyzerEntry entry = getEntryOrCreate(ptr);
				Msg.debug(this, "COM count after AddRef: " + wrapper + " mine=" + entry.myCount);
				entry.myCount++;
			}
		}

		@Override
		public void observedQueryInterface(REFIID riid, PointerByReference ppvObject, HRESULT hr,
				UnknownWithUtils wrapper) {
			Pointer ptr = ppvObject.getValue();
			Msg.debug(this,
				"COM QueryInterface: " + wrapper + "(riid->" + riid.getValue().toGuidString() +
					",ppvObject->" + ptr + ") = " + hr);
			expectWrapper(ptr);
		}

		@Override
		public void observedAddRef(int count, UnknownWithUtils wrapper) {
			Msg.debug(this, "COM AddRef: " + wrapper + "() = " + count);
			Pointer ptr = wrapper.getPointer();
			synchronized (REFS) {
				RefAnalyzerEntry entry = getEntry(ptr);
				if (entry == null) {
					error("COM AddRef on non-refed object ptr=" + ptr + ", wrapper=" + wrapper);
					return;
				}
				entry.myCount++;
				entry.verifyValid(count, wrapper, "AddRef");
				entry.verifyThread();
			}
		}

		@Override
		public void observedRelease(int count, UnknownWithUtils wrapper) {
			Msg.debug(this, "COM Release: " + wrapper + "() = " + count);
			Pointer ptr = wrapper.getPointer();
			synchronized (REFS) {
				RefAnalyzerEntry entry = getEntry(ptr);
				if (entry == null) {
					error("COM Released on non-refed object ptr=" + ptr + ", wrapper=" + wrapper);
					return;
				}
				entry.myCount--;
				Msg.debug(this,
					"COM count after Release: " + wrapper + " mine=" + entry.myCount + ", actual=" +
						count);
				if (entry.myCount == 0) {
					removeEntry(ptr);
				}
				entry.verifyValid(count, wrapper, "Release");
				entry.verifyThread();
			}
		}

		@Override
		public void checkLeaks() {
			// TODO: Can't really guarantee all GC has happened
			// This will create many false positives
			System.gc();
			synchronized (REFS) {
				for (RefAnalyzerEntry entry : REFS.values()) {
					if (entry.myCount != 0) {
						Msg.warn(this, "COM potential ref leak: ptr=" + entry.ptr + ", count=" +
							entry.myCount);
					}
				}

				for (long addr : QIS) {
					Msg.error(this, "Observed QueryInterface without a wrapper: ptr=0x" +
						Long.toHexString(addr));
				}
			}
		}
	}

	public static final RefAnalyzer ANALYZER = new DisabledRefAnalyzer();

	public static interface VTableIndex {
		int getIndex();

		public static <I extends Enum<I> & VTableIndex> int follow(Class<I> prev) {
			I[] all = prev.getEnumConstants();
			int start = all[0].getIndex() - all[0].ordinal();
			return all.length + start;
		}
	}

	public UnknownWithUtils() {
	}

	public UnknownWithUtils(Pointer pvInstance) {
		super(pvInstance);
		// TODO: HACK?
		ANALYZER.observedAddRefViaResult(pvInstance, this);
	}

	protected HRESULT _invokeHR(VTableIndex idx, Object... args) {
		//Msg.info(this, Thread.currentThread() + " invoked " + idx + Arrays.asList(args));
		return (HRESULT) this._invokeNativeObject(idx.getIndex(), args, HRESULT.class);
	}

	@Override
	public HRESULT QueryInterface(REFIID riid, PointerByReference ppvObject) {
		ANALYZER.observeCall(this, "QueryInterface");
		HRESULT hr = super.QueryInterface(riid, ppvObject);
		ANALYZER.observedQueryInterface(riid, ppvObject, hr, this);
		return hr;
	}

	@Override
	public int AddRef() {
		int count = super.AddRef();
		ANALYZER.observedAddRef(count, this);
		return count;
	}

	@Override
	public int Release() {
		int count = super.Release();
		ANALYZER.observedRelease(count, this);
		return count;
	}

	public int getRefCount() {
		int added = super.AddRef();
		int count = super.Release();
		if (added - 1 != count) {
			Msg.warn(this, "COM ref-count impl anomaly wrapper=" +
				this + ", added=" + added + ", count=" + count);
		}
		return count;
	}
}
