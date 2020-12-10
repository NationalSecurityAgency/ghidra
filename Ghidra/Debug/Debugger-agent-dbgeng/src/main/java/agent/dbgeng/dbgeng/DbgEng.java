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
package agent.dbgeng.dbgeng;

import java.lang.ref.Cleaner;

import com.sun.jna.WString;
import com.sun.jna.platform.win32.Kernel32Util;
import com.sun.jna.platform.win32.WinDef.DWORD;
import com.sun.jna.platform.win32.WinNT.HANDLE;
import com.sun.jna.platform.win32.COM.IUnknown;

import agent.dbgeng.impl.dbgeng.client.DebugClientInternal;
import agent.dbgeng.jna.dbgeng.DbgEngNative;
import ghidra.comm.util.BitmaskSet;
import ghidra.util.Msg;

/**
 * A wrapper for Microsoft's {@code dbgeng.dll} that presents a Java-friendly interface.
 * 
 * This is the "root interface" from which all other interfaces to {@code dbgeng.dll} are generated.
 * Not every method listed in the documentation, nor every method present in the header, is
 * implemented. Only those that were necessary to implement the SCTL adapter. However, the class and
 * interface hierarchy was designed so that adding the remaining methods should be fairly
 * straightforward. This wrapper attempts to obtain the most capable COM interfaces for the debug
 * client that it knows. Again, newer interfaces should be fairly straightforward to add.
 * 
 * Methods that are "obviously" wrappers for a COM method are left undocumented, unless there is
 * some nuance to how it has been wrapped. In many cases, a parameter which is an integer in the COM
 * method may be presented as an {@code enum} or {@link BitmaskSet} by the wrapper. Consult the MSDN
 * for the meaning of the various values and bit flags.
 * 
 * Each wrapper interface is implemented by several COM interface wrappers: one for each known COM
 * interface version. The wrapper is optimistic, in that it declares wrapper methods even for COM
 * methods that are only available in later versions. The implementations limited to earlier COM
 * interfaces should either emulate the operation, or throw an
 * {@link UnsupportedOperationException}. Where a newer method is provided by a newer interface, a
 * wrapper implementation should prefer the latest. For example, one series of interfaces introduces
 * {@code *Wide} variants of existing methods. Since Java also uses a UTF-16-like string encoding
 * internally, JNA permits wide strings to be passed by reference. Thus, the wide variant is always
 * preferred.
 * 
 * Pay careful attention to the threading requirements imposed by {@code dbgeng.dll} these can be
 * found in the MSDN. As a general rule of thumb, if the method is reentrant (i.e., it can be called
 * from any thread), it is declared in the {@code *Reentrant} variant of the wrapper interface.
 * There are few of these. Unless the documentation explicitly lists the method as reentrant, do not
 * declare it there. Many methods appear to execute successfully from the wrong thread, but cause
 * latent issues. A practice to prevent accidental use of non-reentrant methods outside of the
 * client's owning thread is to ensure that only the owning thread can see the full interface. All
 * other threads should only have access to the reentrant interface.
 * 
 * If you implement methods that introduce a new callback class, use the existing callback type
 * hierarchies as a model. There are many classes to implement. Furthermore, be sure to keep a
 * reference to any active callback instances within the wrapper that uses them. The JNA has no way
 * of knowing whether or not the instance is still being used by the external C/C++ library. If you
 * do not store a reference, the JVM will think it's garbage and free it, even though COM is still
 * using it. Drop the reference only when you are certain nothing external has a reference to it.
 */
public class DbgEng {
	private static final Cleaner CLEANER = Cleaner.create();

	private static class ReleaseCOMObject implements Runnable {
		private final IUnknown obj;

		ReleaseCOMObject(IUnknown obj) {
			this.obj = obj;
		}

		@Override
		public void run() {
			Msg.debug(this, "Releasing COM object: " + obj);
			obj.Release();
		}
	}

	private static class ReleaseHANDLE implements Runnable {
		private final HANDLE handle;

		public ReleaseHANDLE(HANDLE handle) {
			this.handle = handle;
		}

		@Override
		public void run() {
			Kernel32Util.closeHandle(handle);
		}
	}

	public static class OpaqueCleanable {
		@SuppressWarnings("unused") // A reference to control GC
		private final Object state;
		@SuppressWarnings("unused") // A reference to control GC
		private final Cleaner.Cleanable cleanable;

		public OpaqueCleanable(Object state, Cleaner.Cleanable cleanable) {
			this.state = state;
			this.cleanable = cleanable;
		}
	}

	public static OpaqueCleanable releaseWhenPhantom(Object owner, IUnknown obj) {
		ReleaseCOMObject state = new ReleaseCOMObject(obj);
		return new OpaqueCleanable(state, CLEANER.register(owner, state));
	}

	public static OpaqueCleanable releaseWhenPhantom(Object owner, HANDLE handle) {
		ReleaseHANDLE state = new ReleaseHANDLE(handle);
		return new OpaqueCleanable(state, CLEANER.register(owner, state));
	}

	/**
	 * Connect to a debug session.
	 * 
	 * See {@code DebugConnect} or {@code DebugConnectWide} on the MSDN.
	 * 
	 * @param remoteOptions the options, like those given to {@code -remote}
	 * @return a new client connected as specified
	 */
	public static DebugClient debugConnect(String remoteOptions) {
		WString options = new WString(remoteOptions);
		return DebugClientInternal.tryPreferredInterfaces((refiid,
				ppClient) -> DbgEngNative.INSTANCE.DebugConnectWide(options, refiid, ppClient));
	}

	/**
	 * Create a debug client.
	 * 
	 * Typically, this client is connected to the "local server". See {@code DebugCreate} on the
	 * MSDN.
	 * 
	 * @return a new client
	 */
	public static DebugClient debugCreate() {
		return DebugClientInternal.tryPreferredInterfaces(DbgEngNative.INSTANCE::DebugCreate);
	}

	/**
	 * Create a debug client with the given options.
	 * 
	 * See {@code DebugCreateEx} on the MSDN.
	 * 
	 * @param options the options
	 * @return a new client
	 */
	public static DebugClient debugCreate(int options) {
		DWORD dwOpts = new DWORD(options);
		return DebugClientInternal.tryPreferredInterfaces(
			(refiid, ppClient) -> DbgEngNative.INSTANCE.DebugCreateEx(refiid, dwOpts, ppClient));
	}
}
