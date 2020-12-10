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
package agent.dbgeng.jna.dbgeng;

import java.util.ArrayList;
import java.util.List;
import java.util.function.BiFunction;
import java.util.function.Supplier;

import com.sun.jna.platform.win32.*;
import com.sun.jna.platform.win32.WinDef.DWORD;
import com.sun.jna.platform.win32.WinNT.HANDLE;

import agent.dbgeng.dbgeng.DbgEng;
import agent.dbgeng.dbgeng.DbgEng.OpaqueCleanable;
import agent.dbgeng.jna.dbgeng.Kernel32Extra.PROCESSENTRY32W;
import agent.dbgeng.jna.dbgeng.Kernel32Extra.THREADENTRY32;
import ghidra.comm.util.BitmaskSet;
import ghidra.comm.util.BitmaskUniverse;

public class ToolhelpUtil {
	public static class Snapshot {
		@SuppressWarnings("unused")
		private final OpaqueCleanable cleanable;
		private final HANDLE handle;

		private Snapshot(HANDLE handle) {
			this.cleanable = DbgEng.releaseWhenPhantom(this, handle);
			this.handle = handle;
		}

		protected <T> List<T> getItems(Supplier<T> newStruct, BiFunction<HANDLE, T, Boolean> first,
				BiFunction<HANDLE, T, Boolean> next) {
			List<T> items = new ArrayList<>();

			T entry = newStruct.get();
			for (boolean has = first.apply(handle, entry); has; has = next.apply(handle, entry)) {
				items.add(entry);
				entry = newStruct.get();
			}

			int lastError = Kernel32.INSTANCE.GetLastError();
			if (lastError != W32Errors.ERROR_SUCCESS &&
				lastError != W32Errors.ERROR_NO_MORE_FILES) {
				throw new Win32Exception(lastError);
			}

			return items;
		}

		public List<PROCESSENTRY32W> getProcesses() {
			return getItems(PROCESSENTRY32W::new, Kernel32Extra.INSTANCE::Process32FirstW,
				Kernel32Extra.INSTANCE::Process32NextW);
		}

		public List<THREADENTRY32> getThreads() {
			return getItems(THREADENTRY32::new, Kernel32Extra.INSTANCE::Thread32First,
				Kernel32Extra.INSTANCE::Thread32Next);
		}
	}

	public static enum SnapshotFlags implements BitmaskUniverse {
		HEAPLIST(Tlhelp32.TH32CS_SNAPHEAPLIST), //
		PROCESS(Tlhelp32.TH32CS_SNAPPROCESS), //
		THREAD(Tlhelp32.TH32CS_SNAPTHREAD), //
		MODULE(Tlhelp32.TH32CS_SNAPMODULE), //
		MODULE32(Tlhelp32.TH32CS_SNAPMODULE32), //
		ALL(Tlhelp32.TH32CS_SNAPALL), //
		INHERIT(Tlhelp32.TH32CS_INHERIT), //
		;

		SnapshotFlags(DWORD mask) {
			this.mask = mask.intValue();
		}

		int mask;

		@Override
		public long getMask() {
			return mask;
		}
	}

	public static Snapshot createSnapshot(BitmaskSet<SnapshotFlags> flags, int processId) {
		DWORD dwFlags = new DWORD(flags.getBitmask());
		DWORD dwPID = new DWORD(processId);
		HANDLE hSnap = Kernel32.INSTANCE.CreateToolhelp32Snapshot(dwFlags, dwPID);
		if (hSnap == null) {
			throw new Win32Exception(Kernel32.INSTANCE.GetLastError());
		}

		return new Snapshot(hSnap);
	}
}
