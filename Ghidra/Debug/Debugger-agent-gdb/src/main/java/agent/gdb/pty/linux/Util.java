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
package agent.gdb.pty.linux;

import jnr.ffi.LibraryLoader;
import jnr.ffi.Pointer;
import jnr.ffi.annotations.Out;
import jnr.ffi.byref.IntByReference;

/**
 * The interface for linking to {@code openpty} via jnr-ffi
 */
public interface Util {
	Util INSTANCE = LibraryLoader.create(Util.class).load("util");

	/**
	 * See the Linux manual pages
	 * 
	 * @param amaster (purposefully undocumented here)
	 * @param aslave (purposefully undocumented here)
	 * @param name (purposefully undocumented here)
	 * @param termp (purposefully undocumented here)
	 * @param winp (purposefully undocumented here)
	 * @return (purposefully undocumented here)
	 */
	int openpty(@Out IntByReference amaster, @Out IntByReference aslave, @Out Pointer name,
			@Out Pointer termp, @Out Pointer winp);
}
