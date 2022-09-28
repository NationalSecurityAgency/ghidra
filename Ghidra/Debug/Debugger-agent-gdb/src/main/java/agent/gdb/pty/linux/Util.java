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

import com.sun.jna.*;
import com.sun.jna.ptr.IntByReference;

/**
 * The interface for linking to {@code openpty} via jna
 */
public interface Util extends Library {
	Util INSTANCE = Native.load("util", Util.class);

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
	int openpty(IntByReference amaster, IntByReference aslave, Pointer name,
			Pointer termp, Pointer winp) throws LastErrorException;
}
