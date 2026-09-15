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
package ghidra.pty.windows;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;

import com.microsoft.win32.win32_h;

public class HandlePtr {
	private final MemorySegment seg;

	public HandlePtr(Arena arena) {
		this.seg = arena.allocate(win32_h.HANDLE);
	}

	public MemorySegment asSegment() {
		return seg;
	}

	public MemorySegment get() {
		return seg.get(win32_h.HANDLE, 0);
	}
}
