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
 * 
 * <p>
 * See the UNIX manual pages
 */
public interface Util extends Library {
	Util INSTANCE = Native.load("util", Util.class);

	/**
	 * NOTE: We cannot use {@link LastErrorException} here, because the idiom it applies is not
	 * correct for errno on UNIX. See https://man7.org/linux/man-pages/man3/errno.3.html, in
	 * particular:
	 * 
	 * <blockquote>The value in errno is significant only when the return value of the call
	 * indicated an error (i.e., -1 from most system calls; -1 or NULL from most library functions);
	 * a function that succeeds is allowed to change errno.</blockquote>
	 * 
	 * This actually happens on our test setup when invoking the native {@code openpty} from a
	 * Docker container. It returns 0, but sets errno. JNA will incorrectly interpret this as
	 * failure. Thus, callers to this function must check the return value and handle the error
	 * manually.
	 */
	int openpty(IntByReference amaster, IntByReference aslave, Pointer name, Pointer termp,
			Pointer winp);
}
