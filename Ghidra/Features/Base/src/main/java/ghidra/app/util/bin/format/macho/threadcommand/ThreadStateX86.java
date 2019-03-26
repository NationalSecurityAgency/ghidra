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
package ghidra.app.util.bin.format.macho.threadcommand;

abstract class ThreadStateX86 extends ThreadState {

	@Deprecated
	public final static int i386_THREAD_STATE = 1;
	@Deprecated
	public final static int i386_FLOAT_STATE = 2;
	@Deprecated
	public final static int i386_EXCEPTION_STATE = 3;

	public final static int x86_THREAD_STATE32 = 1;
	public final static int x86_FLOAT_STATE32 = 2;
	public final static int x86_EXCEPTION_STATE32 = 3;
	public final static int x86_THREAD_STATE64 = 4;
	public final static int x86_FLOAT_STATE64 = 5;
	public final static int x86_EXCEPTION_STATE64 = 6;
	public final static int x86_THREAD_STATE = 7;
	public final static int x86_FLOAT_STATE = 8;
	public final static int x86_EXCEPTION_STATE = 9;
	public final static int x86_DEBUG_STATE32 = 10;
	public final static int x86_DEBUG_STATE64 = 11;
	public final static int x86_DEBUG_STATE = 12;
	public final static int THREAD_STATE_NONE = 13;
}
