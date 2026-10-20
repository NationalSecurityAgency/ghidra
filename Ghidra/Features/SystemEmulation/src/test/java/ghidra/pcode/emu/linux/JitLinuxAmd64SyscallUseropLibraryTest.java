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
package ghidra.pcode.emu.linux;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.lang.invoke.MethodHandles;

import ghidra.pcode.emu.PcodeEmulator;
import ghidra.pcode.emu.jit.*;
import ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage.EntryPoint;
import ghidra.pcode.exec.PcodeUseropLibrary;

public class JitLinuxAmd64SyscallUseropLibraryTest extends EmuLinuxAmd64SyscallUseropLibraryTest {

	protected final class LinuxAmd64JitPcodeEmulator extends JitPcodeEmulator {
		public LinuxAmd64JitPcodeEmulator() {
			super(program.getLanguage(), new JitConfiguration(), MethodHandles.lookup());
		}

		@Override
		protected PcodeUseropLibrary<byte[]> createUseropLibrary() {
			syscalls = new EmuLinuxAmd64SyscallUseropLibrary<>(this, fs, program) {
				@Override
				public void unix_exit(long status) {
					fail("Linux-amd64 shoud use group_exit");
					super.unix_exit(status);
				}

				@Override
				public void unix_group_exit(long status) {
					checkStackIsDirect();
					super.unix_group_exit(status);
				}

				@Override
				public int unix_read(int fd, long bufPtr, int count) {
					checkStackIsDirect();
					return super.unix_read(fd, bufPtr, count);
				}

				@Override
				public int unix_write(int fd, long bufPtr, int count) {
					checkStackIsDirect();
					return super.unix_write(fd, bufPtr, count);
				}

				@Override
				public int unix_open(long pathnamePtr, int flags, int mode) {
					checkStackIsDirect();
					return super.unix_open(pathnamePtr, flags, mode);
				}

				@Override
				public int unix_close(int fd) {
					checkStackIsDirect();
					return super.unix_close(fd);
				}
			};
			capture = new CaptureUseropLibrary();
			return syscalls.compose(capture);
		}

		@Override
		protected JitPcodeThread createThread(String name) {
			return new JitPcodeThread(name, this) {
				int count = 0;

				@Override
				public void count(int instructions, int trailingOps) {
					count += (instructions + trailingOps);
					if (count > 1000) {
						fail("Probably an infinite loop");
					}
					super.count(instructions, trailingOps);
				}
			};
		}
	}

	void checkStackIsDirect() {
		Throwable here = new Throwable();
		StackTraceElement oneUp = here.getStackTrace()[2]; // The userop and checkStack
		assertEquals(EntryPoint.class.getName(), oneUp.getClassName());
		assertEquals("run", oneUp.getMethodName());
	}

	@Override
	protected PcodeEmulator createEmulator() {
		return new LinuxAmd64JitPcodeEmulator();
	}
}
