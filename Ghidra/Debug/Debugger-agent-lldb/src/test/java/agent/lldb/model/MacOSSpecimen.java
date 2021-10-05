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
package agent.lldb.model;

import java.io.File;
import java.util.*;

import agent.lldb.model.iface2.LldbModelTargetAvailable;
import ghidra.dbg.target.*;
import ghidra.dbg.target.TargetLauncher.TargetCmdLineLauncher;
import ghidra.dbg.test.AbstractDebuggerModelTest;
import ghidra.dbg.test.AbstractDebuggerModelTest.DebuggerTestSpecimen;
import ghidra.dbg.testutil.DebuggerModelTestUtils;
import ghidra.dbg.testutil.DummyProc;

// codesign --entitlements debuggee-entitlement.xml -fs gdbcert ./xclock-x86_64 

public enum MacOSSpecimen implements DebuggerTestSpecimen, DebuggerModelTestUtils {
	SPIN {
		@Override
		String getCommandLine() {
			return DummyProc.which("expSpin");
		}
	},
	FORK_EXIT {
		@Override
		String getCommandLine() {
			return DummyProc.which("expFork");
		}
	},
	CLONE_EXIT {
		@Override
		String getCommandLine() {
			return DummyProc.which("expCloneExit");
		}
	},
	PRINT {
		@Override
		String getCommandLine() {
			return DummyProc.which("expPrint");
		}
	},
	REGISTERS {
		@Override
		String getCommandLine() {
			return DummyProc.which("expRegisters");
		}
	},
	STACK {
		@Override
		String getCommandLine() {
			return DummyProc.which("expStack");
		}
	},
	CREATE_PROCESS {
		@Override
		String getCommandLine() {
			return DummyProc.which("expCreateProcess");
		}
	},
	CREATE_THREAD_EXIT {
		@Override
		String getCommandLine() {
			return DummyProc.which("expCreateThreadExit");
		}
	};

	abstract String getCommandLine();

	@Override
	public DummyProc runDummy() throws Throwable {
		// This is not great, but....
		return DummyProc.run(getCommandLine().split("\\s+"));
	}

	@Override
	public Map<String, Object> getLauncherArgs() {
		return Map.ofEntries(Map.entry(TargetCmdLineLauncher.CMDLINE_ARGS_NAME, getCommandLine()));
	}

	@Override
	public List<String> getLaunchScript() {
		// NB: this will not appear on the process list until cont
		return List.of(".create " + getCommandLine() + "; g");
	}

	protected static String getShortName(String fullPath) {
		if (fullPath == null) {
			return null;
		}
		return new File(fullPath).getName();
	}

	public String getBinModuleKey() {
		String moduleName = getBinModuleName();
		if (moduleName.endsWith(".exe")) {
			return moduleName.substring(0, moduleName.length() - ".exe".length());
		}
		return moduleName;
	}

	public String getBinModuleName() {
		return getShortName(getCommandLine().split("\\s+")[0]);
	}

	@Override
	public boolean isRunningIn(TargetProcess process, AbstractDebuggerModelTest test)
			throws Throwable {
		// NB. ShellUtils.parseArgs removes the \s. Not good.
		String expected = getBinModuleName();
		TargetObject session = process.getParent().getParent();
		Collection<TargetModule> modules =
			test.m.findAll(TargetModule.class, session.getPath(), true).values();
		return modules.stream()
				.anyMatch(m -> expected.equalsIgnoreCase(getShortName(m.getModuleName())));
	}

	@Override
	public boolean isAttachable(DummyProc dummy, TargetAttachable attachable,
			AbstractDebuggerModelTest test) throws Throwable {
		waitOn(attachable.fetchAttributes());
		long pid =
			attachable.getTypedAttributeNowByName(LldbModelTargetAvailable.PID_ATTRIBUTE_NAME,
				Long.class, -1L);
		return pid == dummy.pid;
	}
}
