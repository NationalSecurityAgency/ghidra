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
package agent.gdb.model;

import java.util.*;

import agent.gdb.model.impl.GdbModelTargetAttachable;
import ghidra.dbg.target.TargetAttachable;
import ghidra.dbg.target.TargetLauncher.TargetCmdLineLauncher;
import ghidra.dbg.target.TargetProcess;
import ghidra.dbg.test.AbstractDebuggerModelTest;
import ghidra.dbg.test.AbstractDebuggerModelTest.DebuggerTestSpecimen;
import ghidra.dbg.testutil.DebuggerModelTestUtils;
import ghidra.dbg.testutil.DummyProc;
import ghidra.dbg.util.ShellUtils;

public enum GdbLinuxSpecimen implements DebuggerTestSpecimen, DebuggerModelTestUtils {
	SLEEP {
		@Override
		String getCommandLine() {
			return "sleep 100000";
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
	SPIN_STRIPPED {
		@Override
		String getCommandLine() {
			return DummyProc.which("expSpin.stripped");
		}
	},
	STACK {
		@Override
		String getCommandLine() {
			return DummyProc.which("expStack");
		}
	};

	abstract String getCommandLine();

	@Override
	public DummyProc runDummy() throws Throwable {
		return DummyProc.run(ShellUtils.parseArgs(getCommandLine()).toArray(String[]::new));
	}

	@Override
	public Map<String, Object> getLauncherArgs() {
		return Map.ofEntries(
			Map.entry(TargetCmdLineLauncher.CMDLINE_ARGS_NAME, getCommandLine()));
	}

	@Override
	public List<String> getLaunchScript() {
		List<String> script = new ArrayList<>();
		List<String> parsed = ShellUtils.parseArgs(getCommandLine());
		if (parsed.size() > 1) {
			script.add("set args " + ShellUtils.generateLine(parsed.subList(1, parsed.size())));
		}
		script.add("file " + ShellUtils.generateLine(parsed.subList(0, 1)));
		script.add("start");
		return script;
	}

	@Override
	public boolean isRunningIn(TargetProcess process, AbstractDebuggerModelTest test)
			throws Throwable {
		waitOn(process.fetchAttributes());
		return process.getDisplay().contains(ShellUtils.parseArgs(getCommandLine()).get(0));
	}

	@Override
	public boolean isAttachable(DummyProc dummy, TargetAttachable attachable,
			AbstractDebuggerModelTest test) throws Throwable {
		waitOn(attachable.fetchAttributes());
		long pid = attachable.getTypedAttributeNowByName(
			GdbModelTargetAttachable.PID_ATTRIBUTE_NAME, Long.class, -1L);
		return pid == dummy.pid;
	}
}
