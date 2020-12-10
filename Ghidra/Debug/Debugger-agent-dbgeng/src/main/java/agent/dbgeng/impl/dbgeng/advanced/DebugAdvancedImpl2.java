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
package agent.dbgeng.impl.dbgeng.advanced;

import com.sun.jna.platform.win32.WinDef.ULONG;
import com.sun.jna.platform.win32.WinDef.ULONGLONG;

import agent.dbgeng.dbgeng.DebugThreadId;
import agent.dbgeng.jna.dbgeng.DbgEngNative.DEBUG_THREAD_BASIC_INFORMATION;
import agent.dbgeng.jna.dbgeng.advanced.IDebugAdvanced2;

import com.sun.jna.platform.win32.COM.COMUtils;

import ghidra.comm.util.BitmaskSet;

public class DebugAdvancedImpl2 extends DebugAdvancedImpl1 {
	private final IDebugAdvanced2 jnaAdvanced;

	public DebugAdvancedImpl2(IDebugAdvanced2 jnaAdvanced) {
		super(jnaAdvanced);
		this.jnaAdvanced = jnaAdvanced;
	}

	@Override
	public DebugThreadBasicInformation getThreadBasicInformation(DebugThreadId tid) {
		ULONG ulWhich = new ULONG(WhichSystemObjectInformation.THREAD_BASIC_INFORMATION.ordinal());
		ULONGLONG ullUnused = new ULONGLONG(0);
		ULONG ulThreadId = new ULONG(tid.id);
		DEBUG_THREAD_BASIC_INFORMATION sInfo = new DEBUG_THREAD_BASIC_INFORMATION();
		ULONG ulBufferSize = new ULONG(sInfo.size());
		COMUtils.checkRC(jnaAdvanced.GetSystemObjectInformation(ulWhich, ullUnused, ulThreadId,
			sInfo.getPointer(), ulBufferSize, null));
		sInfo.read();

		Integer exitStatus = null;
		Integer priorityClass = null;
		Integer priority = null;
		Long createTime = null;
		Long exitTime = null;
		Long kernelTime = null;
		Long userTime = null;
		Long startOffset = null;
		Long affinity = null;

		BitmaskSet<ThreadBasicInformationValidBits> valid =
			new BitmaskSet<>(ThreadBasicInformationValidBits.class, sInfo.Valid.intValue());
		if (valid.contains(ThreadBasicInformationValidBits.EXIT_STATUS)) {
			exitStatus = sInfo.ExitStatus.intValue();
		}
		if (valid.contains(ThreadBasicInformationValidBits.PRIORITY_CLASS)) {
			priorityClass = sInfo.PriorityClass.intValue();
		}
		if (valid.contains(ThreadBasicInformationValidBits.PRIORITY)) {
			priority = sInfo.Priority.intValue();
		}
		if (valid.contains(ThreadBasicInformationValidBits.TIMES)) {
			createTime = sInfo.CreateTime.longValue();
			exitTime = sInfo.ExitTime.longValue();
			kernelTime = sInfo.KernelTime.longValue();
			userTime = sInfo.UserTime.longValue();
		}
		if (valid.contains(ThreadBasicInformationValidBits.START_OFFSET)) {
			startOffset = sInfo.StartOffset.longValue();
		}
		if (valid.contains(ThreadBasicInformationValidBits.AFFINITY)) {
			affinity = sInfo.Affinity.longValue();
		}

		return new DebugThreadBasicInformation(exitStatus, priorityClass, priority, createTime,
			exitTime, kernelTime, userTime, startOffset, affinity);
	}
}
