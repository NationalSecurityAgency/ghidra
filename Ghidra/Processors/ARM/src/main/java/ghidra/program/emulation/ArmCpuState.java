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
package ghidra.program.emulation;

public class ArmCpuState {
	private volatile boolean irqEnabled = true;
	private volatile boolean privileged = true;
	private volatile long mainStackPointer;
	private volatile long processStackPointer;
	private volatile boolean threadModePrivileged;
	private volatile boolean threadMode;

	private volatile long basePriority;

	public boolean isIrqEnabled() {
		return irqEnabled;
	}

	public void setIrqEnabled(boolean irqEnabled) {
		this.irqEnabled = irqEnabled;
	}

	public boolean isPrivileged() {
		return privileged;
	}

	public void setPrivileged(boolean privileged) {
		this.privileged = privileged;
	}

	public long getMainStackPointer() {
		return mainStackPointer;
	}

	public void setMainStackPointer(long mainStackPointer) {
		this.mainStackPointer = mainStackPointer;
	}

	public long getProcessStackPointer() {
		return processStackPointer;
	}

	public void setProcessStackPointer(long processStackPointer) {
		this.processStackPointer = processStackPointer;
	}

	public boolean isThreadModePrivileged() {
		return threadModePrivileged;
	}

	public void setThreadModePrivileged(boolean threadModePrivileged) {
		this.threadModePrivileged = threadModePrivileged;
	}

	public boolean isThreadMode() {
		return threadMode;
	}

	public void setThreadMode(boolean threadMode) {
		this.threadMode = threadMode;
	}

	public long getBasePriority() {
		return basePriority;
	}

	public void setBasePriority(long basePriority) {
		this.basePriority = basePriority;
	}
}
