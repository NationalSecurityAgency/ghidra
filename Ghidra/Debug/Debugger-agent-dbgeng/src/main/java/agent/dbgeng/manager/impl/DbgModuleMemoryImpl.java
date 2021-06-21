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
package agent.dbgeng.manager.impl;

import java.util.List;

import agent.dbgeng.dbgeng.DebugDataSpaces.PageState;
import agent.dbgeng.manager.DbgModuleMemory;

public class DbgModuleMemoryImpl implements DbgModuleMemory {

	protected final String index;
	protected final long vmaStart;
	protected final long vmaEnd;
	protected final long allocationBase;
	protected final List<String> allocationProtect;
	protected final List<String> protect;
	protected final PageState state;
	protected final String type;
	private boolean isRead;
	private boolean isWrite;
	private boolean isExec;

	public DbgModuleMemoryImpl(String index, long vmaStart, long vmaEnd, long allocationBase,
			List<String> allocationProtect, List<String> protect, PageState state, String type,
			boolean isRead, boolean isWrite, boolean isExec) {
		this.index = index;
		this.vmaStart = vmaStart;
		this.vmaEnd = vmaEnd;
		this.allocationBase = allocationBase;
		this.state = state;
		this.type = type;
		this.allocationProtect = List.copyOf(allocationProtect);
		this.protect = List.copyOf(protect);
		this.isRead = isRead;
		this.isWrite = isWrite;
		this.isExec = isExec;
	}

	@Override
	public String getName() {
		return index;
	}

	@Override
	public Long getId() {
		return vmaStart;
	}

	@Override
	public long getVmaStart() {
		return vmaStart;
	}

	@Override
	public long getVmaEnd() {
		return vmaEnd;
	}

	@Override
	public long getAllocationBase() {
		return allocationBase;
	}

	@Override
	public List<String> getAllocationProtect() {
		return allocationProtect;
	}

	@Override
	public List<String> getProtect() {
		return protect;
	}

	@Override
	public String getState() {
		return state.toString();
	}

	@Override
	public String getType() {
		return type;
	}

	public boolean isRead() {
		return isRead;
	}

	public boolean isWrite() {
		return isWrite;
	}

	public boolean isExec() {
		return isExec;
	}
}
