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
package agent.gdb.manager.impl;

import java.util.List;

import agent.gdb.manager.GdbModuleSection;

public class GdbModuleSectionImpl implements GdbModuleSection {
	protected final String name;
	protected final long vmaStart;
	protected final long vmaEnd;
	protected final long fileOffset;
	protected final List<String> attrs;

	public GdbModuleSectionImpl(String name, long vmaStart, long vmaEnd, long fileOffset,
			List<String> attrs) {
		this.name = name;
		this.vmaStart = vmaStart;
		this.vmaEnd = vmaEnd;
		this.fileOffset = fileOffset;
		this.attrs = List.copyOf(attrs);
	}

	@Override
	public String getName() {
		return name;
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
	public long getFileOffset() {
		return fileOffset;
	}

	@Override
	public List<String> getAttributes() {
		return attrs;
	}
}
