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

public class DbgSectionImpl {
	private final long start;
	private final long end;
	private final long size;
	private final long offset;
	private final String objfile;

	public DbgSectionImpl(long start, long end, long size, long offset, String objfile) {
		this.start = start;
		this.end = end;
		this.size = size;
		this.offset = offset;
		this.objfile = objfile;

		assert start + size == end;
	}

	public long getStart() {
		return start;
	}

	public long getEnd() {
		return end;
	}

	public long getSize() {
		return size;
	}

	public long getOffset() {
		return offset;
	}

	public String getObjfile() {
		return objfile;
	}
}
