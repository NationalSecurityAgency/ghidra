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

import java.math.BigInteger;
import java.util.Objects;

public class GdbMemoryMapping {
	private final BigInteger start;
	private final BigInteger end;
	private final BigInteger size;
	private final BigInteger offset;
	private final String objfile;

	public GdbMemoryMapping(BigInteger start, BigInteger end, BigInteger size, BigInteger offset,
			String objfile) {
		this.start = start;
		this.end = end;
		this.size = size;
		this.offset = offset;
		this.objfile = objfile;

		assert Objects.equals(start.add(size), end);
	}

	public BigInteger getStart() {
		return start;
	}

	public BigInteger getEnd() {
		return end;
	}

	public BigInteger getSize() {
		return size;
	}

	public BigInteger getOffset() {
		return offset;
	}

	public String getObjfile() {
		return objfile;
	}
}
