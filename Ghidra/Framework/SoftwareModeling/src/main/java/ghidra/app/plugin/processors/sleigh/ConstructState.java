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
package ghidra.app.plugin.processors.sleigh;

import java.util.ArrayList;
import java.util.List;

import org.apache.commons.lang3.StringUtils;

import generic.hash.SimpleCRC32;
import ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolvedConstructor;

public class ConstructState {
	private Constructor ct;
	private List<ConstructState> resolvedStates = new ArrayList<>();
	private ConstructState parent;
	private int length;		// Length of this instantiation of the constructor
	private int offset;		// Absolute offset (from start of instruction)

	public ConstructState(ConstructState parent) {
		this.parent = parent;
		if (parent != null) {
			parent.addSubState(this);
		}
	}

	public ConstructState getSubState(int index) {
		return resolvedStates.get(index);
	}

	public void addSubState(ConstructState opState) {
		resolvedStates.add(opState);
	}

	public ConstructState getParent() {
		return parent;
	}

	@Override
	public int hashCode() {
		// returns statistically unique value
		return computeHashCode(0x56c93c59);
	}

	private int computeHashCode(int hashcode) {
		if (ct == null) {
			return hashcode;
		}
		int id = ct.getId();
		// Uses a Cyclic Redundancy Check (CRC32) as hash
		hashcode = SimpleCRC32.crc32tab[(hashcode ^ (id >> 8)) & 0xff] ^ (hashcode >> 8);
		hashcode = SimpleCRC32.crc32tab[(hashcode ^ id) & 0xff] ^ (hashcode >> 8);

		for (ConstructState subState : resolvedStates) {
			hashcode = subState.computeHashCode(hashcode);
		}

		return hashcode;
	}

	public Constructor getConstructor() {
		return ct;
	}

	void setConstructor(Constructor constructor) {
		ct = constructor;
	}

	public int getLength() {
		return length;
	}

	void setLength(int length) {
		this.length = length;
	}

	public int getOffset() {
		return offset;
	}

	void setOffset(int off) {
		this.offset = off;
	}

	/**
	 * Used for testing and diagnostics: list the constructor line numbers used to resolve this
	 * encoding
	 * 
	 * This includes braces to describe the tree structure
	 * @see AssemblyResolvedConstructor#dumpConstructorTree()
	 * @return the constructor tree
	 */
	public String dumpConstructorTree() {
		StringBuilder sb = new StringBuilder();
		if (ct == null) {
			return null;
		}
		sb.append(ct.getLineno());

		// TODO: This is not the most efficient, but it's diagnostic.
		List<String> subs = new ArrayList<>();
		for (ConstructState cs : resolvedStates) {
			String s = cs.dumpConstructorTree();
			if (s != null) {
				subs.add(s);
			}
		}

		if (subs.isEmpty()) {
			return sb.toString();
		}
		sb.append('[');
		sb.append(StringUtils.join(subs, ","));
		sb.append(']');
		return sb.toString();
	}
}
