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
import java.util.*;
import java.util.Map.Entry;

/**
 * The abstraction for a line of output from {@code info proc mappings}
 */
public class GdbMemoryMapping {

	static class Index {
		final NavigableMap<BigInteger, GdbMemoryMapping> mappings;
		final Map<String, BigInteger> bases;

		public Index(NavigableMap<BigInteger, GdbMemoryMapping> mappings) {
			this.mappings = mappings;
			this.bases = new HashMap<>();
			for (GdbMemoryMapping mapping : mappings.values()) {
				if (mapping.objfile == null || mapping.objfile.isBlank()) {
					continue;
				}
				// Values should be ordered ascending by address
				if (bases.containsKey(mapping.objfile)) {
					continue;
				}
				bases.put(mapping.objfile, mapping.start);
			}
		}

		public BigInteger computeBase(BigInteger vma) {
			Entry<BigInteger, GdbMemoryMapping> floor = mappings.floorEntry(vma);
			if (floor == null) {
				return vma;
			}
			GdbMemoryMapping mapping = floor.getValue();
			// NB. Ends given by GDB are exclusive
			if (mapping.objfile.isBlank() || mapping.end.compareTo(vma) <= 0) {
				return vma;
			}
			return Objects.requireNonNull(bases.get(mapping.objfile));
		}

		public long computeBase(long vma) {
			return computeBase(BigInteger.valueOf(vma)).longValueExact();
		}
	}

	private final BigInteger start;
	private final BigInteger end;
	private final BigInteger size;
	private final BigInteger offset;
	private final String flags;
	private final String objfile;

	/**
	 * Construct a memory mapping
	 * 
	 * @param start the start offset
	 * @param end the end offset
	 * @param size the size (must be end - start)
	 * @param offset if backed by a file, the offset into that file
	 * @param flags the flags: rwxsp for read, write, execute, shared, private. If not known, the
	 *            default "rwx" should be used.
	 * @param objfile if backed by a file, the name of that file
	 */
	public GdbMemoryMapping(BigInteger start, BigInteger end, BigInteger size, BigInteger offset,
			String flags, String objfile) {
		this.start = start;
		this.end = end;
		this.size = size;
		this.offset = offset;
		this.flags = flags;
		this.objfile = objfile;

		assert Objects.equals(start.add(size), end);
	}

	/**
	 * The start offset
	 * 
	 * @return the offset
	 */
	public BigInteger getStart() {
		return start;
	}

	/**
	 * The end offset
	 * 
	 * @return the end
	 */
	public BigInteger getEnd() {
		return end;
	}

	/**
	 * The size
	 * 
	 * @return the size
	 */
	public BigInteger getSize() {
		return size;
	}

	/**
	 * If backed by a file, the offset into that file
	 * 
	 * @return the offset
	 */
	public BigInteger getOffset() {
		return offset;
	}

	/**
	 * The flags
	 * 
	 * <p>
	 * As of gdb-12.1, this is a four-character string, e.g., r--p, where the first three indicate
	 * <b>r</b>ead, <b>w</b>rite, and e<b>x</b>ecute. Each position is either the character
	 * indicating the flag is present, or a dash indicating the flag is absent. The final position
	 * is either {@code s} or {@code p} to indicate shared or private.
	 * 
	 * @return the flags
	 */
	public String getFlags() {
		return flags;
	}

	/**
	 * If backed by a file, the name of that file
	 * 
	 * @return the file
	 */
	public String getObjfile() {
		return objfile;
	}
}
