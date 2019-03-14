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
package generic.lsh.vector;

import java.util.TreeSet;

/**
 *  A cosine vector where we can accumulate the (feature,weight) pairs over time
 *  using the addHash method.   Once either the getLength or compare methods is
 *  called the vector becomes "finalized" and acts as an ordinary LSHCosineVector
 */
public class LSHCosineVectorAccum extends LSHCosineVector {
	public static class Entry implements Comparable<Entry> {
		public final int hash;
		public final double weight;

		public Entry(int hash, double weight) {
			this.hash = hash;
			this.weight = weight;
		}

		@Override
		public int hashCode() {
			final int prime = 31;
			int result = 1;
			result = prime * result + hash;
			return result;
		}

		@Override
		public boolean equals(Object obj) {
			if (this == obj)
				return true;
			if (obj == null)
				return false;
			if (getClass() != obj.getClass())
				return false;
			Entry other = (Entry) obj;
			if (hash != other.hash)
				return false;
			return true;
		}

		/**
		 * Comparison must be UNSIGNED!!
		 */
		@Override
		public int compareTo(Entry o) {
			if (hash < 0) {
				if (o.hash >= 0)
					return 1;
			}
			else if (o.hash < 0)
				return -1;
			return (hash - o.hash);
		}

		@Override
		public String toString() {
			return hash + "(" + weight + ")";
		}
	}

	private TreeSet<Entry> treehash;
	private boolean finalized = false;

	public LSHCosineVectorAccum() {
		super();
		treehash = new TreeSet<Entry>();
	}

	public void addHash(int h, double w) {
		if (finalized) {
			throw new RuntimeException("already finalized");
		}
		treehash.add(new Entry(h, w));
	}

	public void doFinalize() {
		if (finalized)
			return;
		HashEntry[] entries = new HashEntry[treehash.size()];
		int count = 0;
		for (Entry entry : treehash) {
			HashEntry h = new HashEntry(entry.hash, 1, entry.weight);
			entries[count] = h;
			count += 1;
		}
		setHashEntries(entries);
		treehash = null;				// Allow the accumulator to be reclaimed
		finalized = true;
	}

	@Override
	public double getLength() {
		doFinalize();
		return super.getLength();
	}

	@Override
	public double compare(LSHVector op2, VectorCompare data) {
		doFinalize();
		((LSHCosineVectorAccum) op2).doFinalize();		// Trigger finalization
		return super.compare(op2, data);
	}

	@Override
	public int numEntries() {
		return treehash.size();
	}
}
