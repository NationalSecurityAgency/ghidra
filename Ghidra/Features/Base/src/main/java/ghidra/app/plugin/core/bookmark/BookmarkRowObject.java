/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.app.plugin.core.bookmark;

class BookmarkRowObject implements Comparable<BookmarkRowObject> {

	private final long key;

	BookmarkRowObject(long key) {
		this.key = key;
	}

	long getKey() {
		return key;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + (int) (key ^ (key >>> 32));
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		BookmarkRowObject other = (BookmarkRowObject) obj;
		if (key != other.key) {
			return false;
		}
		return true;
	}

	@Override
	public int compareTo(BookmarkRowObject o) {
		return ((Long) key).compareTo(o.key);
	}

	@Override
	public String toString() {
		return getClass().getSimpleName() + "[key=" + key + "]";
	}
}
