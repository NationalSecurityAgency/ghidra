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
package ghidra.formats.gfilesystem;

import org.apache.commons.collections4.map.ReferenceMap;

/**
 * A best-effort cache of MD5 values of local files based on their {name,timestamp,length} fingerprint.
 * <p>
 * Used to quickly verify that a local file hasn't changed.
 *
 */
public class FileFingerprintCache {

	private ReferenceMap<FileFingerprintRec, String> fileFingerprintToMD5Map = new ReferenceMap<>();

	/**
	 *  Clears the cache.
	 */
	public synchronized void clear() {
		fileFingerprintToMD5Map.clear();
	}

	/**
	 * Add a file's fingerprint to the cache.
	 *
	 * @param path String path to the file
	 * @param md5 hex-string md5 of the file
	 * @param timestamp long last modified timestamp of the file
	 * @param length long file size
	 */
	public synchronized void add(String path, String md5, long timestamp, long length) {
		fileFingerprintToMD5Map.put(new FileFingerprintRec(path, timestamp, length), md5);
	}

	/**
	 * Returns true if the specified file with the specified fingerprints (timestamp, length)
	 * was previously added to the cache with the specified md5.
	 *
	 * @param path String path to the file
	 * @param md5 hex-string md5 of the file
	 * @param timestamp long last modified timestamp of the file
	 * @param length long file size
	 * @return true if the fingerprint has previously been added to the cache.
	 */
	public synchronized boolean contains(String path, String md5, long timestamp, long length) {
		String prevMD5 =
			fileFingerprintToMD5Map.get(new FileFingerprintRec(path, timestamp, length));
		return prevMD5 != null && prevMD5.equals(md5);
	}

	/**
	 * Retrieves the md5 for the specified file that has the specified fingerprint (timestamp, length).
	 *
	 * @param path String path to the file
	 * @param timestamp long last modified timestamp of the file
	 * @param length long file size
	 * @return hex-string md5 or null if not present in the cache.
	 */
	public synchronized String getMD5(String path, long timestamp, long length) {
		String prevMD5 =
			fileFingerprintToMD5Map.get(new FileFingerprintRec(path, timestamp, length));
		return prevMD5;
	}

	//-----------------------------------------------------------------------------------

	static class FileFingerprintRec {
		final String path;
		final long timestamp;
		final long length;

		FileFingerprintRec(String path, long timestamp, long length) {
			this.path = path;
			this.timestamp = timestamp;
			this.length = length;
		}

		@Override
		public int hashCode() {
			final int prime = 31;
			int result = 1;
			result = prime * result + (int) (length ^ (length >>> 32));
			result = prime * result + ((path == null) ? 0 : path.hashCode());
			result = prime * result + (int) (timestamp ^ (timestamp >>> 32));
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
			if (!(obj instanceof FileFingerprintRec)) {
				return false;
			}
			FileFingerprintRec other = (FileFingerprintRec) obj;
			if (length != other.length) {
				return false;
			}
			if (path == null) {
				if (other.path != null) {
					return false;
				}
			}
			else if (!path.equals(other.path)) {
				return false;
			}
			if (timestamp != other.timestamp) {
				return false;
			}
			return true;
		}
	}
}
