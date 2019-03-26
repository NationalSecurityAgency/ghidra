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

import java.io.IOException;

import org.apache.commons.collections4.map.ReferenceMap;

/**
 * A best-effort cache of MD5 values of files, where the file is identified by its parent's
 * MD5 combined with the file's path inside its parent's 'namespace'.
 */
public class FileCacheNameIndex {

	/**
	 * An unlimited size, soft-reference, cache of file md5 values, keyed by a name specific
	 * to a parent file.
	 */
	private ReferenceMap<String, String> parentMD5ObjNameToMD5Map = new ReferenceMap<>();

	public synchronized void clear() {
		parentMD5ObjNameToMD5Map.clear();
	}

	/**
	 * Adds a filename mapping to this cache.
	 *
	 * @param parentMD5 the md5 string of the parent object
	 * @param name the name of this object
	 * @param fileMD5 the md5 string of this object
	 * @throws IOException if missing or bad md5 values.
	 */
	public synchronized void add(String parentMD5, String name, String fileMD5) throws IOException {
		if (parentMD5 == null || parentMD5.length() != FileCache.MD5_HEXSTR_LEN) {
			throw new IOException(
				"Bad MD5 for parent object: " + parentMD5 + ", " + name + ", " + fileMD5);
		}
		if (fileMD5 == null) {
			throw new IOException("Bad fileMD5 value for " + parentMD5 + ", " + name);
		}

		String key = parentMD5 + "_" + name;
		parentMD5ObjNameToMD5Map.put(key, fileMD5);
	}

	/**
	 * Retrieves a filename mapping from this cache.
	 *
	 * @param parentMD5 the md5 string of the parent object
	 * @param name the name of the requested object.
	 * @return the md5 string of the requested object, or null if not in cache.
	 * @throws IOException if missing or bad parent md5 values.
	 */
	public synchronized String get(String parentMD5, String name) throws IOException {
		if (parentMD5 == null || parentMD5.length() != FileCache.MD5_HEXSTR_LEN) {
			throw new IOException("Bad MD5 for parent object: " + parentMD5 + ", " + name);
		}
		String key = parentMD5 + "_" + name;
		return parentMD5ObjNameToMD5Map.get(key);
	}

}
