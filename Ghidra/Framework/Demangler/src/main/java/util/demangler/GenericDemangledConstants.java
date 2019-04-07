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
package util.demangler;

public final class GenericDemangledConstants {

	public final static String VISIBILITY_public = "public";
	public final static String VISIBILITY_protected = "protected";
	public final static String VISIBILITY_private = "private";
	public final static String VISIBILITY_static = "static";
	public final static String VISIBILITY_global = "global";
	public final static String VISIBILITY_virtual = "virtual";

	public final static String[] VISIBILITY_ARR = { VISIBILITY_public, VISIBILITY_protected,
		VISIBILITY_private, VISIBILITY_static, VISIBILITY_global, VISIBILITY_virtual, };

	public final static boolean isVisibility(String visibility) {
		return contains(VISIBILITY_ARR, visibility);
	}

	/////////////////////////////////////////////////////

	public final static String STORAGE_CLASS_const = "const";
	public final static String STORAGE_CLASS_volatile = "volatile";
	public final static String STORAGE_CLASS_far = "far";
	public final static String STORAGE_CLASS_restrict = "restrict";

	public final static String[] STORAGE_CLASS_ARR = { STORAGE_CLASS_const, STORAGE_CLASS_volatile,
		STORAGE_CLASS_far, STORAGE_CLASS_restrict, };

	public final static boolean isStorageClass(String storageClass) {
		return contains(STORAGE_CLASS_ARR, storageClass);
	}

	/////////////////////////////////////////////////////

	private final static boolean contains(String[] array, String target) {
		for (String element : array) {
			if (element.equals(target)) {
				return true;
			}
		}
		return false;
	}
}
