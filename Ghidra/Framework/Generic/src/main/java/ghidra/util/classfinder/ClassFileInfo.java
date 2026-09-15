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
package ghidra.util.classfinder;

/**
 * Information about a class file on disk
 * 
 * @param path The path to the class file (or jar containing the class)
 * @param name The name of the class (including package)
 * @param suffix The class suffix (i.e., extension point type name)
 * @param module The module path for this class
 */
public record ClassFileInfo(String path, String name, String suffix, String module) {

	/**
	 * {@return the simple class name (no package name) for the class represented by this info}
	 */
	public String simpleName() {
		int index = name.lastIndexOf('.');
		if (index < 0) {
			return name; // no package
		}
		return name.substring(index + 1);
	}
}
