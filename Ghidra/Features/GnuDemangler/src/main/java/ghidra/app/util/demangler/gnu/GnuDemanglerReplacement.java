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
package ghidra.app.util.demangler.gnu;

import java.util.Objects;

import generic.jar.ResourceFile;

/**
 * A simple object that is used to find and replace content within Gnu demangled strings.
 * @param find the string to search for; cannot be null
 * @param replace the replacement string; cannot be null
 * @param source the file from whence the replacement came; may be null
 */
public record GnuDemanglerReplacement(String find, String replace, ResourceFile source) {

	public GnuDemanglerReplacement {
		Objects.requireNonNull(find, "'find' cannot be null");
		Objects.requireNonNull(replace, "'replace' cannot be null");
	}

	@Override
	public String toString() {
		return replace + "\t\t" + find;
	}
}
