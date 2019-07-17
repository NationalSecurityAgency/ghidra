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
package ghidra.feature.vt.api.main;

/**
 * VTMatchTag is the interface for the user defined tags that can be set on a version tracking match.
 */
public interface VTMatchTag extends Comparable<VTMatchTag> {

	VTMatchTag UNTAGGED = new VTMatchTag() {
		@Override
		public String getName() {
			return "";
		}

		@Override
		public String toString() {
			return "<Not Tagged>";
		}

		public int compareTo(VTMatchTag o) {
			return getName().compareTo(o.getName());
		}
	};

	/**
	 * Gets the user defined name this tag represents.
	 * @return the tag name
	 */
	public String getName();
}
