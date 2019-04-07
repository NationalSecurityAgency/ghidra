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
package ghidra.sleigh.grammar;

public class Location {
	public static final Location INTERNALLY_DEFINED = new Location("<internally defined>", 1);

	public final String filename;
	public final int lineno;

	public Location(String filename, int lineno) {
		this.filename = filename;
		this.lineno = lineno;
	}

	@Override
	public String toString() {
		return filename + ":" + lineno;
	}
}
