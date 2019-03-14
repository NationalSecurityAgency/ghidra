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
package ghidra.app.plugin.core.overview.entropy;

/**
 * Enum for defining known entropy ranges
 */
public enum EntropyKnot {

	NONE("None", null),
	X86("x86 code", new EntropyRecord("x86", 5.94, 0.4)),
	ARM("ARM code", new EntropyRecord("arm", 5.1252, 0.51)),
	THUMB("THUMB code", new EntropyRecord("thumb", 6.2953, 0.5)),
	POWER_PC("PowerPC code", new EntropyRecord("powerpc", 5.6674, 0.52)),
	ASCII("ASCII strings", new EntropyRecord("ascii", 4.7, 0.5)),
	COMPRESSED("Compressed", new EntropyRecord("compressed", 8.0, 0.5)),
	UTF16("Unicode UTF16", new EntropyRecord("utf16", 3.21, 0.2));

	private String label;
	private EntropyRecord record;

	private EntropyKnot(String label, EntropyRecord rec) {
		this.label = label;
		this.record = rec;
	}

	@Override
	public String toString() {
		return label;
	}

	public EntropyRecord getRecord() {
		return record;
	}
}
