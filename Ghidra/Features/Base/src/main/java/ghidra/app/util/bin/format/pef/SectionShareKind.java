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
package ghidra.app.util.bin.format.pef;

/**
 * Values for the shareKind field.
 */
public enum SectionShareKind {
	/**
	 * Indicates the section is shared within a process,
	 * but a fresh copy is created for different processes.
	 */
	ProcessShare(1),
	/**
	 * Indicates the section is shared between all
	 * processes in the system.
	 */
	GlobalShare(4),
	/**
	 * Indicates the section is shared between all processes,
	 * but is protected. Protected sections are read/write
	 * in privileged mode and read-only in user mode.
	 */
	ProtectedShare(5);

	private int value;

	private SectionShareKind(int value) {
		this.value = value;
	}

	public int getValue() {
		return value;
	}

	public static SectionShareKind get(int value) {
		SectionShareKind [] kinds = values();
		for (SectionShareKind kind : kinds) {
			if (kind.value == value) {
				return kind;
			}
		}
		throw new IllegalArgumentException();
	}
}
