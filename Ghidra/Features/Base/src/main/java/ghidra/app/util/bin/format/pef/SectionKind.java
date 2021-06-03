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
package ghidra.app.util.bin.format.pef;

/**
 * Values for the sectionKind field.
 * Section kind values for instantiated sections.
 */
public enum SectionKind {
	/** Code, presumed pure and position independent.*/
	Code(0, true),
	/** Unpacked writeable data.*/
	UnpackedData(1, true),
	/** Packed writeable data.*/
	PackedData(2, true),
	/** Read-only data.*/
	Constant(3, true),
	/** Loader tables.*/
	Loader(4,false),
	/** Reserved for future use.*/
	Debug(5, false),
	/** Intermixed code and writeable data.*/
	ExecutableData(6, true),
	/** Reserved for future use.*/
	Exception(7, false),
	/** Reserved for future use.*/
	Traceback(8, false);

	private int value;
	private boolean instantiated;

	private SectionKind(int value, boolean instantiated) {
		this.value = value;
		this.instantiated = instantiated;
	}

	public int getValue() {
		return value;
	}
	public boolean isInstantiated() {
		return instantiated;
	}

	public static SectionKind get(int value) {
		SectionKind [] kinds = values();
		for (SectionKind kind : kinds) {
			if (kind.value == value) {
				return kind;
			}
		}
		throw new IllegalArgumentException();
	}
}
