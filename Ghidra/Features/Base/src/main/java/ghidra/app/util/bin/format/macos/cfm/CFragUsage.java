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
package ghidra.app.util.bin.format.macos.cfm;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;

/**
 * Values for type CFragUsage
 */
public enum CFragUsage {
	/** Standard CFM import library. */
	kImportLibraryCFrag,
	/** MacOS application. */
	kApplicationCFrag,
	/** Application or library private extension/plug-in. */
	kDropInAdditionCFrag,
	/** Import library used for linking only. */
	kStubLibraryCFrag,
	/** Import library used for linking only and will be automatically weak linked. */
	kWeakStubLibraryCFrag;

	public static CFragUsage get(BinaryReader reader) throws IOException {
		int value = reader.readNextByte() & 0xff;
		return values()[value];
	}
}
