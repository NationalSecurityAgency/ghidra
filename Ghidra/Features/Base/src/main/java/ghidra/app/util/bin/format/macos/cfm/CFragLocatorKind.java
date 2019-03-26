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

import ghidra.app.util.bin.BinaryReader;

import java.io.IOException;

/**
 * Values for type CFragLocatorKind.
 */
public enum CFragLocatorKind {
	/** Container is in memory. */
	kMemoryCFragLocator,
	/** Container is in a file's data fork. */
	kDataForkCFragLocator,
	/** Container is in a file's resource fork. */
	kResourceCFragLocator,
	/** Reserved for possible future use. */
	kNamedFragmentCFragLocator,
	/** Container is in the executable of a CFBundle. */
	kCFBundleCFragLocator,
	/** Passed to init routines in lieu of kCFBundleCFragLocator. */
	kCFBundlePreCFragLocator;

	public static CFragLocatorKind get(BinaryReader reader) throws IOException {
		int value = reader.readNextByte() & 0xff;
		return values()[value];
	}
}
