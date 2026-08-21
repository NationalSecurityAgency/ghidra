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
package ghidra.app.util.sourcelanguage;

import java.io.IOException;
import java.util.concurrent.atomic.AtomicBoolean;

import ghidra.app.plugin.core.analysis.rust.RustConstants;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.bytesearch.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * The base Rust {@link SourceLanguage} class
 */
public abstract class RustSourceLanguage implements SourceLanguage {

	public static final SourceLanguageID RUST_ID = new SourceLanguageID("Rust");

	@Override
	public SourceLanguageID getID() {
		return RUST_ID;
	}

	/**
	 * Checks if the specified program contains Rust stuff, either by metadata or by searching
	 * the specified {@link MemoryBlock} for byte pattern signatures. 
	 * <p>
	 * This may be used by loaders to determine if a program was compiled with rust.
	 * If the program is determined to be rust, then the compiler property is set to
	 * {@link RustConstants#RUST_COMPILER}.
	 *
	 * @param program The {@link Program}
	 * @param block The {@link MemoryBlock} to scan for Rust signatures
	 * @param monitor The monitor
	 * @return True if the given {@link MemoryBlock} is not null and contains a Rust signature; 
	 *   otherwise, false
	 * @throws IOException if there was an IO-related error
	 * @throws CancelledException if the user cancelled the operation
	 */
	public boolean isRust(Program program, MemoryBlock block, TaskMonitor monitor)
			throws IOException, CancelledException {

		if (block == null) {
			return false;
		}

		// Use a MemoryBytePatternSearch for more efficient byte searching over a list of potential
		// byte signatures. The below action sets our supplied boolean to true on a match, which we
		// can later query and use as a return value for this method.
		GenericMatchAction<AtomicBoolean> action =
			new GenericMatchAction<AtomicBoolean>(new AtomicBoolean()) {
				@Override
				public void apply(Program prog, Address addr, Match match) {
					getMatchValue().set(true);
				}
			};
		MemoryBytePatternSearcher searcher = new MemoryBytePatternSearcher("Rust signatures");
		for (byte[] sig : RustConstants.RUST_SIGNATURES) {
			searcher.addPattern(new GenericByteSequencePattern<AtomicBoolean>(sig, action));
		}

		searcher.search(program, new AddressSet(block.getAddressRange()), monitor);

		return action.getMatchValue().get();
	}
}
