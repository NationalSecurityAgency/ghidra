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
package ghidra.processors.tile;

import ghidra.program.model.lang.*;
import ghidra.program.model.listing.Program;

/**
 * TILE processor loader. This class loads TILE binaries into Ghidra's program database.
 * TILEGX is a RISC processor from Tilera with 64-bit registers and fixed-length 32-bit instructions.
 * Supports both big-endian and little-endian configurations.
 */
public class TILEProcesser {

	/** Unique identifier for the TILE processor type. */
	public static final String PROCESSOR_TYPE = "TILE";
	/** Base language ID for the default big-endian 64-bit TILE configuration. */
	public static final String LANGUAGE_ID_BASE = "TILE:BE:64:default";

	/**
	 * Returns the name of the TILE processor.
	 * @return the string "TILE"
	 */
	public String getName() {
		return "TILE";
	}

	/**
	 * Returns a human-readable description of the TILE loader.
	 * @return description string used in Ghidra's GUI and log output
	 */
	public String getDescription() {
		return "TILE (TileProcessor) Loader";
	}

	/**
	 * Returns the base language ID for the TILE processor.
	 * @return the language ID string "TILE:BE:64:default" used by Ghidra's language database
	 */
	public String getLanguageIDBase() {
		return "TILE:BE:64:default";
	}

	/**
	 * Indicates whether the TILE processor supports debugger integration.
	 * @return true to enable debugger support in the Ghidra GUI
	 */
	public boolean hasSupportForDebugger() {
		return true;
	}

	/**
	 * Indicates whether the TILE processor supports debugger-specific operations
	 * such as instruction stepping, register inspection, and memory access.
	 * @return true to enable advanced debugger capabilities
	 */
	public boolean hasSupportForDebuggerSupport() {
		return true;
	}
}
