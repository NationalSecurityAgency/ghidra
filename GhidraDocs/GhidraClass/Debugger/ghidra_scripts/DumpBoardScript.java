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
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.debug.flatapi.FlatDebuggerAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.Symbol;
import ghidra.trace.model.Trace;

public class DumpBoardScript extends GhidraScript implements FlatDebuggerAPI {
	@Override
	protected void run() throws Exception {
		// --------------------------------
		Trace trace = getCurrentTrace();
		if (trace == null) {
			throw new AssertionError("There is no active session");
		}

		// --------------------------------
		if (!"termmines".equals(currentProgram.getName())) {
			throw new AssertionError("The current program must be termmines");
		}

		// --------------------------------
		List<Symbol> widthSyms = getSymbols("width", null);
		if (widthSyms.isEmpty()) {
			throw new AssertionError("Symbol 'width' is required");
		}
		List<Symbol> heightSyms = getSymbols("height", null);
		if (heightSyms.isEmpty()) {
			throw new AssertionError("Symbol 'height' is required");
		}
		List<Symbol> cellsSyms = getSymbols("cells", null);
		if (cellsSyms.isEmpty()) {
			throw new AssertionError("Symbol 'cells' is required");
		}

		Address widthDyn = translateStaticToDynamic(widthSyms.get(0).getAddress());
		if (widthDyn == null) {
			throw new AssertionError("Symbol 'width' is not mapped to target");
		}
		Address heightDyn = translateStaticToDynamic(heightSyms.get(0).getAddress());
		if (heightDyn == null) {
			throw new AssertionError("Symbol 'height' is not mapped to target");
		}
		Address cellsDyn = translateStaticToDynamic(cellsSyms.get(0).getAddress());
		if (cellsDyn == null) {
			throw new AssertionError("Symbol 'cells' is not mapped to target");
		}

		// --------------------------------
		byte[] widthDat = readMemory(widthDyn, 4, monitor);
		byte[] heightDat = readMemory(heightDyn, 4, monitor);
		byte[] cellsData = readMemory(cellsDyn, 1024, monitor);

		// --------------------------------
		int width = ByteBuffer.wrap(widthDat).order(ByteOrder.LITTLE_ENDIAN).getInt();
		int height = ByteBuffer.wrap(heightDat).order(ByteOrder.LITTLE_ENDIAN).getInt();
		println("Width: " + width);
		println("Height: " + height);
		for (int y = 0; y < height; y++) {
			for (int x = 0; x < width; x++) {
				if ((cellsData[(y + 1) * 32 + x + 1] & 0x80) == 0x80) {
					println("Mine at (%d,%d)".formatted(x, y));
				}
			}
		}
	}
}
