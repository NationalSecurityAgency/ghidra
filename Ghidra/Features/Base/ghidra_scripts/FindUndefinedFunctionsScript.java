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
//Finds undefined functions by searching for common 
//byte patterns used by compilers for function entry points.
//
//Only Intel GCC, Windows, and PowerPC are currently
//handled.
//
//Please feel free to change this script and add
//different byte patterns.
//
//When the byte pattern is found, the instructions 
//will be disassembled and a function will be created.
//
//Please note: this will NOT find all undefined functions!
//@category Functions

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.listing.Data;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;

public class FindUndefinedFunctionsScript extends GhidraScript {

	@Override
	public void run() throws Exception {
		PatternMatcher[] expectedPatterns = getPatterns();

		boolean doIT =
			askYesNo("Find and Create Functions?", "Would you like find and create functions?");
		if (!doIT) {
			return;
		}

		for (PatternMatcher expectedPattern : expectedPatterns) {
			Address address = currentProgram.getMinAddress();
			while (true) {
				if (monitor.isCancelled()) {
					break;
				}

				Data nextUndefined =
					currentProgram.getListing().getUndefinedDataAfter(address, monitor);
				if (nextUndefined == null) {
					break;
				}
				Address undefinedAddress = nextUndefined.getMinAddress();

				MemoryBlock block = currentProgram.getMemory().getBlock(undefinedAddress);
				if (!block.isExecute()) {
					address = undefinedAddress;
					continue;
				}

				if (expectedPattern.isMatch(undefinedAddress)) {
					disassemble(undefinedAddress);
					createFunction(undefinedAddress, null);
					address = undefinedAddress.add(1);
				}
				else {
					address = undefinedAddress;
				}
			}
		}
	}

	private PatternMatcher[] getPatterns() {
		if (currentProgram == null) {
			return null;
		}

		Processor processor = currentProgram.getLanguage().getProcessor();

		if (processor.equals(Processor.findOrPossiblyCreateProcessor("x86"))) {
			CompilerSpecID compilerSpecID = currentProgram.getCompilerSpec().getCompilerSpecID();
			if (compilerSpecID.equals(new CompilerSpecID("windows"))) {
				return new PatternMatcher[] { new PatternMatcher(new byte[] { (byte) 0x55,
					(byte) 0x8b, (byte) 0xec }, false), };
			}
			if (compilerSpecID.equals(new CompilerSpecID("gcc"))) {
				return new PatternMatcher[] { new PatternMatcher(new byte[] { (byte) 0x55,
					(byte) 0x89, (byte) 0xe5 }, false), };
			}
		}

		// Endianness OK here?
		if (processor.equals(Processor.findOrPossiblyCreateProcessor("PowerPC"))) {
			return new PatternMatcher[] { new PatternMatcher(new byte[] { (byte) 0x7c, (byte) 0x08,
				(byte) 0x02, (byte) 0xa6 }, false),//
			};
		}
		if (processor.equals(Processor.findOrPossiblyCreateProcessor("ARM"))) {
			return new PatternMatcher[] {
				//new PatternMatcher(new byte[]{(byte)0x00,(byte)0x00,(byte)0x50,(byte)0xe3}, true),//only check 'cmp' at function entry
				//new PatternMatcher(new byte[]{(byte)0x00,(byte)0x00,(byte)0x51,(byte)0xe3}, true),//only check 'cmp' at function entry
				//new PatternMatcher(new byte[]{(byte)0x00,(byte)0x00,(byte)0x53,(byte)0xe3}, true),//only check 'cmp' at function entry
				new PatternMatcher(
					new byte[] { (byte) 0xf0, (byte) 0x40, (byte) 0x2d, (byte) 0xe9 }, false),//stmdb sp!{r4 r5 r6 r7 lr}
				new PatternMatcher(
					new byte[] { (byte) 0xb0, (byte) 0x40, (byte) 0x2d, (byte) 0xe9 }, false),//stmdb sp!{r4 r5 r7 lr}
				new PatternMatcher(
					new byte[] { (byte) 0x90, (byte) 0x40, (byte) 0x2d, (byte) 0xe9 }, false),//stmdb sp!{r4 r7 lr}
				new PatternMatcher(
					new byte[] { (byte) 0x80, (byte) 0x40, (byte) 0x2d, (byte) 0xe9 }, false),//stmdb sp!{r7 lr}
			};
		}
		throw new RuntimeException("Unsupported language.");
	}

	private class PatternMatcher {
		byte[] expectedBytes;
		boolean requiresEntyPoint;

		PatternMatcher(byte[] expectedBytes, boolean requiresEntryPoint) {
			this.expectedBytes = expectedBytes;
			this.requiresEntyPoint = requiresEntryPoint;
		}

		boolean isMatch(Address undefinedAddress) throws MemoryAccessException {
			byte[] actualBytes = new byte[expectedBytes.length];
			currentProgram.getMemory().getBytes(undefinedAddress, actualBytes);

			if (equals(expectedBytes, actualBytes)) {
				if (requiresEntyPoint) {
//					return currentProgram.getSymbolTable().isExternalEntryPoint(undefinedAddress);
					Symbol primarySymbol =
						currentProgram.getSymbolTable().getPrimarySymbol(undefinedAddress);
					return (primarySymbol != null) &&
						(primarySymbol.getSource() == SourceType.IMPORTED);
				}
				return true;
			}
			return false;
		}

		private boolean equals(byte[] expected, byte[] actual) {
			if (expected.length != actual.length) {
				return false;
			}
			for (int i = 0; i < expected.length; ++i) {
				if (expected[i] != actual[i]) {
					return false;
				}
			}
			return true;
		}
	}

//	private String toString(byte [][] bytes) {
//		StringBuffer buffer = new StringBuffer();
//		for (byte [] array : bytes) {
//			buffer.append('[');
//			for (byte b : array) {
//				buffer.append(toHexString(b, true, true));
//				buffer.append(',');
//			}
//			buffer.deleteCharAt(buffer.length()-1);
//			buffer.append(']');
//			buffer.append('\n');
//		}
//		return buffer.toString();
//	}

}
