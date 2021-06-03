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
package ghidra.app.util.bin.format.pdb2.pdbreader.symbol;

import ghidra.app.util.bin.format.pdb2.pdbreader.*;

/**
 * Local Variable Flags for certain PDB symbols.
 */
public class LocalVariableFlags extends AbstractParsableItem {

	private int flags;
	private boolean isParameter;
	private boolean addressTaken;
	private boolean compilerGenerated;
	private boolean isAggregateWhole;
	private boolean isAggregatedPart;
	private boolean isAliased;
	private boolean isAlias;
	private boolean isFunctionReturnValue;
	private boolean isOptimizedOut;
	private boolean isEnregisteredGlobal;
	private boolean isEnregisteredStatic;

	/**
	 * Constructor for this symbol component.
	 * @param reader {@link PdbByteReader} from which this data is deserialized.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	public LocalVariableFlags(PdbByteReader reader) throws PdbException {
		flags = reader.parseUnsignedShortVal();
		processFlags(flags);
	}

	@Override
	public void emit(StringBuilder builder) {
		builder.insert(0, (isParameter) ? "Param: " : "Local: ");
		DelimiterState ds = new DelimiterState(" ", ", ");
		builder.append(ds.out(addressTaken, "Address Taken"));
		builder.append(ds.out(compilerGenerated, "Compiler Generated"));
		builder.append(ds.out(isAggregateWhole, "aggregate"));
		builder.append(ds.out(isAggregatedPart, "aggregated"));
		builder.append(ds.out(isAliased, "aliased"));
		builder.append(ds.out(isAlias, "alias"));
		builder.append(ds.out(isFunctionReturnValue, "return value"));
		builder.append(ds.out(isOptimizedOut, "optimized away"));
		if (isEnregisteredGlobal) {
			if (isEnregisteredStatic) {
				builder.append(ds.out(true, "file static"));
			}
			else {
				builder.append(ds.out(true, "global"));
			}
		}
		else if (isEnregisteredStatic) {
			builder.append(ds.out(true, "static local"));
		}
	}

	private void processFlags(int val) {
		isParameter = ((val & 0x0001) == 0x0001);
		val >>= 1;
		addressTaken = ((val & 0x0001) == 0x0001);
		val >>= 1;
		compilerGenerated = ((val & 0x0001) == 0x0001);
		val >>= 1;
		isAggregateWhole = ((val & 0x0001) == 0x0001);
		val >>= 1;
		isAggregatedPart = ((val & 0x0001) == 0x0001);
		val >>= 1;
		isAliased = ((val & 0x0001) == 0x0001);
		val >>= 1;
		isAlias = ((val & 0x0001) == 0x0001);
		val >>= 1;
		isFunctionReturnValue = ((val & 0x0001) == 0x0001);
		val >>= 1;
		isOptimizedOut = ((val & 0x0001) == 0x0001);
		val >>= 1;
		isEnregisteredGlobal = ((val & 0x0001) == 0x0001);
		val >>= 1;
		isEnregisteredStatic = ((val & 0x0001) == 0x0001);
	}

}
