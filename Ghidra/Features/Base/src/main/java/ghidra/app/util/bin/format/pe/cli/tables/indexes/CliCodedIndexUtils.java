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
package ghidra.app.util.bin.format.pe.cli.tables.indexes;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.pe.cli.streams.CliStreamMetadata;
import ghidra.app.util.bin.format.pe.cli.tables.CliTypeTable;
import ghidra.program.model.data.*;
import ghidra.util.exception.InvalidInputException;

public class CliCodedIndexUtils {	
	public static DataType toDataType(CliStreamMetadata stream, int bitsUsed, CliTypeTable tables[]) {
		int maxForWord = (1 << (WordDataType.dataType.getLength()*8 - bitsUsed)) - 1;
		for (CliTypeTable table : tables) {
			if (table != null && stream.getNumberRowsForTable(table) > maxForWord)
				return DWordDataType.dataType;
		}
		return WordDataType.dataType;
	}
	
	public static CliTypeTable getTableName(int codedIndex, int bitsUsed, CliTypeTable tables[]) throws InvalidInputException {
		int mask = (2 << (bitsUsed - 1)) - 1; // 2 << (bitsUsed-1) == 2^(bitsUsed)
		int tableBits = codedIndex & mask;
		if (tableBits >= tables.length)
			throw new InvalidInputException("The coded index is not valid for this index type. There is no TableName for the bit pattern.");
		return tables[tableBits];
	}
	
	public static int getRowIndex(int codedIndex, int bitsUsed) {
		return codedIndex >> bitsUsed;
	}
	
	public static int readCodedIndex(BinaryReader reader, CliStreamMetadata stream, int bitsUsed, CliTypeTable tables[]) throws IOException {
		if (toDataType(stream, bitsUsed, tables).getLength() == WordDataType.dataType.getLength()) {
			return reader.readNextShort();
		}
		return reader.readNextInt();
	}

}
