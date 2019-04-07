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
package ghidra.framework.main.logviewer.model;

import java.util.HashMap;
import java.util.Map;

import ghidra.framework.main.logviewer.ui.FVTable;

/**
 * A chunk represents the basic unit of text that is displayed in the {@link FVTable}. This does
 * NOT contain the actual text being displayed; rather it contains metadata describing the 
 * text (start/end byte positions, number of lines in the chunk, etc...).
 * 
 * It should be noted that chunks are transient - they are created and destroyed as different
 * sections of the file are required for display.
 *
 */
public class Chunk {

	// Stores the start and end byte positions of this chunk.
	public long start;
	public long end;

	// Maps a line within this chunk to a byte position within the file. ie: If this chunk
	// contains 20 lines, then byteMap.get(5) will return the starting byte position of the
	// 6th line.  
	//
	// Note that the line numbers in this map do NOT correspond to line numbers within the file, 
	// only within the chunk. 
	public Map<Integer, Pair> rowToFilePositionMap = new HashMap<Integer, Pair>();

	// Keeps track of the number of text lines represented by this chunk. This should always match
	// the ChunkModel.MAX_NUM_LINES var, except when reading the end of the file when 
	// there may not be that many lines left.
	public int linesInChunk = 0;

}
