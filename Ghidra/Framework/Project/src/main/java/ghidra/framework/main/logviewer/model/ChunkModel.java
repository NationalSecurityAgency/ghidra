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

import java.util.*;

/**
 * Stores all chunks read-in by the {@link ChunkReader}. The model is responsible for handling all
 * interaction with the list of chunks.
 *
 */
public class ChunkModel implements Iterable<Chunk> {

	// List of all chunks currently in the table. This should be protected from modification by
	// any other classes.
	private List<Chunk> chunks = new ArrayList<>();

	// Keeps track of the row(s) currently selected in the table, as a start and end byte value.
	// This is required for when the selected rows are scrolled out of view such that they are no longer
	// in the table (and no chunk exists for them), but then must be restored when/if that chunk
	// is loaded into view again.
	public long selectedByteStart;
	public long selectedByteEnd;

	// The maximum number of lines that should be read into a chunk.
	public final int NUM_LINES = 250;

	// The maximum number of chunks to display. This should not change, although it can be 
	// safely increased. It is not recommended to set this less than 3.
	public final int MAX_VISIBLE_CHUNKS = 3;

	/**
	 * Adds the given chunk to the model.
	 * 
	 * @param chunk
	 */
	public void add(Chunk chunk) {
		chunks.add(chunk);
	}

	/**
	 * Adds a chunk at the given index to the model.
	 * 
	 * @param index
	 * @param chunk
	 */
	public void add(int index, Chunk chunk) {
		chunks.add(index, chunk);
	}

	/**
	 * Removes the chunk at the given index from the model.
	 * 
	 * @param index
	 */
	public Chunk remove(int index) {
		if (index >= 0 && index < chunks.size()) {
			return chunks.remove(index);
		}

		return null;
	}

	/**
	 * Clears all chunks from the model.
	 */
	public void clear() {
		this.chunks.clear();
	}

	/**
	 * Returns the number of chunks in the model.
	 * 
	 * @return
	 */
	public int getSize() {
		return chunks.size();
	}

	/**
	 * Returns the chunk at the given index.
	 * 
	 * @param index
	 * @return
	 */
	public Chunk get(int index) {
		if (index >= 0 && index < chunks.size()) {
			return chunks.get(index);
		}

		return null;
	}

	@Override
	public Iterator<Chunk> iterator() {
		Iterator<Chunk> iterator = chunks.iterator();
		return iterator;
	}
	
	/**
	 * 
	 * @return
	 */
	public int getNumChunks() {
		return chunks.size();
	}

	/**
	 * Returns the start/end byte positions within the input file for the given row.
	 * 
	 * To do this we have to loop over all chunks in the {@link ChunkModel} and count the number 
	 * of lines in each chunk until we get to the line (row) we're looking for. We then grab the 
	 * correct value from the byteMap for that chunk line, which is the starting byte for it.
	 * 
	 * @param row
	 * @return the byte position in the file this row corresponds to
	 */
	public Pair getFilePositionForRow(int row) {

		int totalLines = 0;

		Iterator<Chunk> iter = this.iterator();
		while (iter.hasNext()) {
			Chunk chunk = iter.next();
			if (row < chunk.linesInChunk + totalLines) {
				int myRow = chunk.linesInChunk - ((chunk.linesInChunk + totalLines) - row);
				Pair byteRange = chunk.rowToFilePositionMap.get(myRow);
				return byteRange;
			}
			totalLines += chunk.linesInChunk;
		}

		return null;
	}

	/**
	 * Searches the visible chunks to see if any of them contain the given byte. If so, returns
	 * the row in the table where it resides. Returns -1 otherwise.
	 * 
	 * @param selectedByte
	 * @return
	 */
	public int getRowForBytePos(long selectedByte) {

		int totalLines = 0;

		Iterator<Chunk> iter = this.iterator();
		while (iter.hasNext()) {
			Chunk chunk = iter.next();
			
			// See if this byte is in this chunk before doing anything.
			if (selectedByte >= chunk.start && selectedByte <= chunk.end) {	
				
				// We know our byte is in this chunk, so now find out exactly which row it's in.
				for (Map.Entry<Integer, Pair> entry : chunk.rowToFilePositionMap.entrySet()) {
					Integer key = entry.getKey();
					Pair value = entry.getValue();
					if (selectedByte >= value.getStart() && selectedByte <= value.getEnd()) {
						return key + totalLines;
					}
				}
			}

			totalLines += chunk.linesInChunk;
		}

		return -1;
	}
}
