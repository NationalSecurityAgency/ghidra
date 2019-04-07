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

import java.io.*;
import java.util.*;

import ghidra.framework.main.logviewer.ui.FVTable;

/**
 * This class handles reading data from the input file, in the form of {@link Chunk} objects.  Each
 * chunk is stored in the {@link ChunkModel} and represents a single block of text that is 
 * displayed in the {@link FVTable}.
 * 
 */
public class ChunkReader {

	// A handle to the file being read.
	private RandomAccessFile raf;

	// Responsible for reading lines from the file in reverse. This is required when we need
	// to retrieve a previous chunk (ie: when scrolling up).  
	private ReverseLineReader reverser;

	// Stores all chunks currently being viewed.
	private ChunkModel model;

	// The file being viewed.
	private File file;

	/**
	 * 
	 * @param file
	 * @param model
	 * @throws IOException
	 */
	public ChunkReader(File file, ChunkModel model) throws IOException {
		this.model = model;
		this.file = file;
		reload();
	}

	/**
	 * Returns the number of bytes in the input file.
	 * 
	 * @return number of bytes
	 * @throws IOException 
	 */
	public long getFileSize() throws IOException {
		return raf == null ? 0 : raf.length();
	}

	/**
	 * Returns the file being read.
	 * 
	 * @return
	 */
	public File getFile() {
		return file;
	}

	/**
	 * 
	 */
	public void reload() throws IOException {
		raf = new RandomAccessFile(file, "r");
		reverser = new ReverseLineReader("UTF-8", raf);
	}

	/**
	 * Reads one chunk from the end of the file. This is useful when scrolling to the bottom of
	 * the viewport.
	 * 
	 * @return the last chunk, or an empty list
	 * @throws IOException
	 */
	public synchronized List<String> readLastChunk() throws IOException {

		if (raf == null) {
			return new ArrayList<>();
		}

		raf.seek(raf.length());
		return readChunkInReverse(raf.getFilePointer());
	}

	/**
	 * Reads the chunk immediately before the first visible one.
	 * 
	 * @return the previous chunk, or an empty list
	 * @throws IOException
	 */
	public synchronized List<String> readPreviousChunk() throws IOException {

		Chunk first = model.get(0);
		if (first == null) {
			return Collections.<String> emptyList();
		}

		if (raf == null) {
			return Collections.<String> emptyList();
		}
		raf.seek(first.start);
		return readChunkInReverse(raf.getFilePointer());
	}

	/**
	 * Reads a chunk of data from the given location in the file.  To ensure we're always reading
	 * full lines, take the given start position and move forward to the next full line before
	 * reading.
	 * 
	 * @param startByte the position to start reading from
	 * @return the lines of text read
	 * @throws IOException
	 */
	public synchronized List<String> readNextChunkFrom(long startByte) throws IOException {

		if (raf == null) {
			return Collections.<String> emptyList();
		}
		
		// move the pointer to the beginning of the line this byte position is in.
		long lineStart = getStartOfNextLine(startByte);
		raf.seek(lineStart);
			
		return readChunk(raf.getFilePointer());
	}
	
	/**
	 * Reads all bytes from the given byte to the end byte. If the amount of bytes to be read is
	 * greater than the size of an INT, we will have to read this in several chunks, hence the
	 * need to return a list of arrays, and not just a single byte array.
	 * 
	 * @param startByte
	 * @param endByte
	 * @return a map of all the bytes read in (index 0 is first chunk, 1 is next, etc...).
	 * 
	 * @throws IOException 
	 */
	public List<byte[]> readBytes(long startByte, long endByte) throws IOException {
		
		if (raf == null) {
			return Collections.<byte[]> emptyList();
		}
		
		// The list to return.
		List<byte[]> byteArrayList = new ArrayList<>();
		
		// Move the file pointer to the start.
		raf.seek(startByte);
		
		// Figure out how many bytes we need to read.  If the size is greater than MAX_INT, then
		// we have to chunk this up into several reads, as java doesn't support creating byte 
		// arrays with size > MAX_INT.
		long bytesToRead = endByte - startByte + 1;
		while(bytesToRead > 0) {
			byte[] byteArray = bytesToRead > Integer.MAX_VALUE ? new byte[Integer.MAX_VALUE]
					: new byte[(int) bytesToRead];
			int bytesRead = raf.read(byteArray);

			if (bytesRead > 0) {
				byteArrayList.add(byteArray);
				bytesToRead -= bytesRead;
			}
		}
				
		return byteArrayList;
	}

	/**
	 * Reads the next chunk in the file past the last one specified in the {@link ChunkModel}. 
	 * 
	 * @return the lines of text read
	 * @throws FileNotFoundException
	 * @throws IOException
	 */
	public synchronized List<String> readNextChunk() throws FileNotFoundException, IOException {

		if (raf == null) {
			return Collections.<String> emptyList();
		}

		// Need to figure out the position of the last read, and the last corresponding line.
		long readPos = 0;

		// Get end file pos of the last visible chunk, if there is one; if there isn't, just
		// stay at 0.
		if (model.getSize() > 0) {
			Chunk last = model.get(model.getSize() - 1);

			if (last == null) {
				return Collections.<String> emptyList();
			}

			readPos = last.end;
		}

		// Seek to the point in the file indicated by the chunk, and start reading.
		raf.seek(readPos);
		return readChunk(raf.getFilePointer());
	}

	/*************************************************************************************
	 * PRIVATE METHODS
	 *************************************************************************************/
	
	/**
	 * Reads a single chunk of data from the input file. The start point of the read is wherever
	 * the {@link #raf} is currently pointing.
	 * 
	 * @param startByte the byte in the file at which to start reading.
	 * @return the lines of text read
	 * @throws IOException
	 */
	private List<String> readChunk(long startByte) throws IOException {

		if (raf == null) {
			return Collections.<String> emptyList();
		}

		// Create a new chunk to represent the next set of lines we're viewing.
		Chunk chunk = new Chunk();

		List<String> lines = new ArrayList<>();

		// First put the file pointer at beginning of the next line after the start byte given,
		// to make sure we read a full line and not a partial one.
		long lineStart = getStartOfNextLine(startByte);
		raf.seek(lineStart);
		
		// And now start reading in lines.
		for (int i = 0; i < model.NUM_LINES; i++) {
			lineStart = raf.getFilePointer();
			String line = raf.readLine();
			if (line != null) {
				chunk.rowToFilePositionMap.put(i, new Pair(lineStart, raf.getFilePointer()-1));
				lines.add(line);
			}
		}

		// If we have a valid chunk, store some metadata and add it to the model.
		addChunkToModel(chunk, lines, startByte, raf.getFilePointer()-1, false);

		return lines;
	}

	/**
	 * Reads in a chunk from the current file pointer location, backwards.
	 * 
	 * @param startByte the start byte from which to read
	 * @return the lines of text read
	 * @throws IOException
	 */
	private List<String> readChunkInReverse(long startByte) throws IOException {

		if (raf == null || startByte == 1) {
			return Collections.<String> emptyList();
		}

		// Store the end position of the read (where we'll actually start reading from).
		long endPos = startByte;

		// And now tell the reverser where to start.
		reverser.setFilePos(endPos);

		// Create a new chunk to represent the next set of lines we'll be reading.
		Chunk chunk = new Chunk();

		List<String> lines = new ArrayList<>();
		List<Pair> filePositions = new ArrayList<>();

		for (int i = model.NUM_LINES - 1; i >= 0; i--) {

			long end = raf.getFilePointer();
			String line = reverser.readLine();

			if (line == null) {
				break;
			}

			lines.add(line);
			if (raf.getFilePointer() > 0) {
				filePositions.add(new Pair(raf.getFilePointer(), end-1));
			}
			else {
				filePositions.add(new Pair(0, end-1));
			}
		}

		Collections.reverse(filePositions);
		for (int i = 0; i < lines.size(); i++) {
			chunk.rowToFilePositionMap.put(i, filePositions.get(i));
		}

		// If we have a valid chunk, store some metadata and add it to the model.
		addChunkToModel(chunk, lines, raf.getFilePointer(), endPos-1, true);

		// The lines have been read-in in reverse order, so we have to flip them before 
		// returning.
		Collections.reverse(lines);
		return lines;
	}

	/**
	 * Adds the given chunk to the model.
	 * 
	 * @param chunk the chunk to add
	 * @param lines the lines included in the chunk
	 * @param startByte the start byte within the file this chunk represents
	 * @param endByte the end byte within the file this chunk represents
	 * @param addToFront if true, adds the chunk to the front of the chunk list
	 */
	private void addChunkToModel(Chunk chunk, List<String> lines, long startByte, long endByte,
			boolean addToFront) {

		if (!lines.isEmpty()) {
			chunk.start = startByte;
			chunk.end = endByte;
			chunk.linesInChunk = lines.size();

			if (addToFront) {
				model.add(0, chunk);
			}
			else {
				model.add(chunk);
			}
		}
	}
	
	/**
	 * Returns the start of the next line after the given byte. To do this, simply read 
	 * backwards from the given point until a newline or carriage return is found.
	 * 
	 * @param startByte
	 * @return
	 * @throws IOException 
	 */
	public synchronized long getStartOfNextLine(long startByte) throws IOException {
				
		// If the start byte is 0 (or less), just start from here - no need to track forward.
		if (startByte <= 0) {
			return 0;
		}
		
		final int BUFFER_SIZE = 8192;
				
		// Now create a byte array to hold the line we'll read.
		byte[] linePlus = new byte[BUFFER_SIZE];

		// Move the file pointer to our start location and read.
		raf.seek(startByte);
		raf.read(linePlus);
		
		// Move forward through the line until we hit a line feed. When we do, just return
		// the file position immediately past it.
		for (int i = 0; i < linePlus.length; i++) {
			byte c = linePlus[i];
			if (c == '\r' || c == '\n') {
				return startByte + i + 1;
			}
		}
		
		// If we haven't found a line feed, then we most likely (definitely) started reading 
		// somewhere in the last line of the file, so just return the original byte given.
		return startByte;
	}
}
