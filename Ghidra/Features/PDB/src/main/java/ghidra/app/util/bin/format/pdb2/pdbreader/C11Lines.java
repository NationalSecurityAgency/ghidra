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
package ghidra.app.util.bin.format.pdb2.pdbreader;

import java.io.IOException;
import java.io.Writer;
import java.util.ArrayList;
import java.util.List;

import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * C11Lines information.  As best as we know, only one of C11Lines or C13Lines can be found after
 * the symbol information in module debug streams.
 * <P>
 * Note: we have not tested or put this to use yet.
 */
public class C11Lines {

	private AbstractPdb pdb;
	private int cFile; // unsigned short
	private int cSeg; // unsigned short
	// array of (Windows C) unsigned long values (which is 32-bit int); we are limiting to java int.
	// The value is used to move the PdbByteReader index, which takes an int.
	private List<Integer> baseSrcFile;
	private List<C11LinesStartEnd> startEnd;
	private List<Integer> seg; // array of unsigned shorts

	private List<Integer> ccSegs;
	// array of (Windows C) unsigned long values (which is 32-bit int); we are limiting to java int.
	// The value is used to move the PdbByteReader index, which takes an int.
	private List<List<Integer>> baseSrcLines;
	private List<List<C11LinesStartEnd>> startEnds;
	private List<String> names;

	private List<List<Integer>> segmentNumbers; // unsigned short
	private List<List<List<Long>>> offsets; // unsigned int
	private List<List<List<Integer>>> lineNumbers; // unsigned short

	public static C11Lines parse(AbstractPdb pdb, PdbByteReader reader)
			throws PdbException, CancelledException {
		return new C11Lines(pdb, reader);
	}

	//==============================================================================================
	// The below access methods might be temporary until it is decided if some work should
	//  be done within the class with methods to access the work.

	/**
	 * Returns the number of source files
	 * @return the number of source files
	 */
	public int getNumFiles() {
		return cFile;
	}

	/**
	 * Returns the number of segments.  This also is the number of start/end records.  This is
	 * a high-level list whereas there is a per-file list later.  Not sure if this current list
	 * is an encompassing list or something else
	 * @return the number of segments
	 */
	public int getNumSegments() {
		return cSeg;
	}

	/**
	 * Returns the list of segment numbers.  This is a high-level list whereas there is a
	 * per-file list later.  Not sure if this current list is an encompassing list or something
	 * else
	 * @return the segment numbers
	 */
	public List<Integer> getSegments() {
		return seg;
	}

	/**
	 * Returns the list of line start/end records.  This is a high-level list whereas there is
	 * a per-file list of start-end records at a lower level.  Not sure if this current list is
	 * an encompassing list or a list of something else
	 * @return the list of start/end records
	 */
	public List<C11LinesStartEnd> getStartEnd() {
		return startEnd;
	}

	/**
	 * Returns the list of base source file indices?  This is our best guess at this time
	 * @return the indices of the source files
	 */
	public List<Integer> getBaseSrcFiles() {
		return baseSrcFile;
	}

	/**
	 * Returns the list of the number of segments for each source file
	 * @return the list of the number of segments
	 */
	public List<Integer> getPerFileNumSegments() {
		return ccSegs;
	}

	/**
	 * Returns the per-file list of base source lines, where the base is for the particular
	 * segment
	 * @return the per-file list of base source lines
	 */
	public List<List<Integer>> getPerFileBaseSrcLines() {
		return baseSrcLines;
	}

	/**
	 * Returns the per-file list of line start/end records, where the start/ends are for the
	 * particular segment
	 * @return the per-file list of segment start/ends
	 */
	public List<List<C11LinesStartEnd>> getPerFileStartEndRecords() {
		return startEnds;
	}

	/**
	 * The list of file names
	 * @return the list of file names
	 */
	public List<String> getFileNames() {
		return names;
	}

	/**
	 * Returns the per-file list of segment numbers
	 * @return the per-file list of segment numbers
	 */
	public List<List<Integer>> getPerFileSegmentNumbers() {
		return segmentNumbers;
	}

	/**
	 * Returns the per-file list of per-segment list of offsets
	 * @return the offsets
	 */
	public List<List<List<Long>>> getPerFilePerSegmentOffsets() {
		return offsets;
	}

	/**
	 * Returns the per-file list of per-segment list of line numbers pertaining to the offsets
	 * @return the line numbers
	 */
	public List<List<List<Integer>>> getPerFilePerSegmentLineNumbers() {
		return lineNumbers;
	}
	// The above access methods... see note above.
	//==============================================================================================

	private C11Lines(AbstractPdb pdb, PdbByteReader reader)
			throws PdbException, CancelledException {
		this.pdb = pdb;
		if (reader.numRemaining() < 4) {
			return;
		}
		cFile = reader.parseUnsignedShortVal();
		cSeg = reader.parseUnsignedShortVal();
		baseSrcFile = new ArrayList<>();
		startEnd = new ArrayList<>();
		seg = new ArrayList<>();
		for (int i = 0; i < cFile; i++) {
			pdb.checkCancelled();
			int val = reader.parseInt();
			if (val < 0) {
				throw new PdbException("beyond our max integer limitation");
			}
			baseSrcFile.add(val);
		}
		for (int i = 0; i < cSeg; i++) {
			pdb.checkCancelled();
			C11LinesStartEnd se = new C11LinesStartEnd();
			se.parse(reader);
			startEnd.add(se);
		}
		for (int i = 0; i < cSeg; i++) {
			pdb.checkCancelled();
			seg.add(reader.parseUnsignedShortVal());
		}
		ccSegs = new ArrayList<>();
		baseSrcLines = new ArrayList<>();
		startEnds = new ArrayList<>();
		names = new ArrayList<>();
		segmentNumbers = new ArrayList<>();
		offsets = new ArrayList<>();
		lineNumbers = new ArrayList<>();
		for (int i = 0; i < cFile; i++) {
			pdb.checkCancelled();
			reader.setIndex(baseSrcFile.get(i));
			int ccSeg = reader.parseUnsignedShortVal();
			ccSegs.add(ccSeg);
			reader.skip(2); // padding
			List<Integer> baseSrcLn = new ArrayList<>();
			for (int j = 0; j < ccSeg; j++) {
				pdb.checkCancelled();
				baseSrcLn.add(reader.parseInt());
			}
			baseSrcLines.add(baseSrcLn);
			List<C11LinesStartEnd> myStartEnd = new ArrayList<>();
			for (int j = 0; j < ccSeg; j++) {
				C11LinesStartEnd se = new C11LinesStartEnd();
				se.parse(reader);
				myStartEnd.add(se);
			}
			startEnds.add(myStartEnd);
			String name = reader.parseString(pdb, StringParseType.StringNt);
			names.add(name);
			List<Integer> segNums = new ArrayList<>();
			List<List<Long>> fileSegOffsets = new ArrayList<>(); // unsigned int
			List<List<Integer>> fileSegLineNums = new ArrayList<>(); // unsigned short
			for (int j = 0; j < ccSeg; j++) {
				pdb.checkCancelled();
				reader.setIndex(baseSrcLn.get(j));
				int segNum = reader.parseUnsignedShortVal();
				segNums.add(segNum);
				int cPair = reader.parseUnsignedShortVal();
				List<Long> segOffsets = new ArrayList<>(); // unsigned ints
				for (int k = 0; k < cPair; k++) {
					pdb.checkCancelled();
					segOffsets.add(reader.parseUnsignedIntVal());
				}
				fileSegOffsets.add(segOffsets);
				List<Integer> segLineNums = new ArrayList<>(); // unsigned shorts
				for (int k = 0; k < cPair; k++) {
					pdb.checkCancelled();
					segLineNums.add(reader.parseUnsignedShortVal());
				}
				fileSegLineNums.add(segLineNums);
			}
			segmentNumbers.add(segNums);
			offsets.add(fileSegOffsets);
			lineNumbers.add(fileSegLineNums);
		}
	}

	@Override
	public String toString() {
		return String.format("%s: numFiles = %d, numSegs = %d", getClass().getSimpleName(), cFile,
			cSeg);
	}

	/**
	 * Dumps this class to Writer.  This package-protected method is for debugging only
	 * @param writer the writer
	 * @param monitor the task monitor
	 * @throws CancelledException upon user cancellation
	 * @throws IOException upon issue writing to writer
	 */
	void dump(Writer writer, TaskMonitor monitor) throws CancelledException, IOException {
		PdbReaderUtils.dumpHead(writer, this);
		writer.write("cFile: " + cFile + " cSeg: " + cSeg + "\n");
		for (int i = 0; i < cFile; i++) {
			pdb.checkCancelled();
			writer.write("baseSrcFile[" + i + "]: " + baseSrcFile.get(i) + "\n");
		}
		for (int i = 0; i < cSeg; i++) {
			pdb.checkCancelled();
			writer.write(i + ": start:" + startEnd.get(i).getStart() + " end: " +
				startEnd.get(i).getEnd() + " seg: " + seg.get(i) + "\n");
		}
		for (int i = 0; i < cFile; i++) {
			pdb.checkCancelled();
			writer.write(
				"  file[" + i + "]: cSeg: " + ccSegs.get(i) + " name: " + names.get(i) + "\n");
			List<Integer> myBaseSrcLn = baseSrcLines.get(i);
			List<C11LinesStartEnd> myStartEnds = startEnds.get(i);
			for (int j = 0; j < ccSegs.get(i); j++) {
				C11LinesStartEnd se = myStartEnds.get(j);
				writer.write("  " + j + ": baseSrcLn: " + myBaseSrcLn.get(j) + " start: " +
					se.getStart() + " end: " + se.getEnd() + "\n");
			}
			List<Integer> segNums = segmentNumbers.get(i);
			List<List<Long>> fileSegOffsets = offsets.get(i);
			List<List<Integer>> fileSegLineNums = lineNumbers.get(i);
			for (int j = 0; j < fileSegOffsets.size(); j++) {
				pdb.checkCancelled();
				List<Long> segOffsets = fileSegOffsets.get(j);
				List<Integer> segLineNums = fileSegLineNums.get(j);
				writer.write("  seg[" + j + "]: Seg: " + segNums.get(j) + " cPair: " +
					segOffsets.size() + "\n");
				for (int k = 0; k < segOffsets.size(); k++) {
					writer.write("  " + segLineNums.get(k) + ":" + segOffsets.get(k) + "\n");
				}
			}
		}
		PdbReaderUtils.dumpTail(writer, this);
	}

}
