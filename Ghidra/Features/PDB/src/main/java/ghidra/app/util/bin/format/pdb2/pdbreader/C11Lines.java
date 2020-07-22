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

import java.util.ArrayList;
import java.util.List;

import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * C11Lines information.  As best as we know, only one of C11Lines or C13Lines (not implemented
 * yet) can be found after the symbol information in module debug streams.
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
	private List<StartEnd> startEnd;
	private List<Integer> seg; // array of unsigned shorts

	private List<Integer> ccSegs;
	// array of (Windows C) unsigned long values (which is 32-bit int); we are limiting to java int.
	// The value is used to move the PdbByteReader index, which takes an int.
	private List<List<Integer>> baseSrcLines;
	private List<List<StartEnd>> startEnds;
	private List<String> names;

	private List<List<Integer>> segmentNumbers; // unsigned short
	private List<List<List<Long>>> offsets; // unsigned int
	private List<List<List<Integer>>> lineNumbers; // unsigned short

	public C11Lines(AbstractPdb pdb) {
		this.pdb = pdb;
	}

	public void parse(PdbByteReader reader, TaskMonitor monitor)
			throws PdbException, CancelledException {
		if (reader.numRemaining() < 4) {
			return;
		}
		cFile = reader.parseUnsignedShortVal();
		cSeg = reader.parseUnsignedShortVal();
		baseSrcFile = new ArrayList<>();
		startEnd = new ArrayList<>();
		seg = new ArrayList<>();
		for (int i = 0; i < cFile; i++) {
			monitor.checkCanceled();
			int val = reader.parseInt();
			if (val < 0) {
				throw new PdbException("beyond our max integer limitation");
			}
			baseSrcFile.add(val);
		}
		for (int i = 0; i < cSeg; i++) {
			monitor.checkCanceled();
			StartEnd se = new StartEnd();
			se.parse(reader);
			startEnd.add(se);
		}
		for (int i = 0; i < cSeg; i++) {
			monitor.checkCanceled();
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
			monitor.checkCanceled();
			reader.setIndex(baseSrcFile.get(i));
			int ccSeg = reader.parseUnsignedShortVal();
			ccSegs.add(ccSeg);
			reader.skip(2); // padding
			List<Integer> baseSrcLn = new ArrayList<>();
			for (int j = 0; j < ccSeg; j++) {
				monitor.checkCanceled();
				baseSrcLn.add(reader.parseInt());
			}
			baseSrcLines.add(baseSrcLn);
			List<StartEnd> myStartEnd = new ArrayList<>();
			for (int j = 0; j < ccSeg; j++) {
				StartEnd se = new StartEnd();
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
				monitor.checkCanceled();
				reader.setIndex(baseSrcLn.get(j));
				int segNum = reader.parseUnsignedShortVal();
				segNums.add(segNum);
				int cPair = reader.parseUnsignedShortVal();
				List<Long> segOffsets = new ArrayList<>(); // unsigned ints
				for (int k = 0; k < cPair; k++) {
					monitor.checkCanceled();
					segOffsets.add(reader.parseUnsignedIntVal());
				}
				fileSegOffsets.add(segOffsets);
				List<Integer> segLineNums = new ArrayList<>(); // unsigned shorts
				for (int k = 0; k < cPair; k++) {
					monitor.checkCanceled();
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
		return dump();
	}

	/**
	 * Dumps this class.  This package-protected method is for debugging only.
	 * @return the {@link String} output.
	 */
	String dump() {
		StringBuilder builder = new StringBuilder();
		builder.append("Lines-------------------------------------------------------\n");
		builder.append("cFile: " + cFile + " cSeg: " + cSeg + "\n");
		for (int i = 0; i < cFile; i++) {
			builder.append("baseSrcFile[" + i + "]: " + baseSrcFile.get(i) + "\n");
		}
		for (int i = 0; i < cSeg; i++) {
			builder.append(i + ": start:" + startEnd.get(i).getStart() + " end: " +
				startEnd.get(i).getEnd() + " seg: " + seg.get(i) + "\n");
		}
		for (int i = 0; i < cFile; i++) {
			builder.append(
				"  file[" + i + "]: cSeg: " + ccSegs.get(i) + " name: " + names.get(i) + "\n");
			List<Integer> myBaseSrcLn = baseSrcLines.get(i);
			List<StartEnd> myStartEnds = startEnds.get(i);
			for (int j = 0; j < ccSegs.get(i); j++) {
				StartEnd se = myStartEnds.get(j);
				builder.append("  " + j + ": baseSrcLn: " + myBaseSrcLn.get(j) + " start: " +
					se.getStart() + " end: " + se.getEnd() + "\n");
			}
			List<Integer> segNums = segmentNumbers.get(i);
			List<List<Long>> fileSegOffsets = offsets.get(i);
			List<List<Integer>> fileSegLineNums = lineNumbers.get(i);
			for (int j = 0; j < fileSegOffsets.size(); j++) {
				List<Long> segOffsets = fileSegOffsets.get(j);
				List<Integer> segLineNums = fileSegLineNums.get(j);
				builder.append("  seg[" + j + "]: Seg: " + segNums.get(j) + " cPair: " +
					segOffsets.size() + "\n");
				for (int k = 0; k < segOffsets.size(); k++) {
					builder.append("  " + segLineNums.get(k) + ":" + segOffsets.get(k) + "\n");
				}
			}
		}
		builder.append("End Lines---------------------------------------------------\n");
		return builder.toString();
	}

	private class StartEnd {
		private long start; // unsigned long
		private long end; // unsigned long

		public void parse(PdbByteReader reader) throws PdbException {
			start = reader.parseUnsignedIntVal();
			end = reader.parseUnsignedIntVal();
		}

		public long getStart() {
			return start;
		}

		public long getEnd() {
			return end;
		}
	}

}
