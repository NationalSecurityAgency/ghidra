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
import java.io.*;
import java.util.*;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.filefilter.FalseFileFilter;
import org.apache.commons.io.filefilter.FileFilterUtils;
import org.xml.sax.SAXException;

import generic.jar.ResourceFile;
import ghidra.app.analyzers.Patterns;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.xml.XMLErrorHandler;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.bytesearch.*;
import ghidra.util.constraint.ProgramDecisionTree;
import ghidra.util.task.TaskMonitor;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.NonThreadedXmlPullParserImpl;
import ghidra.xml.XmlPullParser;

/**
 * Run patterns over all memory blocks, accumulate stats for
 *    1) hits for each pattern
 *    2) false positives for each pattern
 *
 *  Produce an xml file output of stats for each pattern
 *
 */
public class PatternStats extends GhidraScript implements PatternFactory {

	private MatchActionMarker functionStart =
		new MatchActionMarker(MatchActionMarker.FUNCTION_START);
	private MatchActionMarker possibleFunctionStart =
		new MatchActionMarker(MatchActionMarker.POSSIBLE_FUNCTION_START);
	private MatchActionMarker codeBoundary = new MatchActionMarker(MatchActionMarker.CODE_BOUNDARY);
	private MatchActionMarker context = new MatchActionMarker(MatchActionMarker.CONTEXT);

	private SequenceSearchState root;
	private ArrayList<PatternAccumulate> accumList;
	private FunctionManager functionManager;
	private Listing listing;
	private boolean searchNonExecutableBlocks;
	private int maxFalsePositives;			// Maximum number of false positives to display address for

	public static class MatchActionMarker implements MatchAction {
		private int type;
		public static final int FUNCTION_START = 1;
		public static final int POSSIBLE_FUNCTION_START = 2;
		public static final int CODE_BOUNDARY = 3;
		public static final int CONTEXT = 4;

		public MatchActionMarker(int t) {
			type = t;
		}

		public int getType() {
			return type;
		}

		@Override
		public void apply(Program program, Address addr, Match match) {
		}

		@Override
		public void restoreXml(XmlPullParser parser) {
			parser.discardSubTree();
		}

	}

	public static class PatternAccumulate {
		private static final int MAX_EXAMPLE_PER = 1000;
		public DittedBitSequence pattern;
		public int totalHits;
		public int falsePosWithCode;		// False positive, in a function
		public int falsePosNoCode;			// False positive, not in a function
		public ArrayList<Long> exampleFalse = new ArrayList<>();

		public PatternAccumulate() {	// For use with restoreXml
		}

		public PatternAccumulate(DittedBitSequence pat) {	// Initialize accumulator
			pattern = pat;
			totalHits = 0;
			falsePosWithCode = 0;
			falsePosNoCode = 0;
		}

		public void addExample(Address addr) {
			if (exampleFalse.size() >= MAX_EXAMPLE_PER) {
				return;
			}
			exampleFalse.add(new Long(addr.getOffset()));
		}

		public void saveXml(StringBuffer buf) {
			buf.append("<accumulate>\n  ");
			buf.append("<data>");
			pattern.writeBits(buf);
			buf.append("</data>\n  ");
			buf.append("<total>").append(totalHits).append("</total>\n  ");
			buf.append("<falsecode>").append(falsePosWithCode).append("</falsecode>\n");
			buf.append("<falsenocode>").append(falsePosNoCode).append("</falsenocode>\n");
			for (int i = 0; i < exampleFalse.size(); ++i) {
				buf.append("<example>");
				buf.append(SpecXmlUtils.encodeUnsignedInteger(exampleFalse.get(i).longValue()));
				buf.append("</example>\n");
			}
			buf.append("</accumulate>\n");
		}

		public void restoreXml(XmlPullParser parser) {
			parser.start();
			parser.start("data");
			String text = parser.end().getText();
			pattern = new DittedBitSequence(text);
			parser.start("total");
			totalHits = Integer.decode(parser.end().getText());
			parser.start("falsecode");
			falsePosWithCode = Integer.decode(parser.end().getText());
			parser.start("falsenocode");
			falsePosNoCode = Integer.decode(parser.end().getText());
			while (parser.peek().isStart()) {
				parser.start("example");
				long value = SpecXmlUtils.decodeLong(parser.end().getText());
				exampleFalse.add(new Long(value));
			}
			parser.end();
		}

		public void displaySummary(StringBuffer buf) {
			String totalString = Integer.toString(totalHits);
			String falseWithString = Integer.toString(falsePosWithCode);
			String falseNoString = Integer.toString(falsePosNoCode);
			for (int i = totalString.length(); i < 10; ++i) {
				buf.append(' ');
			}
			buf.append(totalString);
			for (int i = falseWithString.length(); i < 10; ++i) {
				buf.append(' ');
			}
			buf.append(falseWithString);
			for (int i = falseNoString.length(); i < 10; ++i) {
				buf.append(' ');
			}
			buf.append(falseNoString);
			buf.append(" -- ").append(pattern.toString());
		}
	}

	private void accumulateOne(HashMap<DittedBitSequence, PatternAccumulate> hashMap,
			PatternAccumulate accum) {
		PatternAccumulate curAccum = hashMap.get(accum.pattern);
		if (curAccum == null) {
			hashMap.put(accum.pattern, accum);
		}
		else {
			curAccum.falsePosWithCode += accum.falsePosWithCode;
			curAccum.falsePosNoCode += accum.falsePosNoCode;
			curAccum.totalHits += accum.totalHits;
		}
	}

	private void accumulateFile(HashMap<DittedBitSequence, PatternAccumulate> hashMap,
			ResourceFile file) throws FileNotFoundException, IOException, SAXException {
		XMLErrorHandler handler = new XMLErrorHandler();
		InputStream inputStream = file.getInputStream();
		XmlPullParser parser =
			new NonThreadedXmlPullParserImpl(inputStream, file.getName(), handler, false);
		inputStream.close();
		parser.start("accumlist");
		while (parser.peek().isStart()) {
			PatternAccumulate accum = new PatternAccumulate();
			accum.restoreXml(parser);
			accumulateOne(hashMap, accum);
		}
		parser.end();
	}

	protected void runSummary(File dir) throws FileNotFoundException, IOException, SAXException {
		HashMap<DittedBitSequence, PatternAccumulate> hashMap =
			new HashMap<>();

		Iterator<File> iterator = FileUtils.iterateFiles(dir,
			FileFilterUtils.prefixFileFilter("pat_"), FalseFileFilter.INSTANCE);

		while (iterator.hasNext()) {
			File f = iterator.next();
			accumulateFile(hashMap, new ResourceFile(f));
		}

		println("     Total FalseWith   FalseNo  Pattern");
		for (PatternAccumulate accum : hashMap.values()) {
			StringBuffer buf = new StringBuffer();
			accum.displaySummary(buf);
			println(buf.toString());
		}
	}

	@Override
	protected void run() throws Exception {
		searchNonExecutableBlocks = true;
		maxFalsePositives = 20;
		File askDirectory = askDirectory("Result Directory", "Save");
		if (!askDirectory.isDirectory()) {
			println("Result directory does not exist: " + askDirectory.getAbsolutePath());
			return;
		}
		ResourceFile[] fileList = null;
		boolean localPattern = askYesNo("Local Pattern", "Use a local pattern file?");
		if (localPattern) {
			File patFile = askFile("Pattern File", "OK");
			fileList = new ResourceFile[1];
			fileList[0] = new ResourceFile(patFile);
		}
		if (!this.isRunningHeadless()) {
			if (askYesNo("DoSummary", "Would you like to summarize results?")) {
				runSummary(askDirectory);
				return;
			}
		}
		functionManager = currentProgram.getFunctionManager();
		listing = currentProgram.getListing();
		String fileName = "pat_" + currentProgram.getExecutableMD5();
		File resFile = new File(askDirectory, fileName);
		if (resFile.exists()) {
			println("Accumulation file already exists, skipping: " + resFile.getAbsolutePath());
			return;
		}
		ProgramDecisionTree patternDecisionTree = Patterns.getPatternDecisionTree();
		if (fileList == null) {
			fileList = Patterns.findPatternFiles(currentProgram, patternDecisionTree);
		}
		ArrayList<Pattern> patternlist = new ArrayList<>();
		for (ResourceFile element : fileList) {
			Pattern.readPatterns(element, patternlist, this);
		}
		if (patternlist.size() == 0) {
			return;
		}
		root = SequenceSearchState.buildStateMachine(patternlist);
		accumList = new ArrayList<>();
		for (int i = 0; i < patternlist.size(); ++i) {
			accumList.add(new PatternAccumulate(patternlist.get(i)));
		}
		MemoryBlock[] blocks = currentProgram.getMemory().getBlocks();
		for (MemoryBlock block2 : blocks) {
			MemoryBlock block = block2;
			if (!block.isInitialized()) {
				continue;
			}
			if (!searchNonExecutableBlocks && !block.isExecute()) {
				continue;
			}
			searchBlock(currentProgram, block, monitor);
		}
		FileWriter out = new FileWriter(resFile);
		out.write("<accumlist>\n");
		for (int i = 0; i < accumList.size(); ++i) {
			StringBuffer buf = new StringBuffer();
			accumList.get(i).saveXml(buf);
			out.write(buf.toString());
		}
		out.write("</accumlist>\n");
		out.close();
	}

	private boolean collectStats(PatternAccumulate accum, MatchActionMarker marker, Address addr) {
		boolean isFalse = false;
		accum.totalHits += 1;
		if (marker.getType() == MatchActionMarker.FUNCTION_START ||
			marker.getType() == MatchActionMarker.POSSIBLE_FUNCTION_START) {
			Function func = functionManager.getFunctionContaining(addr);
			if (func != null) {
				if (!func.getEntryPoint().equals(addr)) {	// In a function but not function start
					isFalse = true;
					accum.falsePosWithCode += 1;			// worse kind of false positive
				}
			}
			else {
				isFalse = true;
				accum.falsePosNoCode += 1;					// Either not an instruction, or not marked as function
			}
		}
		else if (marker.getType() == MatchActionMarker.CODE_BOUNDARY) {
			CodeUnit codeUnit = listing.getCodeUnitAt(addr);
			if (!(codeUnit instanceof Instruction)) {
				isFalse = true;
				accum.falsePosNoCode += 1;
			}
		}
		return isFalse;
	}

	private void displayFalse(PatternAccumulate accum, Address addr) {
		if (maxFalsePositives <= 0) {
			return;
		}
		maxFalsePositives -= 1;
		StringBuffer buf = new StringBuffer();
		buf.append("False Positive: ");
		accum.pattern.writeBits(buf);
		buf.append(" - ").append(currentProgram.getName());
		buf.append(" - ").append(addr.toString());
		println(buf.toString());
	}

	private void searchBlock(Program program, MemoryBlock block, TaskMonitor taskMonitor)
			throws IOException {
		taskMonitor.setMessage("Byte Search");
		taskMonitor.setMaximum((int) block.getSize());
		taskMonitor.setProgress(0);
		ArrayList<Match> mymatches = new ArrayList<>();
		long streamoffset = block.getStart().getOffset();
		root.apply(block.getData(), mymatches, taskMonitor);
		if (taskMonitor.isCancelled()) {
			return;
		}
		Address start = block.getStart();
		for (int i = 0; i < mymatches.size(); ++i) {
			Match match = mymatches.get(i);
			Address addr = start.add(match.getMarkOffset());
			if (!match.checkPostRules(streamoffset)) {
				continue;
			}
			PatternAccumulate accum = accumList.get(match.getSequenceIndex());
			MatchAction[] matchActions = match.getMatchActions();
			for (MatchAction matchAction : matchActions) {
				boolean isFalse = collectStats(accum, (MatchActionMarker) matchAction, addr);
				if (isFalse) {
					displayFalse(accum, addr);
					accum.addExample(addr);
				}
			}
		}
	}

	@Override
	public MatchAction getMatchActionByName(String nm) {
		if (nm.equals("funcstart")) {
			return functionStart;
		}
		else if (nm.equals("possiblefuncstart")) {
			return possibleFunctionStart;
		}
		else if (nm.equals("codeboundary")) {
			return codeBoundary;
		}
		else if (nm.equals("setcontext")) {
			return context;
		}
		return null;
	}

	@Override
	public PostRule getPostRuleByName(String nm) {
		if (nm.equals("align")) {
			return new AlignRule();
		}
		return null;
	}

}
