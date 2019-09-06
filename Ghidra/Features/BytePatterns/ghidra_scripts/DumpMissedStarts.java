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
//@category CodeAnalysis

import java.io.*;
import java.util.ArrayList;

import generic.jar.ResourceFile;
import ghidra.app.analyzers.Patterns;
import ghidra.app.script.GhidraScript;
import ghidra.framework.Application;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.util.bytesearch.*;
import ghidra.util.constraint.ProgramDecisionTree;

public class DumpMissedStarts extends GhidraScript implements PatternFactory {
	private static int bufsize = 20;
	private DummyMatchAction dummyaction;
	private SequenceSearchState root;
	private Memory memory;
	private byte[] bytebuffer;
	ArrayList<Match> matchlist;

	private boolean functionMatchesPattern(byte[] buff, int numbytes) {
		matchlist.clear();
		root.sequenceMatch(buff, numbytes, matchlist);
		if (matchlist.size() > 0)
			return true;
		return false;
	}

	private boolean detectThunk(Function func, CodeUnit cu) {
		if (cu == null)
			return true;
		if (cu instanceof Data)
			return true;
		return false;
	}

	private void writeBytes(Writer w, byte[] buffer, int numbytes) throws IOException {
		StringBuffer buf = new StringBuffer();
		for (int i = 0; i < numbytes; ++i)
			buf.append(Integer.toHexString(buffer[i] & 0xff)).append(' ');
		buf.append('\n');
		w.write(buf.toString());
	}

	@Override
	protected void run() throws Exception {
		Listing listing = currentProgram.getListing();
		File file =
			Application.getModuleDataFile("BytePatterns", "funcstartsamples.txt").getFile(true);
		dummyaction = new DummyMatchAction();
		matchlist = new ArrayList<>();
		memory = currentProgram.getMemory();
		bytebuffer = new byte[bufsize];
		ProgramDecisionTree patternDecisionTree = Patterns.getPatternDecisionTree();
		ResourceFile[] fileList = Patterns.findPatternFiles(currentProgram, patternDecisionTree);
		ArrayList<Pattern> patternlist = new ArrayList<>();
		for (int i = 0; i < fileList.length; ++i)
			Pattern.readPostPatterns(fileList[i].getFile(true), patternlist, this);
		FileWriter fileWriter = new FileWriter(file);
		root = SequenceSearchState.buildStateMachine(patternlist);

		FunctionManager functionManager = currentProgram.getFunctionManager();
		FunctionIterator iter = functionManager.getFunctions(true);
		while (iter.hasNext()) {
			Function func = iter.next();
			CodeUnit cu = listing.getCodeUnitAt(func.getEntryPoint());
			if (detectThunk(func, cu))
				continue;
			int numbytes = memory.getBytes(func.getEntryPoint(), bytebuffer);
			if ((numbytes > 0) && (!functionMatchesPattern(bytebuffer, numbytes))) {
				writeBytes(fileWriter, bytebuffer, numbytes);
			}
		}
		fileWriter.close();
	}

	@Override
	public MatchAction getMatchActionByName(String nm) {
		return dummyaction;
	}

	@Override
	public PostRule getPostRuleByName(String nm) {
		if (nm.equals("align"))
			return new AlignRule();
		return null;
	}

}
