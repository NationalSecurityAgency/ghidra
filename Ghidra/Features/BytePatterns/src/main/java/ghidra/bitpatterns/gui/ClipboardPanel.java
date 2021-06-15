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
package ghidra.bitpatterns.gui;

import java.awt.FlowLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.*;
import java.math.BigInteger;
import java.util.*;

import javax.swing.*;

import org.xml.sax.*;

import docking.widgets.table.GFilterTable;
import generic.jar.ResourceFile;
import ghidra.app.analyzers.FunctionStartAnalyzer;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.bitpatterns.info.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.block.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.RefType;
import ghidra.util.Msg;
import ghidra.util.bytesearch.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.xml.*;

/**
 * This class represents the Clipboard Panel.  Patterns of interest are sent to the
 * Clipboard for evaluation/export/application.
 */
public class ClipboardPanel extends JPanel {
	private static final int BITS_PER_BYTE = 8;
	private JPanel buttonPanel;
	private PatternInfoTableModel patternInfoTable;
	private FunctionBitPatternsExplorerPlugin plugin;
	private GFilterTable<PatternInfoRowObject> filterTable;
	private Map<Integer, Integer> indexToSize;

	//need a map that supports null values
	//this map could be eliminated (and the code cleaned up a bit) if the inner class
	//ContextAction were factored out of FunctionStartAnalyzer
	//might not be worth it
	private HashMap<DittedBitSequence, ContextRegisterFilter> sequenceToCRegFilter;

	private boolean onlyPrePatterns;

	/**
	 * Class for building the pattern clipboard
	 * @param plugin
	 */
	public ClipboardPanel(FunctionBitPatternsExplorerPlugin plugin) {
		super();
		BoxLayout mainLayout = new BoxLayout(this, BoxLayout.Y_AXIS);
		setLayout(mainLayout);

		this.plugin = plugin;
		patternInfoTable = new PatternInfoTableModel(plugin);
		filterTable = new GFilterTable<>(patternInfoTable);
		buildButtonPanel();
		add(filterTable);
		add(buttonPanel);
		indexToSize = new HashMap<>();
		sequenceToCRegFilter = new HashMap<>();
	}

	private void buildButtonPanel() {
		buttonPanel = new JPanel(new FlowLayout());

		JButton deletedButton = new JButton("Remove Selected Patterns");
		deletedButton.addActionListener(e -> {
			List<PatternInfoRowObject> selected = filterTable.getSelectedRowObjects();
			plugin.removePatterns(selected);
			updateClipboard();
		});
		buttonPanel.add(deletedButton);

		JButton sendToAnalyzerButton = new JButton("Create Functions from Selection");
		sendToAnalyzerButton.addActionListener(new ActionListener() {

			@Override
			public void actionPerformed(ActionEvent e) {
				Program currentProgram = plugin.getCurrentProgram();
				if (currentProgram == null) {
					Msg.showWarn(this, getParent(), "Open Program", "Please open a program");
					return;
				}
				List<PatternInfoRowObject> selected = patternInfoTable.getLastSelectedObjects();
				ArrayList<Pattern> patternList = getPatternList(selected);
				if (patternList.isEmpty()) {
					return;
				}
				if (onlyPrePatterns) {
					Msg.showWarn(this, getParent(), "No Post Pattern",
						"Selected patterns must contain at least one post pattern");
					return;
				}
				//should we required at least one pre-pattern as well?
				FunctionStartAnalyzer funcStartAnalyzer = new FunctionStartAnalyzer();
				for (Pattern pattern : patternList) {
					MatchAction[] actions = getMatchActions(funcStartAnalyzer, pattern);
					pattern.setMatchActions(actions);
				}
				SequenceSearchState root = SequenceSearchState.buildStateMachine(patternList);
				funcStartAnalyzer.setExplicitState(root);
				AutoAnalysisManager autoManager =
					AutoAnalysisManager.getAnalysisManager(currentProgram);
				autoManager.scheduleOneTimeAnalysis(funcStartAnalyzer,
					currentProgram.getMemory().getExecuteSet());
			}
		});

		buttonPanel.add(sendToAnalyzerButton);

		JButton exportButton = new JButton("Export Selected to Pattern File");
		exportButton.addActionListener(new ExportPatternFileActionListener(this, getParent()));

		buttonPanel.add(exportButton);

		JButton importButton = new JButton("Import Patterns From File");
		importButton.addActionListener(new ImportPatternFileActionListener(plugin, this));
		buttonPanel.add(importButton);
	}

	protected static PatternPairSet parsePatternPairSet(ResourceFile xmlFile)
			throws FileNotFoundException, IOException, SAXException {
		PatternPairSet pairSet = null;
		ErrorHandler handler = new ErrorHandler() {
			@Override
			public void error(SAXParseException exception) throws SAXException {
				throw new SAXException("Error: " + exception);
			}

			@Override
			public void fatalError(SAXParseException exception) throws SAXException {
				throw new SAXException("Fatal error: " + exception);
			}

			@Override
			public void warning(SAXParseException exception) throws SAXException {
				throw new SAXException("Warning: " + exception);
			}
		};
		XmlPullParser parser;
		try (InputStream inputStream = xmlFile.getInputStream()) {
			parser =
				new NonThreadedXmlPullParserImpl(inputStream, xmlFile.getName(), handler, false);
		}
		parser.start("patternlist");
		XmlElement el = parser.peek();
		while (el.isStart()) {
			if (el.getName().equals("patternpairs")) {
				pairSet = new PatternPairSet();
				pairSet.restoreXml(parser, new ClipboardPatternFactory());
			}
			el = parser.peek();
		}
		parser.end();
		return pairSet;
	}

	private MatchAction[] getMatchActions(FunctionStartAnalyzer funcStartAnalyzer,
			Pattern pattern) {
		ContextRegisterFilter cRegFilter = sequenceToCRegFilter.get(pattern);
		if (cRegFilter == null) {
			//no context registers to worry about, so the only MatchAction needed is
			//a FunctionStartAction
			MatchAction[] actions = new MatchAction[1];
			actions[0] = funcStartAnalyzer.new FunctionStartAction();
			return actions;
		}
		//there are context registers to worry about, so we need a FunctionStartAction
		//and a FunctionStartAnalyzer.ContextAction for each context register
		Map<String, BigInteger> regsToValues = cRegFilter.getValueMap();
		MatchAction[] actions = new MatchAction[1 + regsToValues.size()];
		actions[0] = funcStartAnalyzer.new FunctionStartAction();
		int matchIndex = 1;
		for (String register : regsToValues.keySet()) {
			BigInteger value = regsToValues.get(register);
			actions[matchIndex] = funcStartAnalyzer.new ContextAction(register, value);
			matchIndex++;
		}
		return actions;
	}

	/**
	 * Evaluate a set of patterns
	 * @param rows patterns to evaluate
	 * @return statistics about the pattern matches
	 */
	public PatternEvaluationStats evaluatePatterns(List<PatternInfoRowObject> rows) {
		ArrayList<Pattern> patternList = getPatternList(rows);
		if (onlyPrePatterns) {
			Msg.showWarn(this, this, "Only Pre-Patterns",
				"Only Pre-Patterns in selection: no true/false positive information will be calculated.");
		}
		SequenceSearchState root = SequenceSearchState.buildStateMachine(patternList);
		indexToSize.clear();
		for (Pattern pattern : patternList) {
			indexToSize.put(pattern.getIndex(), pattern.getSize());
		}
		Program currentProgram = plugin.getCurrentProgram();
		MemoryBlock[] blocks = currentProgram.getMemory().getBlocks();
		PatternEvaluationStats matchStats = new PatternEvaluationStats();
		for (MemoryBlock block : blocks) {
			if (!block.isInitialized()) {
				continue;
			}
			//TODO: add toggle for searching non-executable blocks?
			if (!block.isExecute()) {
				continue;
			}
			searchBlock(root, block, matchStats, currentProgram, TaskMonitor.DUMMY);
		}
		return matchStats;
	}

	private void searchBlock(SequenceSearchState root, MemoryBlock block,
			PatternEvaluationStats matchStats, Program program, TaskMonitor monitor) {
		ArrayList<Match> mymatches = new ArrayList<>();

		try {
			root.apply(block.getData(), mymatches, monitor);
		}
		catch (IOException e) {
			e.printStackTrace();
		}
		if (monitor.isCancelled()) {
			return;
		}

		for (int i = 0; i < mymatches.size(); ++i) {
			Match match = mymatches.get(i);
			if (onlyPrePatterns) {
				evaluatePrePatternMatch(match, program, block, matchStats);
			}
			else {
				evaluateMatch(match, program, block, matchStats);
			}
		}
	}

//Only pre-patterns: don't compute the various kinds of false positives
//just show where all of the matches are and warn the user
	private void evaluatePrePatternMatch(Match match, Program program, MemoryBlock block,
			PatternEvaluationStats matchStats) {
		Address blockStart = block.getStart();
		Address matchStart = blockStart.add(match.getMatchStart());
		Address funcStart = matchStart.add(indexToSize.get(match.getSequenceIndex()));
		Address patternEnd = funcStart.add(-1);
		int totalBits = match.getSequence().getNumFixedBits();
		int postBits = 0;
		PatternEvalRowObject rowObject = new PatternEvalRowObject(PatternMatchType.PRE_PATTERN_HIT,
			new AddressSet(matchStart, patternEnd), match.getHexString(), funcStart, postBits,
			totalBits);
		matchStats.addRowObject(rowObject);
		return;

	}

//if something falls through to it: not a function start
//if there is just a jump to it: possibly a function start
	private void evaluateMatch(Match match, Program program, MemoryBlock block,
			PatternEvaluationStats matchStats) {
		Address blockStart = block.getStart();
		int alignment = program.getLanguage().getInstructionAlignment();
		Address matchStart = blockStart.add(match.getMatchStart());
		if (matchStart.getOffset() % alignment != 0) {
			return; //inconsistent with instruction alignment for language
		}
		long streamoffset = blockStart.getOffset();
		if (!match.checkPostRules(streamoffset)) {
			return;
		}
		Address matchEnd = matchStart.add(indexToSize.get(match.getSequenceIndex()) - 1);
		Address funcStart = blockStart.add(match.getMarkOffset());

		//see whether the pattern conflict with any existing context
		//perhaps this should be after?
		ContextRegisterFilter cRegFilter = sequenceToCRegFilter.get(match.getSequence());
		int totalBits = match.getSequence().getNumFixedBits();
		int postBits = match.getNumPostBits();
		int index = (totalBits - postBits) / BITS_PER_BYTE - 1;
		PatternMatchType type = getMatchType(program, funcStart, cRegFilter);
		PatternEvalRowObject rowObject =
			new PatternEvalRowObject(type, new AddressSet(matchStart, matchEnd),
				addSeparator(match.getHexString(), index), funcStart, postBits, totalBits);
		matchStats.addRowObject(rowObject);
	}

	private PatternMatchType getMatchType(Program program, Address funcStart,
			ContextRegisterFilter cRegFilter) {
		if (cRegFilter != null) {
			boolean passes = passesFilter(program, funcStart, cRegFilter);
			if (!passes) {
				return PatternMatchType.CONTEXT_CONFLICT;
			}
		}

		//pattern in defined data: false positive
		CodeUnit cu = program.getListing().getCodeUnitContaining(funcStart);
		if (cu instanceof Data) {
			if (((Data) cu).isDefined()) {
				return PatternMatchType.FP_DATA;
			}
		}

		//pattern at the start of a function: true positive
		if (program.getFunctionManager().getFunctionAt(funcStart) != null) {
			return PatternMatchType.TRUE_POSITIVE;
		}

		//does the match occur in undefined bytes?
		if (program.getListing().getInstructionContaining(funcStart) == null) {
			return PatternMatchType.POSSIBLE_START_UNDEFINED;
		}
		//the match occurs in an instruction.  is it aligned?
		Instruction instruction = program.getListing().getInstructionAt(funcStart);
		if (instruction == null) {
			return PatternMatchType.FP_MISALIGNED;
		}

		BasicBlockModel bModel = new BasicBlockModel(program);
		CodeBlock cBlock;

		boolean initialBlock = bModel.isBlockStart(instruction);
		//the instruction is at the start of a block.  Does anything flow into it?
		if (initialBlock) {
			try {
				cBlock = bModel.getCodeBlockAt(funcStart, TaskMonitor.DUMMY);
				CodeBlockReferenceIterator refIter = bModel.getSources(cBlock, TaskMonitor.DUMMY);
				if (refIter != null) {
					while (refIter.hasNext()) {
						CodeBlockReference cbRef = refIter.next();
						//TODO: is this sufficient? switch tables?
						if (!cbRef.getFlowType().equals(RefType.UNCONDITIONAL_JUMP)) {
							initialBlock = false;
						}
					}
				}
			}
			catch (CancelledException e) {
				//can't happen from the dummy monitor
			}
		}
		//it's a defined instruction: is it within a block, or a block start?
		if (initialBlock) {
			return PatternMatchType.POSSIBLE_START_CODE;
		}
		return PatternMatchType.FP_WRONG_FLOW;
	}

	private String addSeparator(String match, int index) {
		String[] parts = match.trim().split(" ");
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < parts.length; i++) {
			sb.append(parts[i]);
			sb.append(" ");
			if (i == index) {
				sb.append("*");
				sb.append(" ");
			}
		}
		return sb.toString();
	}

	private boolean passesFilter(Program program, Address funcStart,
			ContextRegisterFilter cRegFilter) {
		Map<String, BigInteger> valueMap = cRegFilter.getValueMap();
		for (String register : valueMap.keySet()) {
			BigInteger value = valueMap.get(register);
			if (value != null) {
				Register reg = program.getRegister(register);
				RegisterValue regValue =
					program.getProgramContext().getNonDefaultValue(reg, funcStart);
				if (regValue == null) {
					//don't report conflict if the register has a non-default value
					//TODO: is this correct?
					return true;
				}
				BigInteger existingValue = regValue.getUnsignedValue();
				if (!value.equals(existingValue)) {
					return false;
				}
			}
		}
		return true;
	}

	/**
	 * Updates the Pattern Clipboard
	 */
	public void updateClipboard() {
		remove(filterTable);
		filterTable.dispose();
		patternInfoTable = new PatternInfoTableModel(plugin);
		filterTable = new GFilterTable<>(patternInfoTable);
		add(filterTable, 0);
		updateUI();
	}

//if there are both PRE and POST patterns, combine them
	private ArrayList<Pattern> getPatternList(List<PatternInfoRowObject> rows) {
		ArrayList<Pattern> patternList = new ArrayList<>();
		List<PatternInfoRowObject> prePatterns = new ArrayList<>();
		List<PatternInfoRowObject> postPatterns = new ArrayList<>();
		sequenceToCRegFilter.clear();
		for (PatternInfoRowObject row : rows) {
			if (row.getPatternType().equals(PatternType.FIRST)) {
				postPatterns.add(row);
			}
			else {
				prePatterns.add(row);
			}
		}
		//only prepatterns
		if ((postPatterns.size() == 0)) {
			for (PatternInfoRowObject row : rows) {
				patternList.add(new Pattern(row.getDittedBitSequence(), 0, new PostRule[0],
					new MatchAction[0]));
			}
			onlyPrePatterns = true;
			return patternList;
		}
		onlyPrePatterns = false;
		//only postpatterns
		if (prePatterns.size() == 0) {
			for (PatternInfoRowObject row : rows) {
				patternList.add(new Pattern(row.getDittedBitSequence(), 0, getAlignRule(null, row),
					new MatchAction[0]));
				sequenceToCRegFilter.put(row.getDittedBitSequence(),
					row.getContextRegisterFilter());
			}
			return patternList;
		}

		//both prepatterns and postpatterns: combine them
		//any issues if the same pair results from two concatenations?
		//cf. PatternPairSet.createFinalPatterns
		for (PatternInfoRowObject prePattern : prePatterns) {
			for (PatternInfoRowObject postPattern : postPatterns) {
				DittedBitSequence pair = new DittedBitSequence(prePattern.getDittedBitSequence());
				pair = pair.concatenate(postPattern.getDittedBitSequence());
				PostRule[] postRules = getAlignRule(prePattern, postPattern);
				patternList.add(new Pattern(pair, prePattern.getDittedBitSequence().getSize(),
					postRules, new MatchAction[0]));
				sequenceToCRegFilter.put(pair, postPattern.getContextRegisterFilter());
			}
		}
		return patternList;
	}

	private PostRule[] getAlignRule(PatternInfoRowObject prePattern,
			PatternInfoRowObject postPattern) {
		int mark = 0;
		if (prePattern != null) {
			mark = prePattern.getDittedBitSequence().getSize();
		}
		Integer alignment = postPattern.getAlignment();
		if (alignment != null && alignment > 0) {
			//alignment must be a power of 2, subtract 1 to get the bitmask
			AlignRule alignRule = new AlignRule(mark, alignment - 1);
			return new PostRule[] { alignRule };
		}
		return new PostRule[0];
	}

	/**
	 * Returns the last selected rows of the pattern info table.
	 * @return last selected rows
	 */
	public List<PatternInfoRowObject> getLastSelectedObjects() {
		return patternInfoTable.getLastSelectedObjects();
	}

	public void dispose() {
		filterTable.dispose();
	}
}
