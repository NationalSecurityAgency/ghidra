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
//Queries all functions in the current selection (or all functions in the current program if
//the current selection is null) against all functions in a user-selected program.
//@category BSim

import java.util.*;

import org.apache.commons.collections4.IteratorUtils;

import generic.lsh.vector.*;
import ghidra.app.decompiler.DecompileException;
import ghidra.app.script.GhidraScript;
import ghidra.app.services.FunctionComparisonService;
import ghidra.app.tablechooser.*;
import ghidra.features.base.codecompare.model.MatchedFunctionComparisonModel;
import ghidra.features.bsim.query.*;
import ghidra.features.bsim.query.client.Configuration;
import ghidra.features.bsim.query.description.FunctionDescription;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.*;

//TODO: docs

public class LocalBSimQueryScript extends GhidraScript {

	//functions with self significance below this bound will be skipped
	private static final double SELF_SIGNIFICANCE_BOUND = 15.0;
	//bsim database template determining the signature settings
	private static final String TEMPLATE_NAME = "medium_nosize";
	//these are analogous to the bounds in a bsim query
	private static final double MATCH_SIMILARITY_LOWER_BOUND = 0.0;
	private static final double MATCH_CONFIDENCE_LOWER_BOUND = 0.0;
	private static final int MATCHES_PER_FUNCTION = 10;
	//decrease this if you only want to see matches that aren't exact
	//for instance, when looking for changes between two versions of a program
	private static final double MATCH_SIMILARITY_UPPER_BOUND = 1.0;

	private TableChooserDialog tableDialog;

	@Override
	protected void run() throws Exception {
		if (isRunningHeadless()) {
			popup("This script cannot be run headlessly.");
			return;
		}

		Set<Function> sourceFuncs = new HashSet<>();
		if (currentSelection == null) {
			IteratorUtils.forEach(currentProgram.getFunctionManager().getFunctions(true),
				x -> sourceFuncs.add(x));
		}
		else {
			IteratorUtils.forEach(
				currentProgram.getFunctionManager().getFunctionsOverlapping(currentSelection),
				x -> sourceFuncs.add(x));
		}

		if (sourceFuncs.isEmpty()) {
			this.popup("No non-stub functions to query!");
			return;
		}

		Program targetProgram = askProgram("Select Target Program");
		if (targetProgram == null) {
			return;
		}
		try {
			List<LocalBSimMatch> localMatches = null;

			//use special optimized method when the target program is the same as the current program
			//in that case, a given function might be in both the source and target sets
			//but we only want to generate signatures for it once 
			if (currentProgram.getUniqueProgramID() == targetProgram.getUniqueProgramID()) {
				localMatches = getMatchesCurrentProgram(sourceFuncs);
			}
			else {
				//in this case there is no overlap between the source and target functions
				localMatches = getMatchesTwoPrograms(sourceFuncs, currentProgram, targetProgram);
			}
			if (localMatches.isEmpty()) {
				popup("No matches meeting criteria.");
				return;
			}
			Collections.sort(localMatches);
			initializeTable(currentProgram, targetProgram);

			//again, use an optimized method for the special case when target program is the same
			//as the current program
			if (currentProgram.getUniqueProgramID() == targetProgram.getUniqueProgramID()) {
				addMatchesOneProgram(localMatches, sourceFuncs);
			}
			else {
				addMatchesTwoPrograms(localMatches);
			}
		}
		finally {
			targetProgram.release(this);
		}
	}

	/**
	 * Iterate through the list of sorted matches, adding the top MATCHES_PER_FUNCTION elements
	 * to the table for each source function.
	 * @param localMatches matches in decreasing order of confidence
	 */
	private void addMatchesTwoPrograms(List<LocalBSimMatch> localMatches) {
		Map<Function, Integer> matchCounts = new HashMap<>();
		for (LocalBSimMatch match : localMatches) {
			int count = matchCounts.getOrDefault(match.getSourceFunc(), 0);
			if (count >= MATCHES_PER_FUNCTION) {
				continue;
			}
			tableDialog.add(match);
			matchCounts.put(match.getSourceFunc(), count + 1);
		}
	}

	/**
	 * Iterate through the list of sorted matches, adding the top MATCHES_PER_FUNCTION elements
	 * to the table for each function ins {@code sourceFuncSet}.
	 * 
	 * By construction, the matches in this list have the "source" function before the "target"
	 * function (in address order).  This is an optimization to prevent essentially the same
	 * data from appearing in the list twice (since the BSim similarity and confidence operations
	 * are commutative).  So, for each match, we need to check whether the source or the 
	 * target are in {@code sourceFuncSet}.
	 * 
	 * @param localMatches matches in decreasing order of confidence
	 * @param sourceFuncSet source functions
	 */
	private void addMatchesOneProgram(List<LocalBSimMatch> localMatches,
			Set<Function> sourceFuncSet) {
		Map<Function, Integer> matchCounts = new HashMap<>();
		for (LocalBSimMatch match : localMatches) {
			Function leftFunc = match.getSourceFunc();
			int leftCount = matchCounts.getOrDefault(leftFunc, 0);
			if (sourceFuncSet.contains(leftFunc) && leftCount < MATCHES_PER_FUNCTION) {
				tableDialog.add(match);
				matchCounts.put(leftFunc, leftCount + 1);
			}
			Function rightFunc = match.getTargetFunc();
			int rightCount = matchCounts.getOrDefault(rightFunc, 0);
			if (sourceFuncSet.contains(rightFunc) && rightCount < MATCHES_PER_FUNCTION) {
				LocalBSimMatch switched = new LocalBSimMatch(rightFunc, leftFunc,
					match.getSimilarity(), match.getSignificance());
				tableDialog.add(switched);
				matchCounts.put(rightFunc, rightCount + 1);
			}
		}
	}

	private List<LocalBSimMatch> getMatchesCurrentProgram(Set<Function> funcs)
			throws LSHException, DecompileException {
		List<LocalBSimMatch> bsimMatches = new ArrayList<>();
		LSHVectorFactory vectorFactory = getVectorFactory();

		//generate the signatures for *all* functions in the program...
		FunctionManager fman = currentProgram.getFunctionManager();
		Iterator<Function> iter = fman.getFunctions(true);
		GenSignatures gensig =
			generateSignatures(currentProgram, iter, fman.getFunctionCount(), vectorFactory);

		//...but use sourceFuncAddrs to ensure that source functions are in the
		//funcs set 
		Set<Address> sourceFuncAddrs = new HashSet<>();
		for (Function func : funcs) {
			sourceFuncAddrs.add(func.getEntryPoint());
		}
		Iterator<FunctionDescription> sourceDescripts =
			gensig.getDescriptionManager().listAllFunctions();
		VectorCompare vecCompare = new VectorCompare();
		while (sourceDescripts.hasNext()) {
			FunctionDescription srcDesc = sourceDescripts.next();
			Address srcAddress = getAddress(currentProgram, srcDesc.getSpaceID(), srcDesc.getAddress());
			//skip if not in selection
			if (!sourceFuncAddrs.contains(srcAddress)) {
				continue;
			}
			//skip if self-significance too small
			LSHVector srcVector = srcDesc.getSignatureRecord().getLSHVector();
			if (vectorFactory.getSelfSignificance(srcVector) <= SELF_SIGNIFICANCE_BOUND) {
				continue;
			}
			Iterator<FunctionDescription> targetDescripts =
				gensig.getDescriptionManager().listAllFunctions();
			Function srcFunc = getFunction(currentProgram, srcDesc.getSpaceID(), srcDesc.getAddress());
			while (targetDescripts.hasNext()) {
				//skip if target is one of the source functions (i.e., in funcs)
				//AND src and target functions reside in the same Address Space
				//AND target before srcFunc in address order
				FunctionDescription targetDesc = targetDescripts.next();;
				Address targetAddress = getAddress(currentProgram, targetDesc.getSpaceID(), targetDesc.getAddress());

				if (sourceFuncAddrs.contains(targetAddress) &&
					targetDesc.getSpaceID() == srcDesc.getSpaceID() &&
					targetDesc.getAddress() <= srcDesc.getAddress()) {
					continue;
				}
				//skip if self-significance too small
				LSHVector targetVector = targetDesc.getSignatureRecord().getLSHVector();
				if (vectorFactory.getSelfSignificance(targetVector) <= SELF_SIGNIFICANCE_BOUND) {
					continue;
				}
				double sim = srcVector.compare(targetVector, vecCompare);
				double sig = vectorFactory.calculateSignificance(vecCompare);
				if (sig >= MATCH_CONFIDENCE_LOWER_BOUND && MATCH_SIMILARITY_LOWER_BOUND <= sim &&
					sim <= MATCH_SIMILARITY_UPPER_BOUND) {
					Function targetFunc = getFunction(currentProgram, targetDesc.getSpaceID(), targetDesc.getAddress());
					bsimMatches.add(new LocalBSimMatch(srcFunc, targetFunc, sim, sig));
				}
			}
		}
		return bsimMatches;
	}

	private List<LocalBSimMatch> getMatchesTwoPrograms(Set<Function> srcFuncs,
			Program sourceProgram, Program targetProgram) throws LSHException, DecompileException {
		List<LocalBSimMatch> bsimMatches = new ArrayList<>();
		LSHVectorFactory vectorFactory = getVectorFactory();
		GenSignatures srcSigs =
			generateSignatures(sourceProgram, srcFuncs.iterator(), srcFuncs.size(), vectorFactory);
		FunctionManager targetFuncMan = targetProgram.getFunctionManager();
		Iterator<Function> targetFuncIter = targetFuncMan.getFunctions(true);
		GenSignatures targetSigs = generateSignatures(targetProgram, targetFuncIter,
			targetFuncMan.getFunctionCount(), vectorFactory);
		Iterator<FunctionDescription> sourceDescripts =
			srcSigs.getDescriptionManager().listAllFunctions();
		VectorCompare vecCompare = new VectorCompare();
		while (sourceDescripts.hasNext()) {
			FunctionDescription srcDesc = sourceDescripts.next();
			//skip if self-significance too small
			LSHVector srcVector = srcDesc.getSignatureRecord().getLSHVector();
			if (vectorFactory.getSelfSignificance(srcVector) <= SELF_SIGNIFICANCE_BOUND) {
				continue;
			}
			Iterator<FunctionDescription> targetDescripts =
				targetSigs.getDescriptionManager().listAllFunctions();
			Function srcFunc = getFunction(sourceProgram, srcDesc.getSpaceID(), srcDesc.getAddress());
			while (targetDescripts.hasNext()) {
				FunctionDescription targetDesc = targetDescripts.next();
				//skip if self-significance too small
				LSHVector targetVector = targetDesc.getSignatureRecord().getLSHVector();
				if (vectorFactory.getSelfSignificance(targetVector) <= SELF_SIGNIFICANCE_BOUND) {
					continue;
				}
				double sim = srcVector.compare(targetVector, vecCompare);
				double sig = vectorFactory.calculateSignificance(vecCompare);
				if (sig >= MATCH_CONFIDENCE_LOWER_BOUND && MATCH_SIMILARITY_LOWER_BOUND <= sim &&
					sim <= MATCH_SIMILARITY_UPPER_BOUND) {
					Function targetFunc = getFunction(targetProgram, targetDesc.getSpaceID(), targetDesc.getAddress());
					bsimMatches.add(new LocalBSimMatch(srcFunc, targetFunc, sim, sig));
				}
			}
		}
		return bsimMatches;
	}

	private Address getAddress(Program program, int spaceid, long offset) {
		Address addr = program.getAddressFactory().getAddress(spaceid, offset);
		return addr;
	}

	private Function getFunction(Program program, int spaceid, long offset) {
		Address addr = getAddress(program, spaceid, offset);
		return program.getFunctionManager().getFunctionAt(addr);
	}

	private LSHVectorFactory getVectorFactory() throws LSHException {
		LSHVectorFactory vectorFactory = FunctionDatabase.generateLSHVectorFactory();
		Configuration config = FunctionDatabase.loadConfigurationTemplate(TEMPLATE_NAME);
		vectorFactory.set(config.weightfactory, config.idflookup, config.info.settings);
		return vectorFactory;
	}

	private GenSignatures generateSignatures(Program program, Iterator<Function> funcs, int count,
			LSHVectorFactory vectorFactory) throws LSHException, DecompileException {
		GenSignatures gensig = new GenSignatures(false);
		gensig.setVectorFactory(vectorFactory);
		gensig.openProgram(program, null, null, null, null, null);
		gensig.scanFunctions(funcs, count, monitor);
		return gensig;
	}

	class LocalBSimMatch implements Comparable<LocalBSimMatch>, AddressableRowObject {
		private Function sourceFunc;
		private Function targetFunc;
		private double similarity;
		private double significance;

		public LocalBSimMatch(Function sourceFunc, Function targetFunc, double sim, double signif) {
			this.sourceFunc = sourceFunc;
			this.targetFunc = targetFunc;
			this.similarity = sim;
			this.significance = signif;
		}

		public Function getSourceFunc() {
			return sourceFunc;
		}

		public Function getTargetFunc() {
			return targetFunc;
		}

		public double getSimilarity() {
			return similarity;
		}

		public double getSignificance() {
			return significance;
		}

		public Program getSourceProgram() {
			return sourceFunc.getProgram();
		}

		public Program getTargetProgram() {
			return targetFunc.getProgram();
		}

		@Override
		public int compareTo(LocalBSimQueryScript.LocalBSimMatch o) {
			return -Double.compare(significance, o.significance);
		}

		@Override
		public Address getAddress() {
			return sourceFunc.getEntryPoint();
		}
	}

	/****************************************************************************************
	 *              table stuff
	 ****************************************************************************************/

	class CompareMatchesExecutor implements TableChooserExecutor {

		private FunctionComparisonService compareService;
		private MatchedFunctionComparisonModel model;

		public CompareMatchesExecutor() {
			compareService = state.getTool().getService(FunctionComparisonService.class);
		}

		@Override
		public String getButtonName() {
			return "Compare Selected Matches";
		}

		@Override
		public boolean execute(AddressableRowObject rowObject) {
			LocalBSimMatch match = (LocalBSimMatch) rowObject;
			if (model == null) {
				model = new MatchedFunctionComparisonModel();
				compareService.createCustomComparison(model, null);
			}
			model.addMatch(match.getSourceFunc(), match.getTargetFunc());
			return false;
		}
	}

	private void initializeTable(Program sourceProgram, Program targetProgram) {
		StringBuilder titleBuilder = new StringBuilder("Local BSim Matches: ");
		titleBuilder.append(sourceProgram.getDomainFile().getPathname());
		titleBuilder.append(" -> ");
		titleBuilder.append(targetProgram.getDomainFile().getPathname());
		tableDialog =
			createTableChooserDialog(titleBuilder.toString(), new CompareMatchesExecutor());
		configureTableColumns(tableDialog);
		tableDialog.setMinimumSize(800, 400);
		tableDialog.show();
		tableDialog.setMessage(null);
	}

	private void configureTableColumns(TableChooserDialog dialog) {

		ColumnDisplay<Double> simColumn = new AbstractComparableColumnDisplay<Double>() {

			@Override
			public Double getColumnValue(AddressableRowObject rowObject) {
				return ((LocalBSimMatch) rowObject).getSimilarity();
			}

			@Override
			public String getColumnName() {
				return "Similarity";
			}
		};

		ColumnDisplay<Double> sigColumn = new AbstractComparableColumnDisplay<Double>() {

			@Override
			public Double getColumnValue(AddressableRowObject rowObject) {
				return ((LocalBSimMatch) rowObject).getSignificance();
			}

			@Override
			public String getColumnName() {
				return "Significance";
			}
		};

		StringColumnDisplay sourceFuncColumn = new StringColumnDisplay() {

			@Override
			public String getColumnValue(AddressableRowObject rowObject) {
				return ((LocalBSimMatch) rowObject).getSourceFunc().getName(true);
			}

			@Override
			public String getColumnName() {
				return "Source Function";
			}
		};

		StringColumnDisplay targetFuncColumn = new StringColumnDisplay() {

			@Override
			public String getColumnValue(AddressableRowObject rowObject) {
				return ((LocalBSimMatch) rowObject).getTargetFunc().getName(true);
			}

			@Override
			public String getColumnName() {
				return "Target Function";
			}
		};

		dialog.addCustomColumn(simColumn);
		dialog.addCustomColumn(sigColumn);
		dialog.addCustomColumn(sourceFuncColumn);
		dialog.addCustomColumn(targetFuncColumn);
	}

}
