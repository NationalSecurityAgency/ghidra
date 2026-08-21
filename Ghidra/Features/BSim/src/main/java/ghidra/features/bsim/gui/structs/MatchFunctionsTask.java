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
package ghidra.features.bsim.gui.structs;

import java.util.*;

import org.jgrapht.Graph;
import org.jgrapht.alg.interfaces.MatchingAlgorithm.Matching;
import org.jgrapht.alg.matching.MaximumWeightBipartiteMatching;
import org.jgrapht.graph.DefaultWeightedEdge;
import org.jgrapht.graph.SimpleWeightedGraph;

import db.Transaction;
import generic.lsh.vector.*;
import ghidra.app.decompiler.DecompileException;
import ghidra.app.services.ConsoleService;
import ghidra.features.bsim.gui.structs.StructureRecoveryPlugin.FunctionMatchOption;
import ghidra.features.bsim.query.*;
import ghidra.features.bsim.query.client.Configuration;
import ghidra.features.bsim.query.description.FunctionDescription;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

public class MatchFunctionsTask extends Task {

	//functions with self significance below this bound will be skipped
	private double SELF_SIGNIFICANCE_BOUND = 15.0;
	//bsim database template determining the signature settings
	private String TEMPLATE_NAME = "medium_nosize";
	//these are analogous to the bounds in a bsim query
	private double MATCH_SIMILARITY_LOWER_BOUND = 0.2;
	//decrease this if you only want to see matches that aren't exact
	//for instance, when looking for changes between two versions of a program
	private double MATCH_SIMILARITY_UPPER_BOUND = 1.0;
	private double MATCH_CONFIDENCE_LOWER_BOUND = 0.0;

	// We'll consider solo matches or matches above this confidence
	private double MIN_CONFIDENCE = 20.0;

	private StructureRecoveryPlugin plugin;
	private ConsoleService console;

	private Program currentProgram;
	private Program targetProgram;
	private BookmarkManager srcBookmarks;
	private BookmarkManager tgtBookmarks;

	private Set<Function> functionsToMatch = new HashSet<>();
	Map<Function, Set<Function>> functionMap = new HashMap<>();

	public final static String TAG = "Function Match";

	public MatchFunctionsTask(StructureRecoveryPlugin plugin, Program target) {
		super("Match Functions", true, false, false);
		this.plugin = plugin;
		this.targetProgram = target;
		this.functionsToMatch = plugin.getFunctionsToMatch();
		this.console = plugin.getConsole();
		this.currentProgram = plugin.getCurrentProgram();
		this.SELF_SIGNIFICANCE_BOUND = plugin.getSelfSiginificanceBound();
		this.MATCH_SIMILARITY_LOWER_BOUND = plugin.getMatchSimilarityLowerBound();
		this.MATCH_SIMILARITY_UPPER_BOUND = plugin.getMatchSimilarityUpperBound();
		this.MATCH_CONFIDENCE_LOWER_BOUND = plugin.getMatchConfidenceLowerBound();
		this.MIN_CONFIDENCE = plugin.getMinConfidence();
		this.srcBookmarks = currentProgram.getBookmarkManager();
		this.tgtBookmarks = targetProgram.getBookmarkManager();
	}

	@Override
	public void run(TaskMonitor monitor) {
		String taskName = getTaskTitle();
		try {
			Thread.currentThread().setName(taskName);
			console.addMessage(taskName, "Running...");
			matchFunctions(monitor);
			console.addMessage(taskName, "Finished!");
		}
		catch (CancelledException e) {
			console.addMessage(taskName, "Cancelled by user.");
		}
		catch (Exception e) {
			if (!monitor.isCancelled()) {
				Msg.showError(this, null, getTaskTitle(), "Error running task: " + taskName +
					"\n" + e.getClass().getName() + ": " + e.getMessage(), e);
				console.addErrorMessage("", "Error running task: " + taskName);
				console.addException(taskName, e);
			}
		}
	}

	private void matchFunctions(TaskMonitor monitor)
			throws CancelledException, LSHException, DecompileException {
		Iterator<Function> functionIter = targetProgram.getFunctionManager().getFunctions(true);
		GenSignatures targetSigs =
			generateSignatures(targetProgram, functionIter, getVectorFactory(), monitor);

		List<LocalBSimMatch> matchResults =
			getMatchesTwoPrograms(functionsToMatch, targetSigs, monitor);

		FunctionMatchOption matchType = plugin.getOptionSoloMatchesOnly();
		if (matchType != FunctionMatchOption.MAX_WEIGHT) {
			defineMapFromSoloMatches(matchResults, matchType, monitor);
		}
		else {
			defineMap(matchResults, monitor);
		}
	}

	private void defineMapFromSoloMatches(List<LocalBSimMatch> matchResults,
			FunctionMatchOption matchType, TaskMonitor monitor) {
		boolean addBookmarks = plugin.getOptionFnMatchBookmarks();
		try (Transaction _ = currentProgram.openTransaction("add");
				Transaction _ = targetProgram.openTransaction("add")) {
			Set<String> processed = new HashSet<>();
			for (LocalBSimMatch match : matchResults) {
				Function left = match.sourceFunc();
				Set<Function> set = functionMap.computeIfAbsent(left, _ -> new HashSet<>());
				Function right = match.targetFunc();
				if (right != null && !matchType.equals(FunctionMatchOption.MAX_WEIGHT)) {
					set.add(right);
					Double sig = match.significance();
					if (addBookmarks && sig >= MIN_CONFIDENCE) {
						addBookmarks(left, right, processed);
					}
				}
			}
			for (Function left : functionMap.keySet()) {
				Set<Function> set = functionMap.get(left);
				if (set.size() == 1) {
					Function right = set.iterator().next();
					if (addBookmarks) {
						addBookmarks(left, right, processed);
					}
				}
			}
		}

		plugin.setFunctionMap(functionMap);
	}

	private void defineMap(List<LocalBSimMatch> matchResults, TaskMonitor monitor)
			throws CancelledException {
		Set<String> setLeft = new HashSet<>();
		Set<String> setRight = new HashSet<>();
		Graph<String, DefaultWeightedEdge> graph =
			new SimpleWeightedGraph<>(DefaultWeightedEdge.class);

		monitor.setMessage("Computing local BSim results...");
		monitor.setMaximum(matchResults.size());
		for (LocalBSimMatch match : matchResults) {
			monitor.checkCancelled();
			Function left = match.sourceFunc();
			Function right = match.targetFunc();
			if (right != null) {
				Double sig = match.significance();
				String leftID = "L" + Long.toString(left.getID());
				String rightID = "R" + Long.toString(right.getID());
				setLeft.add(leftID);
				graph.addVertex(leftID);
				setRight.add(rightID);
				graph.addVertex(rightID);
				addWeightedEdge(graph, leftID, rightID, sig);
			}
		}

		MaximumWeightBipartiteMatching<String, DefaultWeightedEdge> alg =
			new MaximumWeightBipartiteMatching<>(graph, setLeft, setRight);

		boolean addBookmarks = plugin.getOptionFnMatchBookmarks();
		try (Transaction _ = currentProgram.openTransaction("add");
				Transaction _ = targetProgram.openTransaction("add")) {

			FunctionManager sourceManager = currentProgram.getFunctionManager();
			FunctionManager targetManager = targetProgram.getFunctionManager();
			monitor.setMessage("Computing match...");
			Matching<String, DefaultWeightedEdge> matching = alg.getMatching();

			Set<String> processedTags = new HashSet<>();
			monitor.setMessage("Computing map...");
			monitor.setMaximum(matching.getEdges().size());
			for (DefaultWeightedEdge edge : matching.getEdges()) {
				monitor.checkCancelled();
				String edgeSource = graph.getEdgeSource(edge).substring(1);
				Function left = sourceManager.getFunction(Long.parseLong(edgeSource));
				String edgeTarget = graph.getEdgeTarget(edge).substring(1);
				Function right = targetManager.getFunction(Long.parseLong(edgeTarget));
				Set<Function> set = functionMap.computeIfAbsent(left, _ -> new HashSet<>());
				set.add(right);
				if (addBookmarks) {
					addBookmarks(left, right, processedTags);
				}
			}
		}

		plugin.setFunctionMap(functionMap);
	}

	private static void addWeightedEdge(Graph<String, DefaultWeightedEdge> graph, String source,
			String target, double weight) {
		DefaultWeightedEdge edge = graph.addEdge(source, target);
		if (edge != null) {
			graph.setEdgeWeight(edge, weight);
		}
	}

	private void addBookmarks(Function left, Function right, Set<String> processed) {
		String key = left.getID() + "->" + right.getID();
		if (processed.add(key)) {
			srcBookmarks.setBookmark(left.getEntryPoint(), TAG,
				Long.toString(left.getID()), Long.toString(right.getID()));
			tgtBookmarks.setBookmark(right.getEntryPoint(), TAG,
				Long.toString(left.getID()), Long.toString(right.getID()));
		}
	}

	public record LocalBSimMatch(Function sourceFunc, Function targetFunc, double sim,
			double significance) {}

	private List<LocalBSimMatch> getMatchesTwoPrograms(Set<Function> srcFuncs,
			GenSignatures targetSigs, TaskMonitor monitor)
			throws LSHException, DecompileException, CancelledException {
		LSHVectorFactory vectorFactory = getVectorFactory();
		GenSignatures srcSigs =
			generateSignatures(currentProgram, srcFuncs.iterator(), vectorFactory, monitor);
		Iterator<FunctionDescription> sourceDescripts =
			srcSigs.getDescriptionManager().listAllFunctions();

		VectorCompare vecCompare = new VectorCompare();
		List<LocalBSimMatch> bsimMatches = new ArrayList<>();

		List<FunctionDescription> targetList = new ArrayList<>();
		Iterator<FunctionDescription> targetDescriptsIter =
			targetSigs.getDescriptionManager().listAllFunctions();
		while (targetDescriptsIter.hasNext()) {
			monitor.checkCancelled();
			targetList.add(targetDescriptsIter.next());
		}

		while (sourceDescripts.hasNext()) {
			monitor.checkCancelled();
			FunctionDescription srcDesc = sourceDescripts.next();

			//skip if self-significance too small
			LSHVector srcVector = srcDesc.getSignatureRecord().getLSHVector();
			if (vectorFactory.getSelfSignificance(srcVector) <= SELF_SIGNIFICANCE_BOUND) {
				continue;
			}

			Function srcFunc = getFunction(currentProgram, srcDesc.getAddress());
			for (FunctionDescription targetDesc : targetList) {
				//skip if self-significance too small
				LSHVector targetVector = targetDesc.getSignatureRecord().getLSHVector();
				if (vectorFactory.getSelfSignificance(targetVector) <= SELF_SIGNIFICANCE_BOUND) {
					continue;
				}
				double sim = srcVector.compare(targetVector, vecCompare);
				double sig = vectorFactory.calculateSignificance(vecCompare);
				if (sig >= MATCH_CONFIDENCE_LOWER_BOUND && MATCH_SIMILARITY_LOWER_BOUND <= sim &&
					sim <= MATCH_SIMILARITY_UPPER_BOUND) {
					Function targetFunc = getFunction(targetProgram, targetDesc.getAddress());
					if (targetFunc != null) {
						bsimMatches.add(new LocalBSimMatch(srcFunc, targetFunc, sim, sig));
					}
					else {
						Msg.warn(this, "Function not found for " + targetDesc.getAddress());
					}
				}
				monitor.checkCancelled();
			}
		}
		return bsimMatches;
	}

	private Function getFunction(Program program, long offset) {
		Address addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
		return program.getFunctionManager().getFunctionAt(addr);
	}

	private LSHVectorFactory getVectorFactory() throws LSHException {
		LSHVectorFactory vectorFactory = FunctionDatabase.generateLSHVectorFactory();
		Configuration config = FunctionDatabase.loadConfigurationTemplate(TEMPLATE_NAME);
		vectorFactory.set(config.weightfactory, config.idflookup, config.info.settings);
		return vectorFactory;
	}

	private GenSignatures generateSignatures(Program program, Iterator<Function> funcs,
			LSHVectorFactory vectorFactory, TaskMonitor monitor)
			throws LSHException, DecompileException {
		GenSignatures gensig = null;
		try {
			int count = program.getFunctionManager().getFunctionCount();
			gensig = new GenSignatures(false);
			gensig.setVectorFactory(vectorFactory);
			gensig.openProgram(program, null, null, null, null, null);
			gensig.scanFunctions(funcs, count, monitor);
			return gensig;
		}
		finally {
			gensig.dispose();
		}
	}

}
