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
package ghidra.feature.vt.gui.actions;

import java.util.*;

import javax.swing.SwingConstants;

import ghidra.feature.vt.api.correlator.program.*;
import ghidra.feature.vt.api.main.*;
import ghidra.feature.vt.api.util.VTAssociationStatusException;
import ghidra.feature.vt.api.util.VTOptions;
import ghidra.feature.vt.gui.plugin.AddressCorrelatorManager;
import ghidra.feature.vt.gui.task.ApplyMarkupItemTask;
import ghidra.feature.vt.gui.util.*;
import ghidra.framework.options.ToolOptions;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.listing.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.*;

/**
 *  If their options are set, this command runs all of the 
 *  <b>exact</b> {@link VTProgramCorrelator}s that return unique matches (i.e., only one of each 
 *  match is found in each program) for each correlator selected in the autoVT options to run:
 *  <ol>
 *  <li> Exact Symbol Name correlator </li>
 *  <li> Exact Data correlator </li>
 *  <li> Exact Function Byte correlator </li>
 *  <li> Exact Function Instruction correlator </li>
 *  <li> Exact Function Mnemonic correlator </li>
 *  </ol>
 *
 *  <P> After running each of the above correlators all matches are accepted since they are 
 *  exact/unique matches and all markup from the source program functions is applied to the matching 
 *  destination program functions.
 *
 * 	<P> Next, if the autoVT option for this correlator is selected, the command runs the 
 *  Duplicate Function Instruction correlator to find any non-unique
 *  functions with exact instruction bytes. It then compares their operands to try and determine 
 *  unique matches within matching sets and if found will accept correct matches and apply markup.
 *
 *  <P> If chosen, the command then gets a little more speculative by running the Data Reference
 *  Correlator, the Function Reference Correlator, and/or the Combined Function and Data Reference 
 *  Correlator, which use accepted match information from the previous correlators to find more
 *  matches. Only the matches with minimum score/confidence values, as chosen in the autoVT options, 
 *  will be accepted.
 *
 *  <P> If the user chooses to create implied matches then whenever matches are accepted, matches 
 *  that can be implied by those matches as new matches will be created. If the user chooses to 
 *  accept applied matches, then they will be applied if the chosen minimum vote count is met and if
 *  the chosen maximum conflict count is not exceeded.
 *  
 *  All options can be set in the Version Tracking Match Window's Edit -> Tool Options in 
 *  Version Tracking/Auto Version Tracking option folder. 
 *
 */
public class AutoVersionTrackingTask extends Task {

	private static final String NAME = "Auto Version Tracking Command";
	private VTSession session;
	private MatchInfoFactory matchInfoFactory;
	private AddressCorrelatorManager addressCorrelator;
	private Program sourceProgram;
	private Program destinationProgram;
	private AddressSetView sourceAddressSet;
	private AddressSetView destinationAddressSet;
	private ToolOptions toolOptions;
	private String statusMsg = null;
	private static int NUM_CORRELATORS = 8;

	/**
	 * Constructor for a modal/blocking AutoVersionTrackingTask
	 *
	
	 * @param session The Version Tracking session containing the source, destination, correlator
	 * and match information needed for this command.
	 * @param toolOptions the options used when applying matches
	 * @param minCombinedReferenceCorrelatorScore The minimum score used to limit matches created by
	 * the Combined Reference Correlator.
	 * @param minCombinedReferenceCorrelatorConfidence The minimum confidence used to limit matches
	 * created by the Combined Reference Correlator.
	 */
	public AutoVersionTrackingTask(VTSession session, ToolOptions toolOptions) {
		super(NAME, true, true, true);
		this.session = session;
		this.matchInfoFactory = new MatchInfoFactory();
		this.addressCorrelator = new AddressCorrelatorManager(() -> session);
		this.sourceProgram = session.getSourceProgram();
		this.destinationProgram = session.getDestinationProgram();
		this.toolOptions = toolOptions;
	}

	@Override
	public int getStatusTextAlignment() {
		return SwingConstants.LEADING;
	}

	@Override
	public void run(TaskMonitor monitor) throws CancelledException {

		boolean error = true;
		int id = session.startTransaction(NAME);
		try {
			session.setEventsEnabled(false);
			doRun(monitor);
			error = false;
		}
		catch (CancelledException e) {
			error = false; // allow work performed so far to be saved
		}
		finally {
			session.setEventsEnabled(true);
			session.endTransaction(id, !error);
		}
	}

	private void doRun(TaskMonitor realMonitor) throws CancelledException {

		SubTaskMonitor monitor = new SubTaskMonitor(realMonitor);

		boolean hasApplyErrors = false;
		sourceAddressSet = sourceProgram.getMemory().getLoadedAndInitializedAddressSet();
		destinationAddressSet = destinationProgram.getMemory().getLoadedAndInitializedAddressSet();

		int count = 0;
		monitor.doInitialize(NUM_CORRELATORS);

		// save user's Version Tracking (not AutoVT) Create implied match option 

		boolean originalImpliedMatchOption =
			toolOptions.getBoolean(VTOptionDefines.AUTO_CREATE_IMPLIED_MATCH, false);

		// Turn off auto implied matches and handle later if user had that Auto VT option set
		// This is because when run from the VT GUI action implied matches are created automatically
		// by the VT controller when the option is set but they are not created when called from a 
		// script since there is no VT controller in that case. If allowed to happen in 
		// GUI then they will happen twice when called later in this task and the implied match 
		// votes will be wrong. This Task doesn't know if called from GUI or script so this is 
		// klunky but will make sure they are only processed once and will make sure the user option
		// is put back the way the user had it. 
		toolOptions.setBoolean(VTOptionDefines.AUTO_CREATE_IMPLIED_MATCH, false);

		// Start with each correlator's default options and overwrite with appropriate 
		// corresponding AutoVT options
		VTOptions vtOptions;

		String prefix = "%s correlation (%d of " + NUM_CORRELATORS + ") - ";

		// Run the correlators in the following order:
		// Do this one first because we don't want it to find ones that get markup applied by later
		// correlators
		boolean runExactSymbolCorrelator =
			toolOptions.getBoolean(VTOptionDefines.RUN_EXACT_SYMBOL_OPTION, true);
		if (runExactSymbolCorrelator) {
			VTProgramCorrelatorFactory factory = new SymbolNameProgramCorrelatorFactory();

			vtOptions = factory.createDefaultOptions();
			int symbolMin = toolOptions.getInt(VTOptionDefines.SYMBOL_CORRELATOR_MIN_LEN_OPTION, 3);
			vtOptions.setInt(SymbolNameProgramCorrelatorFactory.MIN_SYMBOL_NAME_LENGTH, symbolMin);

			monitor.setPrefix(String.format(prefix, "Symbol Name", ++count));
			hasApplyErrors = correlateAndPossiblyApply(factory, vtOptions, monitor);
			monitor.doIncrementProgress();
		}
		boolean runExactDataCorrelator =
			toolOptions.getBoolean(VTOptionDefines.RUN_EXACT_DATA_OPTION, true);
		if (runExactDataCorrelator) {
			VTProgramCorrelatorFactory factory = new ExactDataMatchProgramCorrelatorFactory();

			vtOptions = factory.createDefaultOptions();
			int dataMin = toolOptions.getInt(VTOptionDefines.DATA_CORRELATOR_MIN_LEN_OPTION, 5);
			vtOptions.setInt(ExactDataMatchProgramCorrelatorFactory.DATA_MINIMUM_SIZE, dataMin);

			monitor.setPrefix(String.format(prefix, "Exact Data", ++count));
			hasApplyErrors |= correlateAndPossiblyApply(factory, vtOptions, monitor);
			monitor.doIncrementProgress();
		}

		int minFunctionLen =
			toolOptions.getInt(VTOptionDefines.FUNCTION_CORRELATOR_MIN_LEN_OPTION, 10);

		boolean runExactFunctionBytesCorrelator =
			toolOptions.getBoolean(VTOptionDefines.RUN_EXACT_FUNCTION_BYTES_OPTION, true);
		if (runExactFunctionBytesCorrelator) {
			VTProgramCorrelatorFactory factory = new ExactMatchBytesProgramCorrelatorFactory();
			vtOptions = factory.createDefaultOptions();

			vtOptions.setInt(ExactMatchBytesProgramCorrelatorFactory.FUNCTION_MINIMUM_SIZE,
				minFunctionLen);

			monitor.setPrefix(String.format(prefix, "Exact Bytes", ++count));
			hasApplyErrors |= correlateAndPossiblyApply(factory, vtOptions, monitor);
			monitor.doIncrementProgress();
		}

		boolean runExactFunctionInstCorrelator =
			toolOptions.getBoolean(VTOptionDefines.RUN_EXACT_FUNCTION_INST_OPTION, true);
		if (runExactFunctionInstCorrelator) {
			VTProgramCorrelatorFactory factory =
				new ExactMatchInstructionsProgramCorrelatorFactory();
			vtOptions = factory.createDefaultOptions();

			vtOptions.setInt(ExactMatchInstructionsProgramCorrelatorFactory.FUNCTION_MINIMUM_SIZE,
				minFunctionLen);

			monitor.setPrefix(String.format(prefix, "Exact Instructions", ++count));
			hasApplyErrors |= correlateAndPossiblyApply(factory, vtOptions, monitor);
			monitor.doIncrementProgress();

			factory = new ExactMatchMnemonicsProgramCorrelatorFactory();
			vtOptions = factory.createDefaultOptions();

			vtOptions.setInt(ExactMatchMnemonicsProgramCorrelatorFactory.FUNCTION_MINIMUM_SIZE,
				minFunctionLen);
			monitor.setPrefix(String.format(prefix, "Exact Mnemonic", ++count));
			hasApplyErrors |= correlateAndPossiblyApply(factory, vtOptions, monitor);
			monitor.doIncrementProgress();
		}


		// This is the first of the "speculative" post-correlator match algorithm. The correlator
		// returns all duplicate function instruction matches so there will always be more
		// than one possible match for each function. The compare mechanism used by the
		// function compare window determines matches based on matching operand values.
		// Given that each function must contains the same instructions to even become a match,
		// and the compare function mechanism has been very well tested, the mechanism for
		// finding the correct match is very accurate.
		boolean runDupeFunctionCorrelator =
			toolOptions.getBoolean(VTOptionDefines.RUN_DUPE_FUNCTION_OPTION, true);

		if (runDupeFunctionCorrelator) {

			VTProgramCorrelatorFactory factory =
				new DuplicateFunctionMatchProgramCorrelatorFactory();
			vtOptions = factory.createDefaultOptions();

			// if Auto VT min function length for dupe matches is different than current
			// exact instruction match setting temporarily change it for auto VT run
			int dupFunctionMinLen =
				toolOptions.getInt(VTOptionDefines.DUPE_FUNCTION_CORRELATOR_MIN_LEN_OPTION, 10);

			vtOptions.setInt(
				ExactMatchInstructionsProgramCorrelatorFactory.FUNCTION_MINIMUM_SIZE,
				dupFunctionMinLen);

			monitor.setPrefix(String.format(prefix, "Duplicate Function", ++count));
			hasApplyErrors |=
				correlateAndPossiblyApplyDuplicateFunctions(factory, vtOptions, monitor);
			monitor.doIncrementProgress();

		}

		// The rest are mores speculative matching algorithms because they depend on our
		// choosing the correct score/confidence pair to determine very probable matches. These
		// values were chosen based on what has been seen so far but this needs to be tested
		// further on more programs and possibly add options for users to give their own thresholds.

		// Get the names of the confidence and similarity score thresholds that
		// are used by all of the "reference" correlators
		boolean runRefCorrelators =
			toolOptions.getBoolean(VTOptionDefines.RUN_REF_CORRELATORS_OPTION, true);
		if (runRefCorrelators) {

			double minScore = toolOptions.getDouble(VTOptionDefines.REF_CORRELATOR_MIN_SCORE_OPTION, 0.95);
			double minConf = toolOptions.getDouble(VTOptionDefines.REF_CORRELATOR_MIN_CONF_OPTION, 10.0);


			// Get the number of data and function matches
			int numDataMatches = getNumberOfDataMatches(monitor);
			int numFunctionMatches = getNumberOfFunctionMatches(monitor);

			// Run the DataReferenceCorrelator if there are accepted data matches but no accepted
			// function matches
			if (numDataMatches > 0 && numFunctionMatches == 0) {
				VTProgramCorrelatorFactory factory = new DataReferenceProgramCorrelatorFactory();
				vtOptions = factory.createDefaultOptions();

				vtOptions.setDouble(
					VTAbstractReferenceProgramCorrelatorFactory.CONFIDENCE_THRESHOLD, minConf);
				vtOptions.setDouble(
					VTAbstractReferenceProgramCorrelatorFactory.SIMILARITY_THRESHOLD, minScore);

				monitor.setPrefix(String.format(prefix, "Data Reference", ++count));
				hasApplyErrors =
					hasApplyErrors | correlateAndPossiblyApply(factory, vtOptions, monitor);
				monitor.doIncrementProgress();

				// Get the number of data and function matches again if this correlator ran
				numDataMatches = getNumberOfDataMatches(monitor);
				numFunctionMatches = getNumberOfFunctionMatches(monitor);
			}

			// Run the FunctionReferenceCorrelator if there are accepted function matches but no
			// accepted data matches
			if (numDataMatches > 0 && numFunctionMatches == 0) {
				VTProgramCorrelatorFactory factory =
					new FunctionReferenceProgramCorrelatorFactory();
				vtOptions = factory.createDefaultOptions();
				vtOptions.setDouble(
					VTAbstractReferenceProgramCorrelatorFactory.CONFIDENCE_THRESHOLD, minConf);
				vtOptions.setDouble(
					VTAbstractReferenceProgramCorrelatorFactory.SIMILARITY_THRESHOLD, minScore);
				factory = new FunctionReferenceProgramCorrelatorFactory();

				monitor.setPrefix(String.format(prefix, "Function Reference", ++count));
				hasApplyErrors =
					hasApplyErrors | correlateAndPossiblyApply(factory, vtOptions, monitor);
				monitor.doIncrementProgress();

				// Get the number of data and function matches again if this correlator ran
				numDataMatches = getNumberOfDataMatches(monitor);
				numFunctionMatches = getNumberOfFunctionMatches(monitor);
			}

			// Run the CombinedDataAndFunctionReferenceCorrelator if there are both accepted function
			// matches but and data matches
			if (numDataMatches > 0 && numFunctionMatches > 0) {
				VTProgramCorrelatorFactory factory =
					new CombinedFunctionAndDataReferenceProgramCorrelatorFactory();
				vtOptions = factory.createDefaultOptions();
				vtOptions.setDouble(
					VTAbstractReferenceProgramCorrelatorFactory.CONFIDENCE_THRESHOLD, minConf);
				vtOptions.setDouble(
					VTAbstractReferenceProgramCorrelatorFactory.SIMILARITY_THRESHOLD, minScore);

				monitor.setPrefix(String.format(prefix, "Function and Data", ++count));
				hasApplyErrors =
					hasApplyErrors | correlateAndPossiblyApply(factory, vtOptions, monitor);
				monitor.doIncrementProgress();
			}
		}

		// Use the AutoVT create implied match option to decide whether to create implied matches
		// when running AutoVT
		boolean autoCreateImpliedMatches =
			toolOptions.getBoolean(VTOptionDefines.CREATE_IMPLIED_MATCHES_OPTION, false);

		// if implied matches are to be created, determine whether user wants them auto-applied
		// and determine the min votes and max conflicts option limits to use
		if (autoCreateImpliedMatches) {
			boolean applyImpliedMatches =
				toolOptions.getBoolean(VTOptionDefines.APPLY_IMPLIED_MATCHES_OPTION, true);
			int minVotes = toolOptions.getInt(VTOptionDefines.MIN_VOTES_OPTION, 2);
			int maxConflicts = toolOptions.getInt(VTOptionDefines.MAX_CONFLICTS_OPTION, 2);
			hasApplyErrors = hasApplyErrors |
				createImpliedMatches(applyImpliedMatches, minVotes, maxConflicts, monitor);
		}

		String applyMarkupStatus = " with no apply markup errors.";
		if (hasApplyErrors) {
			applyMarkupStatus =
				" with some apply markup errors. See the log or the markup table for more details";
		}
		statusMsg = NAME + " completed successfully" + applyMarkupStatus;

		// reset the Version Tracking auto implied match option to user choice
		toolOptions.setBoolean(VTOptionDefines.AUTO_CREATE_IMPLIED_MATCH,
			originalImpliedMatchOption);

	}

	/**
	 * Method to create implied matches for the existing applied matches in the current session
	 * @param applyGoodMatches if true, create applied matches for "good" implied matches based on
	 * votes/conflict information. For all the applied implied matches, rerun the creation of 
	 * applied matches until no new ones found.
	 * @param applyGoodMatches if true, apply matches if minVotes met and maxConflicts not exceeded 
	 * for particular match, if false, don't apply any matches
	 * @param minVotes minimum votes needed to apply a match
	 * @param maxConflicts maximum conflicts allowed to apply a match
	 * @param monitor the task monitor
	 * @return true if there are any apply errors, false otherwise
	 * @throws CancelledException if cancelled
	 */
	private boolean createImpliedMatches(boolean applyGoodMatches, int minVotes, int maxConflicts,
			TaskMonitor monitor)
			throws CancelledException {

		Set<VTAssociation> processedSrcDestPairs = new HashSet<>();
		List<VTMatchSet> matchSets = session.getMatchSets();

		monitor.setMessage("Creating Implied Matches...");
		monitor.initialize(matchSets.size());

		// create implied matches for the existing matchSets (ie sets of results from various 
		// correlators
		for (VTMatchSet matchSet : matchSets) {
			monitor.checkCancelled();

			Collection<VTMatch> matches = matchSet.getMatches();
			createImpliedMatches(monitor, processedSrcDestPairs, matches);
			monitor.incrementProgress();
		}

		// if user chose not to apply good implied matches then don't continue
		if (!applyGoodMatches) {
			return false;
		}

		// otherwise, try to find and apply good implied matches until no more to be found
		boolean hasApplyErrors = false;

		VTMatchSet impliedMatchSet = session.getImpliedMatchSet();

		Set<VTMatch> goodImpliedMatches =
			findGoodImpliedMatches(impliedMatchSet.getMatches(), minVotes,
				maxConflicts, monitor);

		while (goodImpliedMatches.size() > 0) {

			monitor.checkCancelled();

			// apply the "good" implied matches
			hasApplyErrors |= applyMatches(goodImpliedMatches, monitor);

			// possibly create more implied matches from the newly applied matches
			createImpliedMatches(monitor, processedSrcDestPairs, goodImpliedMatches);

			// possibly find more "good" implied matches from any new implied matches found
			impliedMatchSet = session.getImpliedMatchSet();
			goodImpliedMatches = findGoodImpliedMatches(impliedMatchSet.getMatches(),
				minVotes, maxConflicts, monitor);
		}

		return hasApplyErrors;

	}

	private void createImpliedMatches(TaskMonitor monitor, Set<VTAssociation> processedSrcDestPairs,
			Collection<VTMatch> matches) throws CancelledException {
		for (VTMatch match : matches) {
			monitor.checkCancelled();

			VTAssociation association = match.getAssociation();

			// Implied matches currently only created for functions so skip matches that are
			// data matches
			if (association.getType() == VTAssociationType.DATA) {
				continue;
			}

			// Implied matches should only be created for matches that user has accepted as 
			// good matches
			if (association.getStatus() != VTAssociationStatus.ACCEPTED) {
				continue;
			}
			// only process the same match pair once so implied vote counts are not overinflated
			if (processedSrcDestPairs.contains(association)) {
				continue;
			}

			MatchInfo matchInfo = matchInfoFactory.getMatchInfo(match, addressCorrelator);

			if (matchInfo.getSourceFunction() == null ||
				matchInfo.getDestinationFunction() == null) {
				continue;
			}

			ImpliedMatchUtils.updateImpliedMatchForAcceptedAssocation(
				matchInfo.getSourceFunction(),
				matchInfo.getDestinationFunction(), session,
				addressCorrelator, monitor);

			processedSrcDestPairs.add(association);
		}
	}

	/**
	 * Method to find good implied matches based on number of votes and conflicts
	 * @param matchesToProcess the set of matches to process for good implied matches
	 * @param minVoteCountNeeded the minimum vote count needed for a "good" implied match
	 * @param maxConflictsAllowed the maximum number of conflicts allowed for a "good" implied match
	 * @param monitor the monitor
	 * @return a set of good implied matches based on the minVoteCountNeeded needed and
	 *  maxConfictsAllowed
	 * @throws CancelledException if cancelled
	 */
	private Set<VTMatch> findGoodImpliedMatches(Collection<VTMatch> matchesToProcess,
			int minVoteCountNeeded, int maxConflictsAllowed,
			TaskMonitor monitor) throws CancelledException {


		Set<VTMatch> goodImpliedMatches = new HashSet<>();

		for (VTMatch match : matchesToProcess) {
				monitor.checkCancelled();

				VTAssociation association = match.getAssociation();

				// skip if already accepted or blocked match
				if (association.getStatus() != VTAssociationStatus.AVAILABLE) {
					continue;
				}

				// skip if there are any conflicting associations
				int numConflicts = association.getRelatedAssociations().size() - 1;
				if (numConflicts > maxConflictsAllowed) {
					continue;
				}

				int voteCount = association.getVoteCount();

				if (voteCount >= minVoteCountNeeded) {
					goodImpliedMatches.add(match);
				}

				monitor.incrementProgress();
		}

		return goodImpliedMatches;

	}

	private int getNumberOfDataMatches(TaskMonitor monitor) throws CancelledException {

		int numDataMatches = 0;
		List<VTMatchSet> matchSets = session.getMatchSets();
		for (VTMatchSet matchSet : matchSets) {
			monitor.checkCancelled();
			Collection<VTMatch> matches = matchSet.getMatches();
			for (VTMatch match : matches) {
				monitor.checkCancelled();
				if (match.getAssociation().getStatus() == VTAssociationStatus.ACCEPTED &&
					match.getAssociation().getType() == VTAssociationType.DATA) {
					numDataMatches++;
				}
			}
		}
		return numDataMatches;
	}

	private int getNumberOfFunctionMatches(TaskMonitor monitor) throws CancelledException {

		int numFunctionMatches = 0;
		List<VTMatchSet> matchSets = session.getMatchSets();
		for (VTMatchSet matchSet : matchSets) {
			monitor.checkCancelled();
			Collection<VTMatch> matches = matchSet.getMatches();
			for (VTMatch match : matches) {
				monitor.checkCancelled();
				if (match.getAssociation().getStatus() == VTAssociationStatus.ACCEPTED &&
					match.getAssociation().getType() == VTAssociationType.FUNCTION) {
					numFunctionMatches++;
				}
			}
		}
		return numFunctionMatches;
	}

	/**
	 * Runs the given version tracking (VT) correlator and applies the returned matches meeting the
	 * given score and confidence thresholds and are not otherwise blocked.
	 * @param factory The correlator factory used to create and run the desired VT correlator.
	 * @param options The options to pass the correlator including score and confidence values.
	 * @param monitor Checks to see if user has cancelled.
	 * @throws CancelledException if cancelled
	 */
	private boolean correlateAndPossiblyApply(VTProgramCorrelatorFactory factory, VTOptions options,
			TaskMonitor monitor) throws CancelledException {

		monitor.checkCancelled();

		monitor.setMessage(
			"Finding and applying good " + factory.getName() + " matches and markup.");

		VTProgramCorrelator correlator = factory.createCorrelator(sourceProgram, sourceAddressSet,
			destinationProgram, destinationAddressSet, options);

		VTMatchSet results = correlator.correlate(session, monitor);
		monitor.initialize(results.getMatchCount());
		boolean hasMarkupErrors = applyMatches(results.getMatches(), monitor);

		monitor.incrementProgress(1);

		return hasMarkupErrors;

	}

	/**
	 * Runs the Duplicate Exact Function match version tracking (VT) correlator then determines
	 * correct matches based on matching operand values. Those matches are accepted and other
	 * possible matches for those functions are blocked. Markup from accepted source functions
	 * is applied to matching destination functions.
	 * 
	 * @param factory The correlator factory used to create and run the desired VT correlator. In
	 * this case, the duplicate function instruction match correlator.
	 * @param monitor Checks to see if user has cancelled.
	 * @throws CancelledException if cancelled
	 */
	private boolean correlateAndPossiblyApplyDuplicateFunctions(VTProgramCorrelatorFactory factory,
			VTOptions options, TaskMonitor monitor) throws CancelledException {

		monitor.setMessage(
			"Finding and applying good " + factory.getName() + " matches and markup.");

		VTProgramCorrelator correlator = factory.createCorrelator(sourceProgram, sourceAddressSet,
			destinationProgram, destinationAddressSet, options);

		VTMatchSet results = correlator.correlate(session, monitor);
		monitor.initialize(results.getMatchCount());

		boolean hasMarkupErrors = applyDuplicateFunctionMatches(results, monitor);
		monitor.incrementProgress(1);

		return hasMarkupErrors;
	}

	/**
	 * Called for all correlators that are run by this command except the duplicate function
	 * instruction match correlator.
	 * @param matches The set of matches to try to accept
	 * @param monitor the task monitor
	 * @return true if some matches have markup errors and false if none have markup errors
	 * @throws CancelledException if cancelled
	 */
	private boolean applyMatches(Collection<VTMatch> matches, TaskMonitor monitor)
			throws CancelledException {

		// If this value gets set to true then there are some markup errors in the whole set of
		// matches.
		boolean someMatchesHaveMarkupErrors = false;
		// Note: no need to check score/confidence because they are passed into the correlator
		// ahead of time so correlator only returns matches higher than given score/threshold
		for (VTMatch match : matches) {
			monitor.checkCancelled();
			VTAssociation association = match.getAssociation();

			if (!association.getStatus().canApply()) {
				continue;
			}

			if (hasAcceptedRelatedAssociation(association, monitor)) {
				Msg.warn(AutoVersionTrackingTask.class,
					"This association has a related association with an accepted match so cannot " +
						"make this association accepted which would try to block the already accepted " +
						"related association " +
						association);
				continue;
			}

			if (!tryToSetAccepted(association)) {
				continue;
			}

			MatchInfo matchInfo = matchInfoFactory.getMatchInfo(match, addressCorrelator);
			Collection<VTMarkupItem> markupItems = matchInfo.getAppliableMarkupItems(monitor);
			if (markupItems == null || markupItems.size() == 0) {
				continue;
			}

			ApplyMarkupItemTask markupTask =
				new ApplyMarkupItemTask(session, markupItems, toolOptions);

			markupTask.run(monitor);
			boolean currentMatchHasErrors = markupTask.hasErrors();
			if (currentMatchHasErrors) {
				someMatchesHaveMarkupErrors = true;
			}

		}
		return someMatchesHaveMarkupErrors;

	}

	/**
	 * This method tries to set a match association as accepted.
	 * @param association The match association between two match items.
	 * @return true if match is accepted and false if an exception occurred and the match couldn't be
	 * accepted.
	 */
	private static boolean tryToSetAccepted(VTAssociation association) {

		try {
			association.setAccepted();
			return true;
		}
		catch (VTAssociationStatusException e) {
			Msg.warn(AutoVersionTrackingTask.class,
				"Could not set match accepted for " + association, e);
			return false;
		}
	}

	/**
	 * Method to test whether any related associations (ie associations with either the same source 
	 * or the same destination address) have already been accepted
	 * @param association the given association (src/dest match pair)
	 * @param taskMonitor the task monitor
	 * @return true if any related associations have already been accepted, false otherwise
	 * @throws CancelledException if cancelled
	 */
	private boolean hasAcceptedRelatedAssociation(VTAssociation association,
			TaskMonitor taskMonitor) throws CancelledException {

		VTAssociationManager vtAssocManager = session.getAssociationManager();

		Set<VTAssociation> relatedAssociations =
			new HashSet<VTAssociation>(
				vtAssocManager.getRelatedAssociationsBySourceAndDestinationAddress(
					association.getSourceAddress(), association.getDestinationAddress()));

		for (VTAssociation relatedAssociation : relatedAssociations) {

			taskMonitor.checkCancelled();

			//skip self
			if (relatedAssociation.equals(association)) {
				continue;
			}

			VTAssociationStatus status = relatedAssociation.getStatus();

			if (status.equals(VTAssociationStatus.ACCEPTED)) {
				Msg.debug(this, relatedAssociation.toString() + " is already accepted match.");
				return true;
			}

		}
		return false;
	}

	/**
	 * Method to accept matches and apply markup for duplicate function instruction matches with 
	 * matching operands if they are a unique match within their associated subset. To explain in 
	 * more depth, the duplicate function instruction correlator returns a set of function matches 
	 * such that there are subsets of matches where each function pair has the same exact function 
	 * instructions but possibly different operands. Also, there must be more than one possible
	 * function pair association or it would have been identified as a unique match by the exact 
	 * unique function instruction correltor. This method attempts to find unique matches from 
	 * within the related subsets by comparing operand information. 
	 * @param matches The set of matches from the duplicate function instruction correlator
	 * @param monitor Allows user to cancel
	 * @return true if there are any markup errors, false if no markup errors
	 * @throws CancelledException if cancelled
	 */
	private boolean applyDuplicateFunctionMatches(VTMatchSet matchSet, TaskMonitor monitor)
			throws CancelledException {

		Collection<VTMatch> matches = matchSet.getMatches();

		// If this value gets set to true later it indicates markup errors upon applying markup.
		boolean someMatchesHaveMarkupErrors = false;
		Set<VTAssociation> processedSrcDestPairs = new HashSet<>();

		String message = "Processing match %d of %d...";
		int n = matches.size();
		Iterator<VTMatch> it = matches.iterator();
		for (int i = 0; it.hasNext(); i++) {
			monitor.checkCancelled();
			monitor.setMessage(String.format(message, i, n));

			VTMatch match = it.next();

			VTAssociation association = match.getAssociation();

			// skip if match has already been processed (ie matched or determined to be unable 
			// to match)
			if (processedSrcDestPairs.contains(association)) {
				continue;
			}

			// if this association src/dest pair is already matched or blocked skip it
			if (association.getStatus() != VTAssociationStatus.AVAILABLE) {
				processedSrcDestPairs.add(association);
				continue;
			}

			// get the entire set of functions with the same instructions as the given source and 
			// destination pair
			Set<VTAssociation> allRelatedAssociations = getAllRelatedAssociations(
				match.getSourceAddress(), match.getDestinationAddress(), monitor);

			// Try to find all the unique matches in this set with the same operands as each other.
			// The duplicate function instruction correlator already grouped them into sets of
			// functions pairs with exactly the same instructions. This is trying to find the 
			// correct matches in this set.
			Collection<VTAssociation> uniqueAssociations =
				findUniqueAssociations(allRelatedAssociations, monitor);

			// Whether or not a unique association has been found, add these associations to the 
			// processed list so the check is not repeated for another src/dest pair in this
			// set later.
			processedSrcDestPairs.addAll(allRelatedAssociations);
			if (uniqueAssociations == null) {
				continue;
			}

			// For each good match found, accept the match and apply markup
			for (VTAssociation uniqueAssociation : uniqueAssociations) {
				monitor.checkCancelled();

				VTMatch theMatch =
					getAssociationMatchFromMatchSet(uniqueAssociation, matchSet, monitor);
				if (theMatch == null) {
					Msg.error(this,
						uniqueAssociation.toString() + " Should be in the original match set used");
					continue;
				}

				someMatchesHaveMarkupErrors |= tryToAcceptMatchAndApplyMarkup(theMatch, monitor);
			}
		}

		return someMatchesHaveMarkupErrors;

	}

	/**
	 * Get the entire set of related duplicate functions with the same instructions
	 * @param source the given source address
	 * @param destination the given destination address
	 * @param monitor the task monitor
	 * @return the entire set of related duplicate functions with the same instructions
	 * @throws CancelledException if cancelled
	 */
	private Set<VTAssociation> getAllRelatedAssociations(Address source, Address destination,
			TaskMonitor monitor) throws CancelledException {

		// get all associations with the same source or the same destination address
		VTAssociationManager vtAssocManager = session.getAssociationManager();
		Collection<VTAssociation> relatedAssociations =
			vtAssocManager.getRelatedAssociationsBySourceAndDestinationAddress(
				source, destination);

		Set<VTAssociation> allRelatedAssociations = new HashSet<VTAssociation>(relatedAssociations);

		// from the initial set of related associations get all the other ones that have related
		// associations with all the source/destinations of the newly found associations
		for (VTAssociation association : relatedAssociations) {
			monitor.checkCancelled();

			allRelatedAssociations
					.addAll(vtAssocManager.getRelatedAssociationsBySourceAndDestinationAddress(
						association.getSourceAddress(), association.getDestinationAddress()));
		}

		return allRelatedAssociations;
	}

	/**
	 * Given an association, get the VTMatch from the given matchSet (ie set of matches from a 
	 * particular correlator). There may be multiple correlators that have found the same match. 
	 * This is making sure the match is from the desired correlator.
	 * @param association the given association
	 * @param matchSet the given correlator matchSet
	 * @param monitor the task monitor
	 * @return the match with same source and destination addresss as the given association from the
	 * given correlator's set of matches.
	 * @throws CancelledException if cancelled
	 */
	private VTMatch getAssociationMatchFromMatchSet(VTAssociation association,
			VTMatchSet matchSet, TaskMonitor monitor) throws CancelledException {

		List<VTMatch> assocMatchesInMatchSet = new ArrayList<VTMatch>();

		List<VTMatch> assocationMatches = session.getMatches(association);
		Collection<VTMatch> matchSetMatches = matchSet.getMatches();

		for (VTMatch match : assocationMatches) {
			monitor.checkCancelled();

			if (matchSetMatches.contains(match)) {
				assocMatchesInMatchSet.add(match);
			}

		}

		if (assocMatchesInMatchSet.size() == 1) {
			return assocMatchesInMatchSet.get(0);
		}

		Msg.error(this,
			"Expected single match in matchset for association " + association.toString());

		return null;
	}


	/**
	 * From the given related association, ie a group of src/dest pairs of functions with identical
	 *  instructions, use operand information to find any unique matches in the set. 
	 * @param relatedAssociations group of src/dest pairs of functions with identical instructions
	 * @param monitor the task monitor
	 * @return a list of src/destination associations that are uniquely matched based on matching
	 *  operands
	 * @throws CancelledException if cancelled
	 */
	private List<VTAssociation> findUniqueAssociations(
			Collection<VTAssociation> relatedAssociations, TaskMonitor monitor)
			throws CancelledException {


		// create function to operand map maps for each source and destination function
		// in the given related associations (src/dst function pairs)
		Map<Function, Map<Long, Map<Integer, Object>>> sourceFunctionsMap =
			createFunctionsMap(relatedAssociations, true, monitor);

		Map<Function, Map<Long, Map<Integer, Object>>> destFunctionsMap =
			createFunctionsMap(relatedAssociations, false, monitor);


		// only functions with scalar or address operands are mapped so the lists could be
		// empty if there are functions with no operand info to be mapped
		if (sourceFunctionsMap.isEmpty() || destFunctionsMap.isEmpty()) {
			return null;
		}

		List<VTAssociation> uniqueAssociations = findUniqueAssociationsUsingMaps(sourceFunctionsMap,
			destFunctionsMap, monitor);

		return uniqueAssociations;
	}

	/**
	 * Method to use the given function to operand maps, for sets of source and destination functions 
	 * with identical instructions, to identify any unique src/dst matches within the set. 
	 * instructions
	 * @param sourceFunctionsMap the source functions map
	 * @param destFunctionsMap the destination functions map
	 * @param monitor the task monitor
	 * @return the list of unique associations (src/dest function pairs) if any
	 * @throws CancelledException if cancelled
	 */
	private List<VTAssociation> findUniqueAssociationsUsingMaps(
			Map<Function, Map<Long, Map<Integer, Object>>> sourceFunctionsMap,
			Map<Function, Map<Long, Map<Integer, Object>>> destFunctionsMap,
			TaskMonitor monitor)
			throws CancelledException {

		List<VTAssociation> uniqueAssociations = new ArrayList<VTAssociation>();

		// for each source function, try to find a single matching destination function from 
		// the associated functions that have map info
		VTAssociationManager vtAssocManager = session.getAssociationManager();
		Set<Function> sourceFunctions = sourceFunctionsMap.keySet();

		Set<Function> matchedDestFunctions = new HashSet<Function>();

		for (Function sourceFunction : sourceFunctions) {
			monitor.checkCancelled();

			Map<Long, Map<Integer, Object>> sourceFunctionMap =
				sourceFunctionsMap.get(sourceFunction);

			Function destFunction =
				getSingleMatch(sourceFunctionMap, destFunctionsMap, matchedDestFunctions, monitor);

			if (destFunction == null) {
				continue;
			}

			// track matched destination functions so they are not checked again later
			matchedDestFunctions.add(destFunction);

			// add the association for the given src/dest pair to the list of good matches
			VTAssociation association = vtAssocManager
					.getAssociation(sourceFunction.getEntryPoint(), destFunction.getEntryPoint());
			if (association != null) {
				uniqueAssociations.add(association);
			}
		}
		return uniqueAssociations;
	}

	/**
	 * Create an operand map for each source or destination function in the given associations
	 * @param associations The collection of associations (src/dest function pairs)
	 * @param source if true use the source function, if false use the destination function
	 * @param monitor the task monitor
	 * @return the map of functions to their operand maps
	 * @throws CancelledException if cancelled
	 */
	private Map<Function, Map<Long, Map<Integer, Object>>> createFunctionsMap(
			Collection<VTAssociation> associations, boolean source, TaskMonitor monitor)
			throws CancelledException {

		Map<Function, Map<Long, Map<Integer, Object>>> functionsMap =
			new HashMap<>();

		// to keep track of which functions are attempted so only mapped once since there are 
		// multiple pairs with same source function and multiple with the same dest function
		Set<Function> functionsMapAttempted = new HashSet<Function>();

		// make an operand map for each source and destination function in the given associations
		for (VTAssociation association : associations) {
			monitor.checkCancelled();

			Function function = null;
			if (source) {
				function = getSourceFunction(association);
			}
			else {
				function = getDestFunction(association);
			}
			if (function == null) {
				continue;
			}

			if (functionsMapAttempted.contains(function)) {
				continue;
			}

			functionsMapAttempted.add(function);

			// create offset/operand info map for the given source function 
			Map<Long, Map<Integer, Object>> map =
				mapFunctionScalarAndAddressOperands(function, monitor);

			// only keep the ones with operand info to map
			if (map != null) {
				functionsMap.put(function, map);
			}
		}
		return functionsMap;
	}


	/**
	 * Using the given source function's map and a list of destination function maps, and a list 
	 * of destination functions to omit because they already have found matches, try to find a 
	 * single match using matching operand info. 
	 * 
	 * @param sourceFunctionMap the operand map for the source function
	 * @param destFunctionsMap the maps for the destination functions
	 * @param destFunctionsToOmit the destination functions that already have been mapped
	 * @param monitor the task monitor
	 * @return a single matching destination function or null if none or more than one are found
	 * @throws CancelledException if cancelled
	 */
	private Function getSingleMatch(Map<Long, Map<Integer, Object>> sourceFunctionMap,
			Map<Function, Map<Long, Map<Integer, Object>>> destFunctionsMap,
			Set<Function> destFunctionsToOmit,
			TaskMonitor monitor) throws CancelledException {

		Set<Function> destFunctions = destFunctionsMap.keySet();
		Set<Function> matchingFunctions = new HashSet<>();

		// remove the omitted ones which were previously matched to something else
		destFunctions.removeAll(destFunctionsToOmit);

		for (Function destFunction : destFunctions) {
			monitor.checkCancelled();

			Map<Long, Map<Integer, Object>> destFunctionMap =
				destFunctionsMap.get(destFunction);

			// skip if the operand maps don't match
			if (!equalsFunctionMap(sourceFunctionMap, destFunctionMap, monitor)) {
				continue;
			}

			// add to list of operand maps match
			matchingFunctions.add(destFunction);

		}
		if (matchingFunctions.size() == 1) {
			List<Function> list = new ArrayList<Function>(matchingFunctions);
			return list.get(0);
		}
		return null;

	}

	private boolean equalsFunctionMap(Map<Long, Map<Integer, Object>> map1,
			Map<Long, Map<Integer, Object>> map2, TaskMonitor monitor)
			throws CancelledException {

		if (!map1.keySet().equals(map2.keySet())) {
			return false;
		}
		Set<Long> map1Longs = map1.keySet();

		for (Long offset : map1Longs) {

			Map<Integer, Object> opMap1 = map1.get(offset);
			Map<Integer, Object> opMap2 = map2.get(offset);

			if (!equivalentOperandMap(opMap1, opMap2, monitor)) {
				return false;
			}
		}
		return true;

	}

	private boolean equivalentOperandMap(Map<Integer, Object> map1,
			Map<Integer, Object> map2,
			TaskMonitor monitor) throws CancelledException {

		if (!map1.keySet().equals(map2.keySet())) {
			return false;
		}

		for (Integer i : map1.keySet()) {

			monitor.checkCancelled();

			Object op1 = map1.get(i);
			Object op2 = map2.get(i);
			if (!equivalentOperands(op1, op2)) {
				return false;
			}
		}

		return true;

	}

	private boolean equivalentOperands(Object op1, Object op2) {

		if ((op1 instanceof Scalar)) {
			return op1.equals(op2);
		}

		return isEquivalentAddressOperand(op1, op2);

	}

	/**
	 * Method to determine if the two given operands are equivalent Address operands
	 * @param op1 the first operand
	 * @param op2 the second operand
	 * @return true if the operands are equivalent Address operands, false otherwise
	 */
	private boolean isEquivalentAddressOperand(Object op1, Object op2) {

		if (!(op1 instanceof Address)) {
			return false;
		}

		if (!(op2 instanceof Address)) {
			return false;
		}

		Address addr1 = (Address) op1;
		Address addr2 = (Address) op2;

		// if there a defined association then consider it an equivalent operand
		VTAssociation association = session.getAssociationManager().getAssociation(addr1, addr2);
		if (association != null) {
			return true;
		}

		// if either has existing association with something else then consider not equivalent
		if (hasAnyAssociations(addr1, addr2)) {
			return false;
		}

		// if no association information then check to see if both are functions or if both are 
		// same data type
		return isSameOperandType(addr1, addr2);

	}

	/**
	 * Method to check to see if both addresses have functions at them or the same data type at them
	 * @param addr1 the first Address
	 * @param addr2 the second Address
	 * @return
	 */
	private boolean isSameOperandType(Address addr1, Address addr2) {

		Function function1 = sourceProgram.getFunctionManager().getFunctionAt(addr1);
		if (function1 != null) {
			Function function2 = destinationProgram.getFunctionManager().getFunctionAt(addr2);
			if (function2 != null) {
				return true;
			}
			else {
				return false;
			}
		}

		Data data1 = sourceProgram.getListing().getDataAt(addr1);
		if (data1 != null && data1.isDefined()) {
			Data data2 = destinationProgram.getListing().getDataAt(addr2);
			if (data2 == null) {
				return false;
			}
			if (!data2.isDefined()) {
				return false;
			}

			if (data1.getDataType().getName().equals(data2.getDataType().getName())) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Method to determine if the given src or dest addresses have existing association 
	 * @param source the source address
	 * @param dest the destination address
	 * @return true if there are any existin associations, false if none
	 */
	private boolean hasAnyAssociations(Address source, Address dest) {


		Collection<VTAssociation> sourceAssociations = session.getAssociationManager()
				.getRelatedAssociationsBySourceAddress(source);

		if (!sourceAssociations.isEmpty()) {
			return true;
		}

		Collection<VTAssociation> destAssociations = session.getAssociationManager()
				.getRelatedAssociationsByDestinationAddress(dest);

		if (!destAssociations.isEmpty()) {
			return true;
		}

		return false;
	}

	private Function getSourceFunction(VTAssociation association) {

		Address address = association.getSourceAddress();
		return sourceProgram.getFunctionManager().getFunctionAt(address);
	}

	private Function getDestFunction(VTAssociation association) {

		Address address = association.getDestinationAddress();
		return destinationProgram.getFunctionManager().getFunctionAt(address);
	}

	/**
	 * Method to create a map of the given functions scalar operands and address reference operands. 
	 * The map keys will be offsets from the top of the function to the instruction containing the
	 *  operand(s).
	 * The map entries will be a map of the operands at the instruction indicated by the key's 
	 *  offset value. This map has keys for operand index and entries for the type of object at
	 *  that operand index, either Scalar or Address 
	 * @param function the given function
	 * @param monitor the task monitor
	 * @return the resulting map for the given function
	 * @throws CancelledException if cancelled
	 */
	private Map<Long, Map<Integer, Object>> mapFunctionScalarAndAddressOperands(
			Function function, TaskMonitor monitor)
			throws CancelledException {

		Map<Long, Map<Integer, Object>> offsetToOperandsMap = new HashMap<>();
		

		Program program = function.getProgram();

		InstructionIterator func1InstIter =
			program.getListing().getInstructions(function.getBody(), true);

		while (func1InstIter.hasNext()) {
			monitor.checkCancelled();

			Instruction inst = func1InstIter.next();

			Map<Integer, Object> map = createOperandsMap(inst);

			if (map.keySet().isEmpty()) {
				continue;
			}
			
			// get offset from top of function to use in function to operandMap map
			// can be positive or negative offset (positive means instruction address is after 
			// the entry address, negative means instruction address is before entry address)
			Long entryOffset = function.getEntryPoint().getOffset();
			Long instOffset = inst.getAddress().getOffset();
			Long offset = instOffset - entryOffset;

			offsetToOperandsMap.put(offset, map);
		}

		if (offsetToOperandsMap.keySet().isEmpty()) {
			return null;
		}

		return offsetToOperandsMap;
	}

	/**
	 * Method to create offset/operand mapping for each function in match set
	 * if more than one identical offset/operand mapping in src or dest piles then remove
	 * if no operands remove
	 * 
	 */
	private Map<Integer, Object> createOperandsMap(Instruction inst) {

		Map<Integer, Object> map = new HashMap<>();
		int numOperands = inst.getNumOperands();

		for (int opIndex = 0; opIndex < numOperands; opIndex++) {

			int opType = inst.getOperandType(opIndex);

			// save off operand if a scalar or a code or data reference
			if (OperandType.isScalar(opType)) {
				map.put(opIndex, inst.getScalar(opIndex));
				continue;
			}

			// if operands are addresses check to see if both refer to data or both refer to code
			if (OperandType.isAddress(opType)) {
				if (OperandType.isDataReference(opType)) {
					//Reference opRef = inst.getPrimaryReference(opIndex);
					map.put(opIndex, inst.getAddress(opIndex));
					continue;
				}

				if (OperandType.isCodeReference(opType)) {
					map.put(opIndex, inst.getAddress(opIndex));
					continue;
				}

			}
		}
		return map;
	}

	/**
	 * Try to accept the given match and if can accept the match try to apply its markup
	 * @param match The match to try and accept and apply markup to
	 * @param monitor Allow user to cancel
	 * @return true if there are any markup errors, false if no markup errors
	 * @throws CancelledException if cancelled
	 */
	private boolean tryToAcceptMatchAndApplyMarkup(VTMatch match, TaskMonitor monitor)
			throws CancelledException {

		VTAssociation association = match.getAssociation();

		// skip already accepted or blocked matches
		if (association.getStatus() == VTAssociationStatus.AVAILABLE) {

			if (hasAcceptedRelatedAssociation(association, monitor)) {
				Msg.warn(AutoVersionTrackingTask.class,
					"This association has a related association with an accepted match so cannot " +
						"make this association accepted which would try to block the already accepted " +
						"related association " +
						association);
				return false;
			}

			// Try to accept the match
			if (tryToSetAccepted(association)) {

				// If accept match succeeds apply the markup for the match
				MatchInfo matchInfo = matchInfoFactory.getMatchInfo(match, addressCorrelator);
				Collection<VTMarkupItem> markupItems = matchInfo.getAppliableMarkupItems(monitor);
				if (markupItems != null && markupItems.size() != 0) {

					ApplyMarkupItemTask markupTask =
						new ApplyMarkupItemTask(session, markupItems, toolOptions);
					markupTask.run(monitor);
					boolean currentMatchHasErrors = markupTask.hasErrors();
					if (currentMatchHasErrors) {
						return true;
					}
				}
			}
		}
		return false;
	}

	public String getStatusMsg() {
		return statusMsg;
	}

	/** A task monitor that allows us to control the message content and the progress */
	private class SubTaskMonitor extends WrappingTaskMonitor {

		private String prefix;

		SubTaskMonitor(TaskMonitor delegate) {
			super(delegate);
		}

		void setPrefix(String prefix) {
			this.prefix = prefix;
		}

		void doIncrementProgress() {
			super.incrementProgress(1);
		}

		void doInitialize(long max) {
			super.initialize(max);
		}

		@Override
		public void setMessage(String message) {
			super.setMessage(prefix + message);
		}

		@Override
		public void initialize(long max) {
			// we control the max value
		}

		@Override
		public synchronized void setMaximum(long max) {
			// we control the max value
		}

		@Override
		public void setProgress(long value) {
			// we control the progress
		}

		@Override
		public void incrementProgress(long incrementAmount) {
			// we control progress
		}
	}
}
