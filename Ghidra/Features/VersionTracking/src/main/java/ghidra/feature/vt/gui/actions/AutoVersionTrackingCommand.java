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

import ghidra.feature.vt.api.correlator.program.*;
import ghidra.feature.vt.api.main.*;
import ghidra.feature.vt.api.util.VTAssociationStatusException;
import ghidra.feature.vt.api.util.VTOptions;
import ghidra.feature.vt.gui.plugin.VTController;
import ghidra.feature.vt.gui.task.ApplyMarkupItemTask;
import ghidra.feature.vt.gui.util.MatchInfo;
import ghidra.framework.cmd.BackgroundCommand;
import ghidra.framework.model.DomainObject;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.listing.*;
import ghidra.program.util.ListingDiff;
import ghidra.util.Msg;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import util.CollectionUtils;

/**
 *  This command runs all of the <b>exact</b> {@link VTProgramCorrelator}s that return 
 *  unique matches (ie only one of each match is found in each program):
 *  <ol>
 *  <li> Exact Symbol Name correlator </li>
 *  <li> Exact Data correlator </li>
 *  <li> Exact Function Byte correlator </li> 
 *  <li> Exact Function Instruction correlator </li>
 *  <li> Exact Function Mnemonic correlator </li>
 *  </ol>
 *  
 *  <P> After running each correlator all matches are accepted since they are exact/unique matches
 *  and all markup from the source program functions is applied to the matching destination program
 *  functions.
 *   
 * 	<P> Next, this command runs the Duplicate Function Instruction correlator to find any non-unique 
 *  functions with exact instruction bytes then compares their operands to determine and accept 
 *  correct matches with markup. 
 *  
 *  <P> The command then gets a little more speculative by running the Combined Function and Data 
 *  Reference correlator, which uses match information from the previous correlators to find more 
 *  matches. 
 *  
 *  <P> As more techniques get developed, more automation will be added to this command.
 *   
 */
public class AutoVersionTrackingCommand extends BackgroundCommand {

	private VTSession session;
	private Program sourceProgram;
	private Program destinationProgram;
	private PluginTool serviceProvider;
	private AddressSetView sourceAddressSet;
	private AddressSetView destinationAddressSet;
	private VTController controller;
	private double minCombinedReferenceCorrelatorScore;
	private double minCombinedReferenceCorrelatorConfidence;
	private final ToolOptions applyOptions;
	private String statusMsg = null;
	private static int NUM_CORRELATORS = 7;

	/**
	 * Constructor for AutoVersionTrackingCommand
	 * 
	 * @param controller The Version Tracking controller for this session containing option and
	 * tool information needed for this command.
	 * @param session The Version Tracking session containing the source, destination, correlator 
	 * and match information needed for this command. 
	 * @param minCombinedReferenceCorrelatorScore The minimum score used to limit matches created by
	 * the Combined Reference Correlator.
	 * @param minCombinedReferenceCorrelatorConfidence The minimum confidence used to limit matches 
	 * created by the Combined Reference Correlator.
	 */
	public AutoVersionTrackingCommand(VTController controller, VTSession session,
			double minCombinedReferenceCorrelatorScore,
			double minCombinedReferenceCorrelatorConfidence) {
		this.session = session;
		this.sourceProgram = session.getSourceProgram();
		this.destinationProgram = session.getDestinationProgram();
		this.serviceProvider = controller.getTool();
		this.controller = controller;
		this.minCombinedReferenceCorrelatorScore = minCombinedReferenceCorrelatorScore;
		this.minCombinedReferenceCorrelatorConfidence = minCombinedReferenceCorrelatorConfidence;
		this.applyOptions = controller.getOptions();
	}

	@Override
	public boolean applyTo(DomainObject obj, TaskMonitor monitor) {

		boolean hasApplyErrors = false;
		sourceAddressSet = sourceProgram.getMemory().getLoadedAndInitializedAddressSet();
		destinationAddressSet = destinationProgram.getMemory().getLoadedAndInitializedAddressSet();
		try {
			monitor.setMessage("Running Auto Version Tracking");
			monitor.setCancelEnabled(true);
			monitor.initialize(NUM_CORRELATORS);

			// Use default options for all of the "exact" correlators and passed in options for
			// the others. 
			VTOptions options;

			// Run the correlators in the following order: 
			// Do this one first because we don't want it to find ones that get markup 
			// applied by later correlators
			VTProgramCorrelatorFactory factory = new SymbolNameProgramCorrelatorFactory();
			options = factory.createDefaultOptions();
			hasApplyErrors = correlateAndPossiblyApply(factory, options, monitor);

			factory = new ExactDataMatchProgramCorrelatorFactory();
			options = factory.createDefaultOptions();
			hasApplyErrors |= correlateAndPossiblyApply(factory, options, monitor);

			factory = new ExactMatchBytesProgramCorrelatorFactory();
			options = factory.createDefaultOptions();
			hasApplyErrors |= correlateAndPossiblyApply(factory, options, monitor);

			factory = new ExactMatchInstructionsProgramCorrelatorFactory();
			options = factory.createDefaultOptions();
			hasApplyErrors |= correlateAndPossiblyApply(factory, options, monitor);

			factory = new ExactMatchMnemonicsProgramCorrelatorFactory();
			options = factory.createDefaultOptions();
			hasApplyErrors |= correlateAndPossiblyApply(factory, options, monitor);

			// This is the first of the "speculative" post-correlator match algorithm. The correlator
			// returns all duplicate function instruction matches so there will always be more
			// than one possible match for each function. The compare mechanism used by the 
			// function compare window determines matches based on matching operand values. 
			// Given that each function must contains the same instructions to even become a match, 
			// and the compare function mechanism has been very well tested, the mechanism for 
			// finding the correct match is very accurate.
			factory = new DuplicateFunctionMatchProgramCorrelatorFactory();
			options = factory.createDefaultOptions();
			hasApplyErrors |=
				correlateAndPossiblyApplyDuplicateFunctions(factory, options, monitor);

			// The rest are mores speculative matching algorithms because they depend on our
			// choosing the correct score/confidence pair to determine very probable matches. These
			// values were chosen based on what has been seen so far but this needs to be tested 
			// further on more programs and possibly add options for users to
			// give their own thresholds. 

			// Get the names of the confidence and similarity score thresholds that 
			// are used by all of the "reference" correlators
			String confidenceOption =
				VTAbstractReferenceProgramCorrelatorFactory.CONFIDENCE_THRESHOLD;
			String scoreOption = VTAbstractReferenceProgramCorrelatorFactory.SIMILARITY_THRESHOLD;

			// Get the number of data and function matches
			int numDataMatches = getNumberOfDataMatches(monitor);
			int numFunctionMatches = getNumberOfFunctionMatches(monitor);

			// Run the DataReferenceCorrelator if there are accepted data matches but no accepted 
			// function matches
			if (numDataMatches > 0 && numFunctionMatches == 0) {
				factory = new DataReferenceProgramCorrelatorFactory();
				options = factory.createDefaultOptions();
				options.setDouble(confidenceOption, minCombinedReferenceCorrelatorConfidence);
				options.setDouble(scoreOption, minCombinedReferenceCorrelatorScore);
				hasApplyErrors =
					hasApplyErrors | correlateAndPossiblyApply(factory, options, monitor);

				// Get the number of data and function matches again if this correlator ran
				numDataMatches = getNumberOfDataMatches(monitor);
				numFunctionMatches = getNumberOfFunctionMatches(monitor);
			}

			// Run the FunctionReferenceCorrelator if there are accepted function matches but
			// no accepted data matches
			if (numDataMatches > 0 && numFunctionMatches == 0) {
				factory = new FunctionReferenceProgramCorrelatorFactory();
				options = factory.createDefaultOptions();
				options.setDouble(confidenceOption, minCombinedReferenceCorrelatorConfidence);
				options.setDouble(scoreOption, minCombinedReferenceCorrelatorScore);
				factory = new FunctionReferenceProgramCorrelatorFactory();
				hasApplyErrors =
					hasApplyErrors | correlateAndPossiblyApply(factory, options, monitor);

				// Get the number of data and function matches again if this correlator ran
				numDataMatches = getNumberOfDataMatches(monitor);
				numFunctionMatches = getNumberOfFunctionMatches(monitor);
			}

			// Run the CombinedDataAndFunctionReferenceCorrelator if there are both accepted function matches but
			// and data matches
			if (numDataMatches > 0 && numFunctionMatches > 0) {
				factory = new CombinedFunctionAndDataReferenceProgramCorrelatorFactory();
				options = factory.createDefaultOptions();
				options.setDouble(confidenceOption, minCombinedReferenceCorrelatorConfidence);
				options.setDouble(scoreOption, minCombinedReferenceCorrelatorScore);
				hasApplyErrors =
					hasApplyErrors | correlateAndPossiblyApply(factory, options, monitor);
			}
		}
		catch (CancelledException e) {
			statusMsg = getName() + " was cancelled.";
			return false;
		}

		String applyMarkupStatus = " with no apply markup errors.";
		if (hasApplyErrors) {
			applyMarkupStatus =
				" with some apply markup errors. See the log or the markup table for more details";
		}
		statusMsg =

			getName() + " completed successfully" + applyMarkupStatus;

		controller.getTool().setStatusInfo(statusMsg);

		return true;
	}

	private int getNumberOfDataMatches(TaskMonitor monitor) throws CancelledException {

		int numDataMatches = 0;
		List<VTMatchSet> matchSets = session.getMatchSets();
		for (VTMatchSet matchSet : matchSets) {
			monitor.checkCanceled();
			Collection<VTMatch> matches = matchSet.getMatches();
			for (VTMatch match : matches) {
				monitor.checkCanceled();
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
			monitor.checkCanceled();
			Collection<VTMatch> matches = matchSet.getMatches();
			for (VTMatch match : matches) {
				monitor.checkCanceled();
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
	 * @throws CancelledException
	 */
	private boolean correlateAndPossiblyApply(VTProgramCorrelatorFactory factory, VTOptions options,
			TaskMonitor monitor) throws CancelledException {

		monitor.checkCanceled();

		monitor.setMessage(
			"Finding and applying good " + factory.getName() + " matches and markup.");

		VTProgramCorrelator correlator = factory.createCorrelator(serviceProvider, sourceProgram,
			sourceAddressSet, destinationProgram, destinationAddressSet, options);

		VTMatchSet results = correlator.correlate(session, monitor);

		boolean hasMarkupErrors = applyMatches(results.getMatches(), correlator.getName(), monitor);

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
	 * @throws CancelledException
	 */
	private boolean correlateAndPossiblyApplyDuplicateFunctions(VTProgramCorrelatorFactory factory,
			VTOptions options, TaskMonitor monitor) throws CancelledException {

		monitor.setMessage(
			"Finding and applying good " + factory.getName() + " matches and markup.");

		VTProgramCorrelator correlator = factory.createCorrelator(serviceProvider, sourceProgram,
			sourceAddressSet, destinationProgram, destinationAddressSet, options);

		VTMatchSet results = correlator.correlate(session, monitor);
		boolean hasMarkupErrors = applyDuplicateFunctionMatches(results.getMatches(), monitor);

		monitor.incrementProgress(1);

		return hasMarkupErrors;
	}

	/**
	 * Called for all correlators that are run by this command except the duplicate function 
	 * instruction match correlator. 
	 * @param matches The set of matches to try to accept as matches. 
	 * @param correlatorName The name of the Version Tracking correlator whose matches are being 
	 * applied here. 
	 * @param monitor Checks to see if user has cancelled.
	 * @return true if some matches have markup errors and false if none have markup errors.
	 * @throws CancelledException
	 */
	private boolean applyMatches(Collection<VTMatch> matches, String correlatorName,
			TaskMonitor monitor) throws CancelledException {

		// If this value gets set to true then there are some markup errors in the whole set of
		// matches.
		boolean someMatchesHaveMarkupErrors = false;
		// Note: no need to check score/confidence because they are passed into the correlator 
		// ahead of time so correlator only returns matches higher than given score/threshold
		for (VTMatch match : matches) {
			monitor.checkCanceled();
			VTAssociation association = match.getAssociation();

			if (!association.getStatus().canApply()) {
				continue;
			}

			if (!tryToSetAccepted(association)) {
				continue;
			}

			MatchInfo matchInfo = controller.getMatchInfo(match);
			Collection<VTMarkupItem> markupItems = matchInfo.getAppliableMarkupItems(monitor);
			if (markupItems == null || markupItems.size() == 0) {
				continue;
			}

			ApplyMarkupItemTask markupTask =
				new ApplyMarkupItemTask(controller.getSession(), markupItems, applyOptions);
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
			Msg.warn(AutoVersionTrackingCommand.class,
				"Could not set match accepted for " + association, e);
			return false;
		}
	}

	/**
	 * Accept matches and apply markup for duplicate function instruction matches with matching operands 
	 * if they are a unique match within their associated set.
	 * @param matches A collection of version tracking matches from the duplicate instruction 
	 * matcher. 
	 * @param monitor Allows user to cancel
	 * @return true if any markup errors, false if no markup errors.
	 * @throws CancelledException
	 */
	private boolean applyDuplicateFunctionMatches(Collection<VTMatch> matches, TaskMonitor monitor)
			throws CancelledException {

		// If this value gets set to true later it indicates markup errors upon applying markup.
		boolean someMatchesHaveMarkupErrors = false;
		Set<VTMatch> copyOfMatches = new HashSet<>(matches);

		// Process matches in related sets of matches
		for (VTMatch match : matches) {
			monitor.checkCanceled();

			// if match has already been removed (ie it was in a set that was already processed) 
			// then skip it
			if (!copyOfMatches.contains(match)) {
				continue;
			}

			// get a set of related matches from the set of all matches
			// ie these all have the same instructions as each other but not necessarily 
			// the same operands.
			Set<VTMatch> relatedMatches = getRelatedMatches(match, matches, monitor);

			// remove related matches from the set of matches to process next time
			removeMatches(copyOfMatches, relatedMatches);

			// remove any matches that have identical source functions - if more than one 
			// with exactly the same instructions and operands then cannot determine a unique match
			Set<Address> sourceAddresses = getSourceAddressesFromMatches(relatedMatches, monitor);
			Set<Address> uniqueSourceFunctionAddresses =
				dedupeMatchingFunctions(sourceProgram, sourceAddresses, monitor);

			// remove any matches that have identical destination functions - if more than one 
			// with exactly the same instructions and operands then cannot determine a unique match
			Set<Address> destAddresses =
				getDestinationAddressesFromMatches(relatedMatches, monitor);
			Set<Address> uniqueDestFunctionAddresses =
				dedupeMatchingFunctions(destinationProgram, destAddresses, monitor);

			//Keep only matches containing the unique sources and destination functions determined above
			Set<VTMatch> dedupedMatches = getMatches(relatedMatches, uniqueSourceFunctionAddresses,
				uniqueDestFunctionAddresses, monitor);

			// Loop through all the source functions
			for (Address sourceAddress : uniqueSourceFunctionAddresses) {
				monitor.checkCanceled();

				//Find all destination functions with equivalent operands to current source function
				Set<VTMatch> matchesWithEquivalentOperands = getMatchesWithEquivalentOperands(
					dedupedMatches, sourceAddress, uniqueDestFunctionAddresses, monitor);

				// If there is just one equivalent match try to accept the match and apply markup 
				if (matchesWithEquivalentOperands.size() == 1) {
					VTMatch theMatch = CollectionUtils.any(matchesWithEquivalentOperands);
					someMatchesHaveMarkupErrors = tryToAcceptMatchAndApplyMarkup(theMatch, monitor);
				}
			}
		}

		return someMatchesHaveMarkupErrors;

	}

	/**
	 * Try to accept the given match and if can accept the match try to apply its markup
	 * @param match The match to try and accept and apply markup to
	 * @param monitor Allow user to cancel
	 * @return true if there are any markup errors, false if no markup errors
	 */
	private boolean tryToAcceptMatchAndApplyMarkup(VTMatch match, TaskMonitor monitor) {

		VTAssociation association = match.getAssociation();

		// skip already accepted or blocked matches
		if (association.getStatus() == VTAssociationStatus.AVAILABLE) {

			// Try to accept the match
			if (tryToSetAccepted(association)) {

				// If accept match succeeds apply the markup for the match
				MatchInfo matchInfo = controller.getMatchInfo(match);
				Collection<VTMarkupItem> markupItems = matchInfo.getAppliableMarkupItems(monitor);
				if (markupItems != null && markupItems.size() != 0) {

					ApplyMarkupItemTask markupTask =
						new ApplyMarkupItemTask(controller.getSession(), markupItems, applyOptions);
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

	/**
	 * Get a set of matches with equivalent operands.
	 * @param matches Set of version tracking matches with matching instructions
	 * @param sourceAddress Address of source function to compare with destination functions
	 * @param destAddresses Addresses of destination functions to compare with source function
	 * @param monitor Allows user to cancel
	 * @return Set of all matches with equivalent operands.
	 * @throws CancelledException
	 */
	private Set<VTMatch> getMatchesWithEquivalentOperands(Set<VTMatch> matches,
			Address sourceAddress, Set<Address> destAddresses, TaskMonitor monitor)
			throws CancelledException {

		Set<VTMatch> matchesWithEquivalentOperands = new HashSet<>();
		for (Address destAddress : destAddresses) {

			if (haveEquivalentOperands(sourceProgram, sourceAddress, destinationProgram,
				destAddress, monitor)) {
				VTMatch goodMatch = getMatch(matches, sourceAddress, destAddress);
				if (goodMatch != null) {
					matchesWithEquivalentOperands.add(goodMatch);
				}
			}
		}
		return matchesWithEquivalentOperands;
	}

	/**
	 * Determine which matches from a collection of matches are related to the given match, ie 
	 * have the same source or destination address as the current match. 
	 * @param match Current version tracking match
	 * @param matches Collection version tracking matches
	 * @param monitor Allows user to cancel
	 * @return Set of matches related to the given match
	 * @throws CancelledException
	 */
	private Set<VTMatch> getRelatedMatches(VTMatch match, Collection<VTMatch> matches,
			TaskMonitor monitor) throws CancelledException {

		VTAssociationManager vtAssocManager = session.getAssociationManager();
		Set<VTMatch> relatedMatches = new HashSet<>();

		Collection<VTAssociation> relatedAssociations =
			vtAssocManager.getRelatedAssociationsBySourceAndDestinationAddress(
				match.getSourceAddress(), match.getDestinationAddress());

		//Add the current match and all related matches to a new set to process
		relatedMatches.add(match);
		// create set of related duplicate matches and remove all related matches from the
		// copied set of all matches so they are not processed more than once
		for (VTAssociation relatedAssociation : relatedAssociations) {
			monitor.checkCanceled();
			VTMatch relMatch = getMatch(matches, relatedAssociation.getSourceAddress(),
				relatedAssociation.getDestinationAddress());
			if (relMatch != null) {
				relatedMatches.add(relMatch);
			}

		}
		return relatedMatches;
	}

	/**
	 * Remove given matches from a set of matches.
	 * @param matchSet Set of matches. 
	 * @param matchesToRemove Set of matches to remove from matches set.
	 */
	private void removeMatches(Set<VTMatch> matchSet, Set<VTMatch> matchesToRemove) {

		for (VTMatch matchToRemove : matchesToRemove) {
			VTMatch match = getMatch(matchSet, matchToRemove.getSourceAddress(),
				matchToRemove.getDestinationAddress());
			if (match != null) {
				matchSet.remove(match);
			}
		}
	}

	/**
	 * Get the source addresses from a set of version tracking matches.
	 * @param matches Set of version tracking matches
	 * @param monitor Allows user to cancel
	 * @return A set of source addresses from the given set of version tracking matches.
	 * @throws CancelledException
	 */
	private Set<Address> getSourceAddressesFromMatches(Set<VTMatch> matches, TaskMonitor monitor)
			throws CancelledException {

		Set<Address> sourceAddresses = new HashSet<>();
		for (VTMatch match : matches) {
			monitor.checkCanceled();
			sourceAddresses.add(match.getSourceAddress());
		}
		return sourceAddresses;
	}

	/**
	 * Get the destination addresses from a set of version tracking matches.
	 * @param matches Set of version tracking matches
	 * @param monitor Allows user to cancel
	 * @return A set of destination addresses from the given set of version tracking matches.
	 * @throws CancelledException
	 */
	private Set<Address> getDestinationAddressesFromMatches(Set<VTMatch> matches,
			TaskMonitor monitor) throws CancelledException {

		Set<Address> destAddresses = new HashSet<>();
		for (VTMatch match : matches) {
			monitor.checkCanceled();
			destAddresses.add(match.getDestinationAddress());
		}
		return destAddresses;
	}

	/**
	 * Given a set of version tracking matches, return the match with the given source/destination
	 * address pair.
	 * @param matches Set of version tracking matches.
	 * @param sourceAddress Address of the source program match item.
	 * @param destAddress Address of the destination program match item.
	 * @return The match with the given source/destination address pair or null if not found.
	 */
	private VTMatch getMatch(Collection<VTMatch> matches, Address sourceAddress,
			Address destAddress) {
		for (VTMatch match : matches) {
			if (match.getSourceAddress().equals(sourceAddress) &&
				match.getDestinationAddress().equals(destAddress)) {
				return match;
			}
		}
		return null;
	}

	/**
	 * From a set of matches get the subset that contains the given source and destination addresses.  
	 * @param matches Set of matches
	 * @param sourceAddresses Set of source addresses
	 * @param destAddresses Set of destination addresses
	 * @param monitor Allows user to cancel
	 * @return Set of matches containing given source and destination addresses.
	 * @throws CancelledException
	 */
	private Set<VTMatch> getMatches(Set<VTMatch> matches, Set<Address> sourceAddresses,
			Set<Address> destAddresses, TaskMonitor monitor) throws CancelledException {

		Set<VTMatch> results = new HashSet<>();
		for (VTMatch match : matches) {
			monitor.checkCanceled();
			if (sourceAddresses.contains(match.getSourceAddress()) &&
				destAddresses.contains(match.getDestinationAddress())) {
				results.add(match);
			}
		}
		return results;
	}

	/**
	 *  * This method is only called to compare functions with identical instruction
	 *  bytes, identical operand lengths, but possibly different operand values. It returns true 
	 *  if the two functions in the match have potentially equivalent operands. It returns false if 
	 *  any of the operands do not match. 
	 *  Potentially equivalent means corresponding scalar operands match, corresponding other operands have
	 *  the same type of operand (ie code, data,register)
	 * @param program1 Program containing function1
	 * @param function1 Function to compare with function2
	 * @param program2 Program containing function2
	 * @param function2 Function to compare with function1
	 * @param monitor Allows user to cancel
	 * @return true if all operands between the two functions match and false otherwise.
	 * @throws CancelledException
	 */
	private boolean haveEquivalentOperands(Program program1, Address address1, Program program2,
			Address address2, TaskMonitor monitor) throws CancelledException {

		Function function1 = program1.getFunctionManager().getFunctionAt(address1);
		Function function2 = program2.getFunctionManager().getFunctionAt(address2);
		if (function1 == null || function2 == null) {
			return false;
		}

		InstructionIterator func1InstIter =
			program1.getListing().getInstructions(function1.getBody(), true);
		InstructionIterator func2InstIter =
			program2.getListing().getInstructions(function2.getBody(), true);

		// Setup the function comparer
		ListingDiff listingDiff = new ListingDiff();
		listingDiff.setIgnoreByteDiffs(false);
		listingDiff.setIgnoreConstants(false);
		listingDiff.setIgnoreRegisters(false);

		while (func1InstIter.hasNext() && func2InstIter.hasNext()) {
			monitor.checkCanceled();

			Instruction inst1 = func1InstIter.next();
			Instruction inst2 = func2InstIter.next();

			// Get the differing operands for this instruction
			int[] operandsThatDiffer = listingDiff.getOperandsThatDiffer(inst1, inst2);
			if (!haveEquivalentOperands(inst1, inst2, operandsThatDiffer)) {
				return false;
			}
		}

		// This should never happen but if it does then throw an error because that means something
		// weird is happening like the action updating the source and destination match lengths 
		// didn't do it correctly.
		if (func1InstIter.hasNext() || func2InstIter.hasNext()) {
			throw new AssertException(
				"Expected Source and Destination function number of instructions to be equal but they differ.");
		}
		// True does not necessarily mean they are THE match. This has hopefully weeded out more
		// bad matches but there are cases where we can't determine one unique match
		return true;
	}

	/**
	 * Determine if the given instructions which have at least one differing operand, have equivalent
	 * operand types. If operand type is a scalar, is it the same scalar. 
	 * @param inst1 Instruction 1
	 * @param inst2 Instruction 2
	 * @param operandsThatDiffer Array of indexes of operands that differ
	 * @return true if all operands in the two instructions are equivalent types and scalars are equal, 
	 * else return false
	 */
	private boolean haveEquivalentOperands(Instruction inst1, Instruction inst2,
			int[] operandsThatDiffer) {

		for (int operand : operandsThatDiffer) {

			// First, check to see if the op type is the same. If not, return false.
			int srcOpType = inst1.getOperandType(operand);
			int destOpType = inst2.getOperandType(operand);
			if (srcOpType != destOpType) {
				return false;
			}

			// If the matching op types are scalars, check to see if they are the same. If not
			// return false.
			if (OperandType.isScalar(srcOpType) &&
				!inst1.getScalar(operand).equals(inst2.getScalar(operand))) {
				return false;
			}

			// if operands are addresses check to see if both refer to data or both refer to code
			if (OperandType.isAddress(srcOpType)) {
				if (OperandType.isDataReference(srcOpType) &&
					OperandType.isDataReference(destOpType)) {
					continue;
				}

				if (OperandType.isCodeReference(srcOpType) &&
					OperandType.isCodeReference(destOpType)) {
					continue;
				}
				return false;
			}
		}
		return true;
	}

	/**
	 * Method to determine if two functions with exactly the same instructions also have exactly the
	 * same operands. 
	 * @param program1 Program that contains function1
	 * @param function1 Function to compare with function2
	 * @param program2 Program that contains function2 (can be same or different than program1) 
	 * @param function2 Function to compare with function1
	 * @param monitor
	 * @return true if two functions have no operand differences, else returns false
	 * @throws CancelledException
	 */
	private boolean haveSameOperands(Program program1, Function function1, Program program2,
			Function function2, TaskMonitor monitor) throws CancelledException {

		CodeUnitIterator sourceFuncCodeUnitIter =
			program1.getListing().getCodeUnits(function1.getBody(), true);
		CodeUnitIterator destFuncCodeUnitIter =
			program2.getListing().getCodeUnits(function2.getBody(), true);

		ListingDiff listingDiff = new ListingDiff();
		listingDiff.setIgnoreByteDiffs(false);
		listingDiff.setIgnoreConstants(false);
		listingDiff.setIgnoreRegisters(false);

		while (sourceFuncCodeUnitIter.hasNext() && destFuncCodeUnitIter.hasNext()) {
			monitor.checkCanceled();
			CodeUnit srcCodeUnit = sourceFuncCodeUnitIter.next();
			CodeUnit dstCodeUnit = destFuncCodeUnitIter.next();

			int[] operandsThatDiffer = listingDiff.getOperandsThatDiffer(srcCodeUnit, dstCodeUnit);

			if (operandsThatDiffer.length > 0) {
				return false;
			}
		}
		// This should never happen but if it does then throw an error because that means something
		// weird is happening like the action updating the source and destination match lengths 
		// didn't do it correctly.
		if (sourceFuncCodeUnitIter.hasNext() || destFuncCodeUnitIter.hasNext()) {
			throw new AssertException(
				"Expected Source and Destination function number of instructions to be equal but they differ.");
		}
		return true;
	}

	/**
	 * Remove addresses from a set of function starting addresses if any functions have all matching
	 * operands.
	 * @param program Program containing functions we are interested in deduping.
	 * @param addresses Set of function start addresses.
	 * @param functionManager Function manager to get functions using their start addresses.
	 * @param monitor
	 * @return Set of addresses of deduped function bytes.
	 * @throws CancelledException
	 */
	public Set<Address> dedupeMatchingFunctions(Program program, Set<Address> addresses,
			TaskMonitor monitor) throws CancelledException {

		FunctionManager functionManager = program.getFunctionManager();

		// Copy the list of addresses to a new array list
		Set<Address> uniqueFunctionAddresses = new HashSet<>(addresses);

		List<Address> list = new ArrayList<>(addresses);

		// Compare 0 to 1, 0 to 2, ... 0 to j-1, 1 to 2, 1 to 3, ... 1- j-1, .... i-2 to j-1 
		for (int i = 0; i < list.size(); i++) {

			Address address1 = list.get(i);
			if (!uniqueFunctionAddresses.contains(address1)) {
				continue;
			}

			for (int j = i + 1; j < list.size(); j++) {
				monitor.checkCanceled();

				Address address2 = list.get(j);

				// If either of the two function addresses are not on the list, they have already
				// been deemed a duplicate so no need to compare either of them again.
				if (!uniqueFunctionAddresses.contains(address2)) {
					continue;
				}

				// Compare the functions at address1 and address2 and see if they have no matching
				// operands. Since all functions in this list already have matching instructions, then
				// if their operands all match, they are completely identical functions and we
				// want to throw them out so remove them from the list.
				if (haveSameOperands(program, functionManager.getFunctionAt(address1), program,
					functionManager.getFunctionAt(address2), monitor)) {

					uniqueFunctionAddresses.remove(address1);
					uniqueFunctionAddresses.remove(address2);
				}
			}
		}

		return uniqueFunctionAddresses;
	}

	@Override
	public String getStatusMsg() {
		return statusMsg;
	}

	@Override
	public String getName() {
		return "Auto Version Tracking Command";
	}
}
