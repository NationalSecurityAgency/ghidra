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
package ghidra.feature.vt.gui.util;

import static ghidra.feature.vt.api.main.VTAssociationType.*;

import java.util.*;

import ghidra.feature.vt.api.impl.MatchSetImpl;
import ghidra.feature.vt.api.main.*;
import ghidra.feature.vt.gui.plugin.AddressCorrelatorManager;
import ghidra.feature.vt.gui.plugin.VTController;
import ghidra.feature.vt.gui.provider.impliedmatches.VTImpliedMatchInfo;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.util.AddressCorrelation;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Utility class for finding version tracking implied matches given an accepted matched function.
 * Each referenced data and function that exist in equivalent sections of the matched source
 * and destination functions will added to the current version tracking session as an implied match. 
 */
public class ImpliedMatchUtils {

	/**
	 * Method for finding version tracking implied matches given an accepted matched
	 * function. Each referenced data and function that exist in equivalent sections
	 * of the matched source and destination functions will added to the current
	 * version tracking session as an implied match.
	 * 
	 * @param controller Version Tracking controller for the current VT tool
	 * @param sourceFunction The matched function from the source program
	 * @param destinationFunction The matched function from the destination program
	 * @param session The Version Tracking session
	 * @param correlationManager Keeps track of which section of the source function corresponds to 
	 * the which section of the destination function
	 * @param monitor Handles user cancellations
	 * @return a set of VTImpliedMatchInfo objects
	 */
	public static Set<VTImpliedMatchInfo> findImpliedMatches(VTController controller,
			Function sourceFunction, Function destinationFunction, VTSession session,
			AddressCorrelatorManager correlatorManager, TaskMonitor monitor)
			throws CancelledException {
		Set<VTImpliedMatchInfo> set = new HashSet<>();

		AddressCorrelation correlator =
			correlatorManager.getCorrelator(sourceFunction, destinationFunction);
		VTMatchSet possibleMatchSet = new MatchSetImpl(session, "Possible Implied Match");

		ReferenceManager referenceManager = sourceFunction.getProgram().getReferenceManager();
		AddressSetView body = sourceFunction.getBody();
		AddressIterator iterator = referenceManager.getReferenceSourceIterator(body, true);
		while (iterator.hasNext()) {
			monitor.checkCanceled();
			Address address = iterator.next();
			Reference[] referencesFrom = referenceManager.getReferencesFrom(address);
			for (Reference reference : referencesFrom) {
				monitor.checkCanceled();
				VTImpliedMatchInfo match = findImpliedMatch(correlator, sourceFunction,
					destinationFunction, reference, possibleMatchSet, monitor);

				if (match != null) {
					set.add(match);
				}
			}
		}

		return set;
	}

	private static VTImpliedMatchInfo findImpliedMatch(AddressCorrelation correlator,
			Function sourceFunction, Function destinationFunction, Reference sourceRef,
			VTMatchSet possibleMatchSet, TaskMonitor monitor) throws CancelledException {

		// Get the reference type of the passed in reference and make sure it is either a call or 
		// data reference
		RefType refType = sourceRef.getReferenceType();
		if (!(refType.isCall() || refType.isData())) {
			return null;
		}

		// Get the source reference's "to" address (the address the reference is pointing to)
		// and make sure it is in the current program memory space
		Address srcRefToAddress = sourceRef.getToAddress();
		if (!srcRefToAddress.isMemoryAddress()) {
			return null;
		}

		// Get corrected source reference "to" address if necessary (ie if thunk get the thunked 
		// function)
		srcRefToAddress = getReference(sourceFunction.getProgram(), srcRefToAddress);
		
		// Get the source reference's "from" address (where the reference itself is located)
		Address srcRefFromAddress = sourceRef.getFromAddress();

		// Get the destination reference address corresponding to the given source reference address  
		AddressRange range = correlator.getCorrelatedDestinationRange(srcRefFromAddress, monitor);
		if (range == null) {
			return null;
		}
		Address destinationAddress = range.getMinAddress();
		ReferenceManager destRefMgr = destinationFunction.getProgram().getReferenceManager();
		Reference[] referencesFrom = destRefMgr.getReferencesFrom(destinationAddress);
		Reference destinationRef = findMatchingRef(refType, referencesFrom);
		if (destinationRef == null) {
			return null;
		}
		
		// Get the destination reference's "to" address
		Address destRefToAddress = destinationRef.getToAddress();
		
		// Get corrected destination reference "to" address if necessary (ie if thunk get the 
		// thunked function)
		destRefToAddress = getReference(destinationFunction.getProgram(), destRefToAddress);

		// Create the initial empty matchInfo for this possible implied match
		VTImpliedMatchInfo matchInfo =
			new VTImpliedMatchInfo(possibleMatchSet, sourceRef, destinationRef);

		// Add the source and destination addresses of the possible implied match
		matchInfo.setSourceAddress(srcRefToAddress);
		matchInfo.setDestinationAddress(destRefToAddress);

		VTAssociationType type;

		if (refType.isData()) {
			type = DATA;
			if (sourceFunction.getProgram().getListing().getInstructionAt(
				srcRefToAddress) != null) {
				if (refType != RefType.DATA) {
					return null; // read/write reference to instruction - not sure what this is
				}
				// otherwise assume it is a function
				type = FUNCTION;
			}
		}
		else {
			type = FUNCTION;
		}

		if (type == FUNCTION) {
			if (sourceFunction.getProgram().getFunctionManager().getFunctionAt(
				srcRefToAddress) == null) {
				return null; // function may not have been created here.
			}
		}

		// Add association type, score, and confidence
		matchInfo.setAssociationType(type);
		matchInfo.setSimilarityScore(new VTScore(0));
		matchInfo.setConfidenceScore(new VTScore(1));

		// Update the length of the match
		updateVTSourceAndDestinationLengths(matchInfo);

		return matchInfo;
	}

	/**
	 * This method checks to see if the given reference is a thunk function and if so returns 
	 * the address of the thunked function instead of thunk function
	 * @param program
	 * @param refToAddress The address of the interesting reference
	 * @return Returns either the same address passed in or the address of the thunked function if 
	 * the original address refers to a thunk
	 */
	private static Address getReference(Program program, Address refToAddress) {
		// If the type is a call then get the function
		// If the function is a thunk - get the thunked to function and make that the implied match
		// source not the thunk

		// if the reference is a thunk function change the refToAddress to the THUNKED function 
		// address instead of the thunk function address
		Function referencedFunction = program.getFunctionManager().getFunctionAt(refToAddress);
		if ((referencedFunction != null) && (referencedFunction.isThunk())) {
			refToAddress = referencedFunction.getThunkedFunction(true).getEntryPoint();
		}
		
		return refToAddress;
	}

	/**
	 * Updates the length values for the source and dest functions or data in the VTMatchInfo object
	 */
	private static void updateVTSourceAndDestinationLengths(VTMatchInfo matchInfo) {
		VTSession session = matchInfo.getMatchSet().getSession();
		Program sourceProgram = session.getSourceProgram();
		Program destinationProgram = session.getDestinationProgram();

		Address sourceAddress = matchInfo.getSourceAddress();
		Address destinationAddress = matchInfo.getDestinationAddress();

		if (matchInfo.getAssociationType() == VTAssociationType.FUNCTION) {
			Function sourceFunction =
				sourceProgram.getFunctionManager().getFunctionAt(sourceAddress);
			Function destFunction =
				destinationProgram.getFunctionManager().getFunctionAt(destinationAddress);
			if (sourceFunction != null) {
				matchInfo.setSourceLength((int) sourceFunction.getBody().getNumAddresses());
			}
			if (destFunction != null) {
				matchInfo.setDestinationLength((int) destFunction.getBody().getNumAddresses());
			}
		}
		else {
			CodeUnit cu = sourceProgram.getListing().getCodeUnitContaining(sourceAddress);
			if (cu != null) {
				matchInfo.setSourceLength(cu.getLength());
			}
			cu = destinationProgram.getListing().getCodeUnitContaining(destinationAddress);
			if (cu != null) {
				matchInfo.setDestinationLength(cu.getLength());
			}
		}
	}

	private static Reference findMatchingRef(RefType refType, Reference[] referencesFrom) {
		if (referencesFrom == null) {
			return null;
		}
		for (Reference reference : referencesFrom) {
			if (reference.getReferenceType() == refType) {
				return reference;
			}
		}
		return null;
	}

	/**
	 * Returns an existing match that best correlates to the implied match; returns null if no
	 * existing match can be found.
	 *
	 * @param impliedMatch The implied match for which to find a real match
	 * @param session The session to search for the match
	 * @return an existing match that best correlates to the implied match; returns null if no
	 * 			existing match can be found.
	 */
	public static VTMatch resolveImpliedMatch(VTImpliedMatchInfo impliedMatch, VTSession session) {
		VTAssociationManager associationManager = session.getAssociationManager();
		Address sourceAddress = impliedMatch.getSourceAddress();
		Address destinationAddress = impliedMatch.getDestinationAddress();
		VTAssociation existingAssociation =
			associationManager.getAssociation(sourceAddress, destinationAddress);

		if (existingAssociation != null) {
			VTMatch bestMatch = getBestMatch(existingAssociation, session);
			return bestMatch;
		}

		return null;
	}

	/**
	 * Given matches in an association, return the pair with the best similarity score
	 */
	private static VTMatch getBestMatch(VTAssociation association, VTSession session) {
		List<VTMatch> matches = session.getMatches(association);
		int n = matches.size();
		if (n == 0) {
			return null;
		}
		if (n == 1) {
			return matches.get(0);
		}
		VTMatch bestMatch = matches.get(0);
		VTScore bestScore = bestMatch.getSimilarityScore();
		for (VTMatch vtMatch : matches) {
			if (vtMatch.getSimilarityScore().compareTo(bestScore) > 0) {
				bestMatch = vtMatch;
				bestScore = bestMatch.getSimilarityScore();
			}
		}
		return bestMatch;
	}

	/**
	 * Returns the source function given a version tracking session and association pair
	 *
	 * @param session The Version Tracking session 
	 * @param association The association pair for a match
	 * @return the source function given a version tracking session and association pair
	 */
	public static Function getSourceFunction(VTSession session, VTAssociation association) {
		Program sourceProgram = session.getSourceProgram();
		Address sourceAddress = association.getSourceAddress();
		FunctionManager functionManager = sourceProgram.getFunctionManager();
		return functionManager.getFunctionAt(sourceAddress);
	}

	/**
	 * Returns the destination function given a version tracking session and association pair
	 *
	 * @param session The Version Tracking session 
	 * @param association The association pair for a match
	 * @return the destination function given a version tracking session and association pair
	 */
	public static Function getDestinationFunction(VTSession session, VTAssociation association) {
		Program destinationProgram = session.getDestinationProgram();
		Address destinationAddress = association.getDestinationAddress();
		FunctionManager functionManager = destinationProgram.getFunctionManager();
		return functionManager.getFunctionAt(destinationAddress);
	}
}
