/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.feature.vt.api.util;

import ghidra.feature.vt.api.impl.VTRelatedMatchImpl;
import ghidra.feature.vt.api.main.*;
import ghidra.feature.vt.gui.provider.relatedMatches.VTRelatedMatchCorrelationType;
import ghidra.feature.vt.gui.provider.relatedMatches.VTRelatedMatchType;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import java.util.*;

public class VTRelatedMatchUtil {

	public static Collection<VTRelatedMatch> getRelatedMatches(TaskMonitor monitor,
			VTSession session, VTMatch match) throws CancelledException {
		List<VTRelatedMatch> list = new ArrayList<VTRelatedMatch>();
		VTAssociation association = match.getAssociation();

		Program sourceProgram = session.getSourceProgram();
		Address sourceAddress = association.getSourceAddress();
		Function sourceFunction = sourceProgram.getListing().getFunctionAt(sourceAddress);
		if (sourceFunction == null) {
			return list;
		}
		Set<Address> sourceCallersOf = VTRelatedMatchUtil.getCallersOf(sourceFunction);
		Set<Address> sourceCalleesOf = VTRelatedMatchUtil.getCalleesOf(sourceFunction);

		Program destinationProgram = session.getDestinationProgram();
		Address destinationAddress = association.getDestinationAddress();
		Function destinationFunction =
			destinationProgram.getListing().getFunctionAt(destinationAddress);
		Set<Address> destinationCallersOf = VTRelatedMatchUtil.getCallersOf(destinationFunction);
		Set<Address> destinationCalleesOf = VTRelatedMatchUtil.getCalleesOf(destinationFunction);

		Listing sourceListing = sourceProgram.getListing();
		Listing destinationListing = destinationProgram.getListing();

		int matchCount = getMatchCount(session);
		monitor.setMessage("Searching for related matches");
		monitor.initialize(matchCount);

		List<VTMatchSet> matchSets = session.getMatchSets();
		for (VTMatchSet matchSet : matchSets) {
			Collection<VTMatch> matches = matchSet.getMatches();
			for (VTMatch otherMatch : matches) {
				monitor.checkCanceled();
				VTAssociation otherAssociation = otherMatch.getAssociation();
				VTAssociationStatus associationStatus = otherAssociation.getStatus();
				Address otherSourceAddress = otherAssociation.getSourceAddress();
				Address otherDestinationAddress = otherAssociation.getDestinationAddress();
				VTRelatedMatchCorrelationType sourceCorrelationType;
				VTRelatedMatchCorrelationType destinationCorrelationType;
				if (sourceCallersOf.contains(otherSourceAddress)) {
					sourceCorrelationType = VTRelatedMatchCorrelationType.CALLER;
				}
				else if (sourceCalleesOf.contains(otherSourceAddress)) {
					sourceCorrelationType = VTRelatedMatchCorrelationType.CALLEE;
				}
				else if (otherSourceAddress.equals(sourceAddress)) {
					sourceCorrelationType = VTRelatedMatchCorrelationType.TARGET;
				}
				else {
					sourceCorrelationType = VTRelatedMatchCorrelationType.UNRELATED;
				}
				if (destinationCallersOf.contains(otherDestinationAddress)) {
					destinationCorrelationType = VTRelatedMatchCorrelationType.CALLER;
				}
				else if (destinationCalleesOf.contains(otherDestinationAddress)) {
					destinationCorrelationType = VTRelatedMatchCorrelationType.CALLEE;
				}
				else if (otherDestinationAddress.equals(destinationAddress)) {
					destinationCorrelationType = VTRelatedMatchCorrelationType.TARGET;
				}
				else {
					destinationCorrelationType = VTRelatedMatchCorrelationType.UNRELATED;
				}
				VTRelatedMatchType relatedMatchType =
					VTRelatedMatchType.findMatchType(sourceCorrelationType,
						destinationCorrelationType, associationStatus);
				Function otherSourceFunction = sourceListing.getFunctionAt(otherSourceAddress);
				Function otherDestinationFunction =
					destinationListing.getFunctionAt(otherDestinationAddress);
				if (relatedMatchType != null && otherSourceFunction != null &&
					otherDestinationFunction != null) {
					list.add(new VTRelatedMatchImpl(relatedMatchType, otherSourceAddress,
						otherSourceFunction, otherDestinationAddress, otherDestinationFunction));
				}

				monitor.incrementProgress(1);
			}
		}

		return list;
	}

	private static int getMatchCount(VTSession session) {
		List<VTMatchSet> matchSets = session.getMatchSets();
		int count = 0;
		for (VTMatchSet matchSet : matchSets) {
			count += matchSet.getMatchCount();
		}
		return count;
	}

	public static Set<Address> getCalleesOf(Function function) {
		HashSet<Address> result = new HashSet<Address>();
		ReferenceManager referenceManager = function.getProgram().getReferenceManager();
		AddressSetView body = function.getBody();
		AddressIterator iterator = referenceManager.getReferenceSourceIterator(body, true);
		while (iterator.hasNext()) {
			Address address = iterator.next();
			Reference[] referencesFrom = referenceManager.getReferencesFrom(address);
			for (Reference reference : referencesFrom) {
				RefType refType = reference.getReferenceType();
				if (refType.isCall()) {
					result.add(reference.getToAddress());
				}
			}
		}
		return result;
	}

	public static Set<Address> getCallersOf(Function function) {
		HashSet<Address> result = new HashSet<Address>();
		ReferenceManager referenceManager = function.getProgram().getReferenceManager();
		Address entryPoint = function.getEntryPoint();
		ReferenceIterator referencesTo = referenceManager.getReferencesTo(entryPoint);
		Listing listing = function.getProgram().getListing();
		while (referencesTo.hasNext()) {
			Reference reference = referencesTo.next();
			Address fromAddress = reference.getFromAddress();
			Function referenceFunction = listing.getFunctionContaining(fromAddress);
			if (referenceFunction != null) {
				result.add(referenceFunction.getEntryPoint());
			}
		}
		return result;
	}
}
