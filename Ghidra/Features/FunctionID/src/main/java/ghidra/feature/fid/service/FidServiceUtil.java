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
package ghidra.feature.fid.service;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;

import java.util.HashSet;
import java.util.Set;

/**
 * Utility functions for the FID service.
 */
public class FidServiceUtil {

	/**
	 * Computes the parent functions of a function (who calls me?).
	 * @param function the target function
	 * @return a set of functions that call the target function
	 */
	static Set<Function> computeParents(Function function) {
		HashSet<Function> results = new HashSet<Function>();
		Program program = function.getProgram();
		FunctionManager functionManager = program.getFunctionManager();
		ReferenceManager referenceManager = program.getReferenceManager();
		ReferenceIterator referencesTo = referenceManager.getReferencesTo(function.getEntryPoint());
		for (Reference reference : referencesTo) {
			if (reference.getReferenceType().isCall()) {
				Function parent = functionManager.getFunctionContaining(reference.getFromAddress());
				if (parent != null) {
					results.add(parent);
				}
			}
		}
		return results;
	}

	/**
	 * Computes the child functions of a function (who do I call?).
	 * @param function the target function
	 * @return a set of functions that the target function calls
	 */
	static Set<Function> computeChildren(Function function) {
		HashSet<Function> results = new HashSet<Function>();
		Program program = function.getProgram();
		FunctionManager functionManager = program.getFunctionManager();
		ReferenceManager referenceManager = program.getReferenceManager();
		AddressIterator referenceIterator =
			referenceManager.getReferenceSourceIterator(function.getBody(), true);
		for (Address address : referenceIterator) {
			Reference[] referencesFrom = referenceManager.getReferencesFrom(address);
			for (Reference reference : referencesFrom) {
				if (reference.getReferenceType().isCall()) {
					Function child = functionManager.getFunctionAt(reference.getToAddress());
					if (child != null) {
						results.add(child);
					}
				}
			}
		}
		return results;
	}
}
