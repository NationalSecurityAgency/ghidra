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
package ghidra.app.util.pdb.pdbapplicator;

import java.util.*;

import ghidra.app.util.SymbolPath;
import ghidra.app.util.bin.format.pdb2.pdbreader.AbstractTypeProgramInterface;
import ghidra.app.util.bin.format.pdb2.pdbreader.RecordNumber;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Two-way Maps forward references with corresponding definitions for composites and enums.
 * Uses the forward reference and definition members of the AbstractComplexTypeApplier.
 */
// We have probably tried 5 or more ways of doing this, all with mixed results.  The current
//  implementation seems to yield the best results at the moment.  Keeping some of the old code
//  around until we are solid on our algorithm and until we document some of the various algorithms
//  tried.
public class ComplexTypeApplierMapper {

	private PdbApplicator applicator;

//	private Map<SymbolPath, AbstractComplexTypeApplier> complexTypeAppliersBySymbolPath;
	private Map<SymbolPath, LinkedList<AbstractComplexTypeApplier>> compositeAppliersQueueBySymbolPath;
	private Map<SymbolPath, LinkedList<AbstractComplexTypeApplier>> enumAppliersQueueBySymbolPath;

	//==============================================================================================
	public ComplexTypeApplierMapper(PdbApplicator applicator) {
		Objects.requireNonNull(applicator, "applicator cannot be null");
		this.applicator = applicator;
//		complexTypeAppliersBySymbolPath = new HashMap<>();
		compositeAppliersQueueBySymbolPath = new HashMap<>();
		enumAppliersQueueBySymbolPath = new HashMap<>();
	}

	//==============================================================================================
	//==============================================================================================
	void mapAppliers(TaskMonitor monitor) throws CancelledException {
		AbstractTypeProgramInterface typeProgramInterface =
			applicator.getPdb().getTypeProgramInterface();
		if (typeProgramInterface == null) {
			return;
		}
		int indexLimit = typeProgramInterface.getTypeIndexMaxExclusive();
		int indexNumber = typeProgramInterface.getTypeIndexMin();
		monitor.initialize(indexLimit - indexNumber);
		applicator.setMonitorMessage("PDB: Mapping Composites...");
		while (indexNumber < indexLimit) {
			monitor.checkCanceled();
			//PdbResearch.checkBreak(indexNumber);
			MsTypeApplier applier =
				applicator.getTypeApplier(RecordNumber.typeRecordNumber(indexNumber++));
			// From real data, we know that an enum and a composite both had the same SymbolPath,
			//  so enums and composites must be maintained separately so they do not get matched
			//  with each other.
			if (applier instanceof CompositeTypeApplier) {
//				mapComplexApplierBySymbolPath(compositeAppliersFwdRefQueueBySymbolPath,
//					(AbstractComplexTypeApplier) applier);
				mapComplexApplierTwoWayBySymbolPath(compositeAppliersQueueBySymbolPath,
					(AbstractComplexTypeApplier) applier);
			}
			else if (applier instanceof EnumTypeApplier) {
//				mapComplexApplierBySymbolPath(enumAppliersFwdRefQueueBySymbolPath,
//					(AbstractComplexTypeApplier) applier);
				mapComplexApplierTwoWayBySymbolPath(enumAppliersQueueBySymbolPath,
					(AbstractComplexTypeApplier) applier);
			}
//			if (applier instanceof AbstractComplexTypeApplier) {
//				mapComplexApplierByQueue((AbstractComplexTypeApplier) applier);
//				//mapComplexApplierForwardOnly((AbstractComplexTypeApplier) applier);
//				//mapComplexApplier((AbstractComplexTypeApplier) applier);
//			}
			monitor.incrementProgress(1);
		}
	}

	private void mapComplexApplierTwoWayBySymbolPath(
			Map<SymbolPath, LinkedList<AbstractComplexTypeApplier>> applierQueueBySymbolPath,
			AbstractComplexTypeApplier complexApplier) {
		SymbolPath symbolPath = complexApplier.getSymbolPath();
		Objects.requireNonNull(symbolPath, "SymbolPath may not be null");

		LinkedList<AbstractComplexTypeApplier> appliers = applierQueueBySymbolPath.get(symbolPath);
		if (appliers == null) {
			appliers = new LinkedList<>();
			applierQueueBySymbolPath.put(symbolPath, appliers);
			// Putting forward reference or definition (doesn't matter which it is)
			if (!appliers.add(complexApplier)) {
				// Error
			}
		}
		else if (appliers.peekFirst().isForwardReference() == complexApplier.isForwardReference()) {
			// Only need to look at first on list, as all on list are the same forward reference
			// of definition.
			// If same as what is on list, add to the list.
			if (!appliers.add(complexApplier)) {
				// Error
			}
		}
		else {
			if (complexApplier.isForwardReference()) {
				AbstractComplexTypeApplier definitionApplier = appliers.removeFirst();
				definitionApplier.setForwardReferenceApplier(complexApplier);
				complexApplier.setDefinitionApplier(definitionApplier);
			}
			else {
				AbstractComplexTypeApplier forwardReferenceApplier = appliers.removeFirst();
				forwardReferenceApplier.setDefinitionApplier(complexApplier);
				complexApplier.setForwardReferenceApplier(forwardReferenceApplier);
			}
			if (appliers.isEmpty()) {
				// Do not need to keep all of these around.
				applierQueueBySymbolPath.remove(symbolPath);
			}
		}
	}

//	private void mapComplexApplier(AbstractComplexTypeApplier complexApplier) {
//		SymbolPath symbolPath = complexApplier.getSymbolPath();
//
//		AbstractComplexTypeApplier cachedComplexApplier =
//			getComplexTypeApplierBySymbolPath(symbolPath, complexApplier.getClass());
//		if (cachedComplexApplier == null) {
//			// Setting cache if not already set or setting to definition.
//			putComplexTypeApplierBySymbolPath(symbolPath, complexApplier);
//		}
//		else if (cachedComplexApplier.isForwardReference()) {
//			if (!complexApplier.isForwardReference()) {
//				cachedComplexApplier.setDefinitionApplier(complexApplier);
//				complexApplier.setFwdRefApplier(cachedComplexApplier);
//			}
//			// Setting cache to new applier, whether fwd ref or definition.
//			putComplexTypeApplierBySymbolPath(symbolPath, complexApplier);
//		}
//		else { // cached is definition
//			if (!complexApplier.isForwardReference()) { // we are definition
//				// Setting cache if not already set or setting to definition.
//				putComplexTypeApplierBySymbolPath(symbolPath, complexApplier);
//			}
//			else { // we are forward ref
//				AbstractComplexTypeApplier fwdRef =
//					cachedComplexApplier.getFwdRefApplier(complexApplier.getClass());
//				if (fwdRef == null) {
//					// cached definition did not have a forward ref but we are one, so hook it up?
//					// problem is if a definition follows... ugh. Not sure want to do this.
//					complexApplier.setDefinitionApplier(cachedComplexApplier);
//					cachedComplexApplier.setFwdRefApplier(complexApplier);
//					// would like to cache a forward ref, but are are tying it to a previous
//					// definition, so not.
//				}
//				else {
//					// Setting cache if not already set or setting to definition.
//					putComplexTypeApplierBySymbolPath(symbolPath, complexApplier);
//				}
//			}
//		}
//	}
//
//	// Only caching forward ref and then mapping only following def to forward reference.
//	//  Clearing cache after that def so next def does not map.
//	private void mapComplexApplierForwardOnly(AbstractComplexTypeApplier complexApplier) {
//		SymbolPath symbolPath = complexApplier.getSymbolPath();
//
//		if (complexApplier.isForwardReference()) {
//			putComplexTypeApplierBySymbolPath(symbolPath, complexApplier);
//		}
//		else {
//			AbstractComplexTypeApplier cachedComplexApplier =
//				getComplexTypeApplierBySymbolPath(symbolPath, complexApplier.getClass());
//			if (cachedComplexApplier != null) {
//				cachedComplexApplier.setDefinitionApplier(complexApplier);
//				complexApplier.setFwdRefApplier(cachedComplexApplier);
//				// set cache back to null
//				complexTypeAppliersBySymbolPath.remove(symbolPath);
//			}
//		}
//	}
//
//	private void putComplexTypeApplierBySymbolPath(SymbolPath symbolPath,
//			AbstractComplexTypeApplier applier) {
//		Objects.requireNonNull(symbolPath, "SymbolPath may not be null");
//		Objects.requireNonNull(applier, "CompositeTypeApplier may not be null");
//		complexTypeAppliersBySymbolPath.put(symbolPath, applier);
//	}
//
//	private <T extends AbstractComplexTypeApplier> T getComplexTypeApplierBySymbolPath(
//			SymbolPath symbolPath, Class<T> typeClass) {
//		Objects.requireNonNull(symbolPath, "SymbolPath may not be null");
//		Objects.requireNonNull(typeClass, "typeClass may not be null");
//		AbstractComplexTypeApplier applier = complexTypeAppliersBySymbolPath.get(symbolPath);
//		if (!typeClass.isInstance(applier)) {
//			return null;
//		}
//		return typeClass.cast(applier);
//	}
//
//	//==============================================================================================
//	private void mapComplexApplierBySymbolPath(
//			Map<SymbolPath, LinkedList<AbstractComplexTypeApplier>> applierQueueBySymbolPath,
//			AbstractComplexTypeApplier complexApplier) {
//		SymbolPath symbolPath = complexApplier.getSymbolPath();
//		Objects.requireNonNull(symbolPath, "SymbolPath may not be null");
//
//		LinkedList<AbstractComplexTypeApplier> fwdList = applierQueueBySymbolPath.get(symbolPath);
//		if (fwdList == null) {
//			fwdList = new LinkedList<>();
//			applierQueueBySymbolPath.put(symbolPath, fwdList);
//		}
//
//		if (complexApplier.isForwardReference()) {
//			if (!fwdList.add(complexApplier)) {
//				// Error
//			}
//		}
//		else if (!fwdList.isEmpty()) {
//			AbstractComplexTypeApplier fwdApplier = fwdList.removeFirst();
//			fwdApplier.setDefinitionApplier(complexApplier);
//			complexApplier.setFwdRefApplier(fwdApplier);
//		}
//	}
//

}
