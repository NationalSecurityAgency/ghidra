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
import ghidra.app.util.SymbolPathParser;
import ghidra.app.util.bin.format.pdb2.pdbreader.TypeProgramInterface;
import ghidra.app.util.bin.format.pdb2.pdbreader.type.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Maps forward references with corresponding definitions for composites and enums.  Map is of
 * record number (index) to record number (index)--always of TYPE RecordCategory, as we are not
 * expecting Complex type records numbers to be mapped from ITEM RecordCategory lists. We are
 * always creating a map of higher number to lower number, as we are assuming that processing
 * will be done in an increasing-record-number order.
 *
 * (This class is Based off of ComplexTypeApplierMapper, which would get eliminated if we find
 * success down this path.)
 */
// We have probably tried 5 or more ways of doing this, all with mixed results.  The current
//  implementation seems to yield the best results at the moment.  Keeping some of the old code
//  around until we are solid on our algorithm and until we document some of the various algorithms
//  tried.
public class ComplexTypeMapper {

	private Map<Integer, Integer> map;

	//==============================================================================================
	public ComplexTypeMapper() {
		map = new HashMap<>();
	}

//	/**
//	 * Returns map to alternate record number or argument record number if no map.  Result is
//	 *  record number of alternative record for the complex type.  It should be the lower of the
//	 *  two numbers for the set of fwdref and def records, with the fwdref generally, but not
//	 *  always, the lower-numbered record.
//	 * @param recordNumber the record number for which to do the lookup
//	 * @return the mapped number
//	 */
	/**
	 * Returns map to alternate record number or argument record number if no map.  Result is
	 *  record number of alternative record for the complex type.  Map is of fwdref to definition
	 *  numbers.  The fwdref number is generally, but not always, the lower number
	 * @param recordNumber the record number for which to do the lookup
	 * @return the mapped number
	 */
	public Integer getMapped(int recordNumber) {
		return map.getOrDefault(recordNumber, recordNumber);
	}

	// Temporary method while switching over processing mechanisms and still using
	//  ComplexTypeApplierMapper (vs. this ComplexTypeMapper).
	@Deprecated
	Map<Integer, Integer> getMap() {
		return map;
	}

	// Storing type (isFwd or isDef) so that if we decide to parse Types on demand, we will not
	// have to parse it again to see if it is a fwdref or def.
	private record NumFwdRef(int number, boolean isFwd) {}

	//==============================================================================================
	//==============================================================================================
	public void mapTypes(PdbApplicator applicator) throws CancelledException {
		Objects.requireNonNull(applicator, "applicator cannot be null");

		TypeProgramInterface typeProgramInterface = applicator.getPdb().getTypeProgramInterface();
		if (typeProgramInterface == null) {
			return;
		}

		// Purely using these LinkedLists for FIFO queues for matching next available forward
		//  reference with next available definition.  Need a separate FIFO for composites vs.
		//  enums, as a label can be used for both a composite and for an enum.  But we do not
		//  need four FIFOs (which would be one each for forward reference and definition for
		//  each of composites and enums) because the fwdref and def use the same FIFO.
		//  Each FIFO will either have all forward references or all definitions at any given
		//  time.  If, for example it only has forward references and another forward reference
		//  is seen in the input stream, it is just pushed onto the FIFO, but if a definition is
		//  seen next in the input stream, then the that definition gets matched with the first
		//  record in the FIFO (which gets peeled off the FIFO).  This continues as long as
		//  more definitions come in the input stream.  If the FIFO empties of forward references,
		//  and another definition is found in the input stream, then the FIFO starts storing
		//  definitions instead.
		// Specifically using LinkedList in Map, as not all Queues are appropriate
		//  (e.g., PriorityQueue).
		Map<SymbolPath, LinkedList<NumFwdRef>> compositeFIFOsByPath = new HashMap<>();
		Map<SymbolPath, LinkedList<NumFwdRef>> enumFIFOsByPath = new HashMap<>();

		// Map is used for combo of Composites and Enums, but the FIFOs above had to be
		//  separated (or get complicated in other ways by adding more to the FIFO values).
		map = new HashMap<>();

		int indexLimit = typeProgramInterface.getTypeIndexMaxExclusive();
		int indexNumber = typeProgramInterface.getTypeIndexMin();
		TaskMonitor monitor = applicator.getMonitor();
		monitor.initialize(indexLimit - indexNumber);
		monitor.setMessage("PDB: Mapping Complex Types...");
		while (indexNumber < indexLimit) {
			monitor.checkCancelled();
			// Getting explicit type with no worrying about remapping of TYPE to ITEM or ITEM
			// to TYPE as we could get using applicator.getPdb().getTypeRecord(recordNumber)
			// where recordNumber is a RecordNumber.  This is because we are not expecting
			// a remap for Complex types.
			AbstractMsType type = typeProgramInterface.getRecord(indexNumber);
			if (type instanceof AbstractCompositeMsType compositeType) {
				mapComplexTypesByPath(compositeFIFOsByPath, indexNumber, compositeType);
			}
			else if (type instanceof AbstractEnumMsType enumType) {
				mapComplexTypesByPath(enumFIFOsByPath, indexNumber, enumType);
			}
			indexNumber++;
			monitor.incrementProgress(1);
		}
	}

	// Always mapping higher index to lower index, as we are assuming we will processing indices
	// in an increasing order later.
	private void mapComplexTypesByPath(Map<SymbolPath, LinkedList<NumFwdRef>> typeFIFOsByPath,
			int indexNumber, AbstractComplexMsType complexType) {

		SymbolPath symbolPath = new SymbolPath(SymbolPathParser.parse(complexType.getName()));
		boolean isFwdRef = complexType.getMsProperty().isForwardReference();

		LinkedList<NumFwdRef> numTypeFIFO = typeFIFOsByPath.get(symbolPath);
		if (numTypeFIFO == null) {
			numTypeFIFO = new LinkedList<>();
			typeFIFOsByPath.put(symbolPath, numTypeFIFO);

			// Putting forward reference or definition (doesn't matter which it is)
			if (!numTypeFIFO.add(new NumFwdRef(indexNumber, isFwdRef))) {
				// Error
			}
		}
		else {
			NumFwdRef firstNumFwdRef = numTypeFIFO.peekFirst();

			// If same in FIFO, then add to bottom of the FIFO, as all records on this FIFO
			//  will be the same per this algorithm.
			if (firstNumFwdRef.isFwd() == isFwdRef) {
				if (!numTypeFIFO.add(new NumFwdRef(indexNumber, isFwdRef))) {
					// Error
				}
			}
			else {
				numTypeFIFO.removeFirst();

				// ORIGINAL THOUGHT AND CODE
				// It doesn't matter now if first is fwdref and second is def or vice versa, as we
				//  are always storing the new incoming (larger) index as the key and the existing
				//  index as the value
				//map.put(indexNumber, firstNumFwdRef.number());

				// NEW THOUGHT AND CODE
				// Here we are always mapping fwdref to definition.  This is because there are
				//  times when we need the definition record number to be part of the fixed
				//  symbol path and we need the fwdref symbol path to be the same.  Thus we
				//  want to be able to have ready access to the def record.
				if (isFwdRef) {
					map.put(indexNumber, firstNumFwdRef.number());
//					// Following is just temporary during development to compare with
//					//  previous mapping capability.  TODO remove
//					System.out.println(String.format("%d %s %d -> %d",
//					(complexType instanceof AbstractEnumMsType) ? 1 : 0, symbolPath.toString(),
//					indexNumber, firstNumFwdRef.number()));
				}
				else {
					map.put(firstNumFwdRef.number(), indexNumber);
//					// Following is just temporary during development to compare with
//					//  previous mapping capability.  TODO remove
//					System.out.println(String.format("%d %s %d <- %d",
//					(complexType instanceof AbstractEnumMsType) ? 1 : 0, symbolPath.toString(),
//					firstNumFwdRef.number(), indexNumber));
				}

				// Do not need to keep all of these around.  Might come back but will regenerate
				if (numTypeFIFO.isEmpty()) {
					typeFIFOsByPath.remove(symbolPath);
				}
			}
		}
	}

}
