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
package ghidra.feature.vt.api.correlator.program;

import java.util.*;
import java.util.Map.Entry;

import generic.DominantPair;
import generic.lsh.KandL;
import generic.lsh.LSHMemoryModel;
import generic.lsh.vector.LSHCosineVectorAccum;
import generic.lsh.vector.VectorCompare;
import ghidra.feature.vt.api.main.*;
import ghidra.feature.vt.api.util.VTAbstractProgramCorrelator;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class SimilarSymbolNameProgramCorrelator extends VTAbstractProgramCorrelator {

	public static double SIMILARITY_THRESHOLD = 0.5;

	protected SimilarSymbolNameProgramCorrelator(ServiceProvider serviceProvider,
			Program sourceProgram, AddressSetView sourceAddressSet, Program destinationProgram,
			AddressSetView destinationAddressSet, ToolOptions options) {
		super(serviceProvider, sourceProgram, sourceAddressSet, destinationProgram,
			destinationAddressSet, options);
	}

	HashMap<Symbol, LSHCosineVectorAccum> sourceMap;
	HashMap<Symbol, LSHCosineVectorAccum> destinationMap;

	HashMap<String, Integer> idMap;

	int featureID = 0;
	int minNameLength;

	@Override
	protected void doCorrelate(VTMatchSet matchSet, TaskMonitor monitor) throws CancelledException {
		minNameLength =
			getOptions().getInt(SimilarSymbolNameProgramCorrelatorFactory.MIN_NAME_LENGTH,
				SimilarSymbolNameProgramCorrelatorFactory.MIN_NAME_LENGTH_DEFAULT);

		LSHMultiHash<Symbol> sourceDictionary;
		monitor.setMessage("Generating source dictionary");
		sourceDictionary = generateDictionary(getSourceProgram(), matchSet, monitor);

		monitor.setMessage("Finding destination symbols");
		findDestinations(matchSet, sourceDictionary, SIMILARITY_THRESHOLD, monitor);
	}

	private void extractNGramFeatures(VTMatchSet matchSet, TaskMonitor monitor, int n) {
		sourceMap = new HashMap<Symbol, LSHCosineVectorAccum>();
		destinationMap = new HashMap<Symbol, LSHCosineVectorAccum>();
		idMap = new HashMap<String, Integer>();

		final Program sourceProgram = getSourceProgram();
		final Program destinationProgram = getDestinationProgram();

		final SymbolTable sourceSymbolTable = sourceProgram.getSymbolTable();
		final SymbolTable destinationSymbolTable = destinationProgram.getSymbolTable();

		SymbolIterator sourceSymbols = sourceSymbolTable.getAllSymbols(false);
		SymbolIterator destinationSymbols = destinationSymbolTable.getAllSymbols(false);

		addSymbolsToMap(sourceSymbols, true, n, monitor);
		addSymbolsToMap(destinationSymbols, false, n, monitor);
	}

	private void addSymbolsToMap(SymbolIterator symbolIt, boolean isSourceProgram, int n,
			TaskMonitor monitor) {
		double weight = 1.0 / n;
		AddressSetView addressSet;
		if (isSourceProgram) {
			addressSet = getSourceAddressSet();
		}
		else {
			addressSet = getDestinationAddressSet();
		}
		while (symbolIt.hasNext()) {
			if (monitor.isCancelled()) {
				break;
			}
			Symbol symbol = symbolIt.next();
			String symbolName = symbol.getName();

			if (symbolName.length() < minNameLength) {
				continue;
			}
			if (!addressSet.contains(symbol.getAddress())) {
				continue;
			}
			if (symbol.getSource() == SourceType.DEFAULT ||
				symbol.getSource() == SourceType.ANALYSIS) {
				continue;
			}

			for (int i = 0; i < symbolName.length() - (n - 1); i++) {
				String threeGram = symbolName.substring(i, i + n);
				LSHCosineVectorAccum vector;
				if (isSourceProgram) {
					vector = sourceMap.get(symbol);
				}
				else {
					vector = destinationMap.get(symbol);
				}
				if (vector == null) {
					vector = new LSHCosineVectorAccum();
					if (isSourceProgram) {
						sourceMap.put(symbol, vector);
					}
					else {
						destinationMap.put(symbol, vector);
					}
				}
				int id = getFeatureID(threeGram);
				vector.addHash(id, weight);
			}
		}
	}

	private int getFeatureID(String threeGram) {
		if (idMap.containsKey(threeGram)) {
			return idMap.get(threeGram);
		}
		featureID++;
		idMap.put(threeGram, featureID);
		return featureID;
	}

	private LSHMultiHash<Symbol> generateDictionary(Program program, VTMatchSet matchSet,
			final TaskMonitor monitor) {
		final LSHMultiHash<Symbol> dictionary = generateLSHMultiHash();
		extractNGramFeatures(matchSet, monitor, 3);
		dictionary.add(sourceMap, monitor);
		return dictionary;
	}

	private void findDestinations(VTMatchSet matchSet, LSHMultiHash<Symbol> sourceDictionary,
			double threshold, TaskMonitor monitor) {
		monitor.initialize(destinationMap.size());
		for (Entry<Symbol, LSHCosineVectorAccum> entry : destinationMap.entrySet()) {
			if (monitor.isCancelled()) {
				return;
			}
			monitor.incrementProgress(1);
			Symbol destinationSymbol = entry.getKey();
			LSHCosineVectorAccum vector = entry.getValue();
			Set<DominantPair<Symbol, LSHCosineVectorAccum>> neighbors =
				sourceDictionary.lookup(vector);
			List<VTMatchInfo> members =
				transform(matchSet, destinationSymbol, vector, neighbors, threshold, monitor);
			for (VTMatchInfo member : members) {
				if (monitor.isCancelled()) {
					return;
				}
				if (member != null) {
					matchSet.addMatch(member);
				}
			}
		}
	}

	private List<VTMatchInfo> transform(VTMatchSet matchSet, Symbol destinationSymbol,
			LSHCosineVectorAccum destinationVector,
			Set<DominantPair<Symbol, LSHCosineVectorAccum>> neighbors, double threshold,
			TaskMonitor monitor) {
		List<VTMatchInfo> result = new ArrayList<VTMatchInfo>();
		int sourceLength = 0;
		int destinationLength = 0;

		Address destinationAddress = destinationSymbol.getAddress();
		FunctionManager destinationFunctionManager = getDestinationProgram().getFunctionManager();
		Function destinationFunction = destinationFunctionManager.getFunctionAt(destinationAddress);
		CodeUnit destinationCodeUnit = null;
		VectorCompare veccompare = new VectorCompare();
		if (destinationFunction == null) {
			destinationCodeUnit =
				getDestinationProgram().getListing().getCodeUnitAt(destinationAddress);
			if (destinationCodeUnit == null) {
				return result;
			}
		}
		if (destinationFunction != null && destinationFunction.isThunk()) {
			return result;
		}

		for (DominantPair<Symbol, LSHCosineVectorAccum> neighbor : neighbors) {
			if (monitor.isCancelled()) {
				break;
			}
			Symbol sourceSymbol = neighbor.first;
			Address sourceAddress = sourceSymbol.getAddress();

			VTAssociationType type;

			FunctionManager sourceFunctionManager = getSourceProgram().getFunctionManager();
			Function sourceFunction = sourceFunctionManager.getFunctionAt(sourceAddress);
			if (destinationFunction != null) {
				if (sourceFunction == null || sourceFunction.isThunk()) {
					continue;
				}
				type = VTAssociationType.FUNCTION;
				sourceLength = (int) sourceFunction.getBody().getNumAddresses();
				destinationLength = (int) destinationFunction.getBody().getNumAddresses();
			}
			else {
				if (sourceFunction != null) {
					continue;
				}
				CodeUnit sourceCodeUnit =
					getSourceProgram().getListing().getCodeUnitAt(sourceAddress);
				if (sourceCodeUnit == null) {
					continue;
				}
				type = VTAssociationType.DATA;
				sourceLength = sourceCodeUnit.getLength();
				destinationLength = destinationCodeUnit.getLength();
			}

			LSHCosineVectorAccum sourceVector = neighbor.second;

			double similarity = sourceVector.compare(destinationVector, veccompare);

			if (similarity < threshold || Double.isNaN(similarity)) {
				continue;
			}

			double confidence =
				similarity * sourceVector.getLength() * destinationVector.getLength();

			confidence *= 10.0;

			VTMatchInfo match = new VTMatchInfo(matchSet);

			match.setSimilarityScore(new VTScore(similarity));
			match.setConfidenceScore(new VTScore(confidence));
			match.setSourceLength(sourceLength);
			match.setDestinationLength(destinationLength);
			match.setSourceAddress(sourceAddress);
			match.setDestinationAddress(destinationAddress);
			match.setTag(null);
			match.setAssociationType(type);

			result.add(match);
		}

		return result;
	}

	private LSHMultiHash<Symbol> generateLSHMultiHash() {
		LSHMemoryModel model =
			getOptions().getEnum(SimilarSymbolNameProgramCorrelatorFactory.MEMORY_MODEL,
				SimilarSymbolNameProgramCorrelatorFactory.MEMORY_MODEL_DEFAULT);
		int L = KandL.memoryModelToL(model);
		return new LSHMultiHash<Symbol>(model.getK(), L);
	}

	@Override
	public String getName() {
		return SimilarSymbolNameProgramCorrelatorFactory.NAME;
	}
}
