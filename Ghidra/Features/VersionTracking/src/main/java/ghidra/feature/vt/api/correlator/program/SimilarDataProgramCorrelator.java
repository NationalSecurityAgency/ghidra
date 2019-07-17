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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map.Entry;
import java.util.Set;

import generic.DominantPair;
import generic.hash.FNV1a64MessageDigest;
import generic.hash.MessageDigest;
import generic.lsh.KandL;
import generic.lsh.LSHMemoryModel;
import generic.lsh.vector.LSHCosineVectorAccum;
import generic.lsh.vector.VectorCompare;
import ghidra.feature.vt.api.main.VTAssociationType;
import ghidra.feature.vt.api.main.VTMatchInfo;
import ghidra.feature.vt.api.main.VTMatchSet;
import ghidra.feature.vt.api.main.VTScore;
import ghidra.feature.vt.api.util.VTAbstractProgramCorrelator;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class SimilarDataProgramCorrelator extends VTAbstractProgramCorrelator {

	public static final double SIMILARITY_THRESHOLD = 0.5;

	protected SimilarDataProgramCorrelator(ServiceProvider serviceProvider, Program sourceProgram,
			AddressSetView sourceAddressSet, Program destinationProgram,
			AddressSetView destinationAddressSet, ToolOptions options) {
		super(serviceProvider, sourceProgram, sourceAddressSet, destinationProgram,
			destinationAddressSet, options);
	}

	HashMap<Address, LSHCosineVectorAccum> sourceMap;
	HashMap<Address, LSHCosineVectorAccum> destinationMap;

	HashMap<Long, Integer> idMap;

	int featureID = 0;
	int minDataLength;

	@Override
	protected void doCorrelate(VTMatchSet matchSet, TaskMonitor monitor) throws CancelledException {
		minDataLength =
			getOptions().getInt(SimilarDataProgramCorrelatorFactory.MIN_NAME_LENGTH,
				SimilarDataProgramCorrelatorFactory.MIN_NAME_LENGTH_DEFAULT);
		boolean skipHomogenousData =
			getOptions().getBoolean(SimilarDataProgramCorrelatorFactory.SKIP_HOMOGENOUS_DATA,
				SimilarDataProgramCorrelatorFactory.SKIP_HOMOGENOUS_DATA_DEFAULT);

		LSHMultiHash<Address> sourceDictionary;
		monitor.setMessage("Generating source dictionary");
		sourceDictionary =
			generateDictionary(getSourceProgram(), matchSet, skipHomogenousData, monitor);

		monitor.setMessage("Finding destination data");
		findDestinations(matchSet, sourceDictionary, SIMILARITY_THRESHOLD, monitor);
	}

	private LSHMultiHash<Address> generateDictionary(Program sourceProgram, VTMatchSet matchSet,
			boolean skipHomogenousData, TaskMonitor monitor) throws CancelledException {
		final LSHMultiHash<Address> dictionary = generateLSHMultiHash();
		extractNGramFeatures(matchSet, skipHomogenousData, monitor, 4);
		dictionary.add(sourceMap, monitor);
		return dictionary;
	}

	private void extractNGramFeatures(VTMatchSet matchSet, boolean skipHomogenousData,
			TaskMonitor monitor, int n) throws CancelledException {
		sourceMap = new HashMap<Address, LSHCosineVectorAccum>();
		destinationMap = new HashMap<Address, LSHCosineVectorAccum>();
		idMap = new HashMap<Long, Integer>();

		final Program sourceProgram = getSourceProgram();
		final Program destinationProgram = getDestinationProgram();

		DataIterator sourceDataIterator =
			sourceProgram.getListing().getDefinedData(getSourceAddressSet(), true);
		DataIterator destinationDataIterator =
			destinationProgram.getListing().getDefinedData(getDestinationAddressSet(), true);

		addDataToMap(sourceDataIterator, true, skipHomogenousData, n, monitor);
		addDataToMap(destinationDataIterator, false, skipHomogenousData, n, monitor);
	}

	private void addDataToMap(DataIterator dataIt, boolean isSourceProgram,
			boolean skipHomogenousData, int n, TaskMonitor monitor) throws CancelledException {
		double weight = 1.0 / n;
		AddressSetView addressSet;
		if (isSourceProgram) {
			addressSet = getSourceAddressSet();
		}
		else {
			addressSet = getDestinationAddressSet();
		}
		MessageDigest digest = new FNV1a64MessageDigest();
		while (dataIt.hasNext()) {
			if (monitor.isCancelled()) {
				break;
			}

			Data data = dataIt.next();
			int length = data.getLength();

			if (length < minDataLength) {
				continue;
			}
			Address address = data.getAddress();
			if (!addressSet.contains(address)) {
				continue;
			}

			byte[] allBytes;
			try {
				allBytes = data.getBytes();
			}
			catch (MemoryAccessException e1) {
				continue;
			}
			if (isRepeating(allBytes, monitor) && skipHomogenousData) {
				continue;
			}

			byte[] bytes = new byte[n];
			for (int i = 0; i < data.getLength() - (n - 1); i++) {
				if (monitor.isCancelled()) {
					break;
				}
				LSHCosineVectorAccum vector;
				if (data.getBytes(bytes, i) != n) {
					throw new RuntimeException("failed to read vector data at " + address);
				}
				if (isSourceProgram) {
					vector = sourceMap.get(address);
				}
				else {
					vector = destinationMap.get(address);
				}
				if (vector == null) {
					vector = new LSHCosineVectorAccum();
					if (isSourceProgram) {
						sourceMap.put(address, vector);
					}
					else {
						destinationMap.put(address, vector);
					}
				}

				digest.update(bytes, monitor);
				long hash = digest.digestLong();
				int id = getFeatureID(hash);
				vector.addHash(id, weight);
			}
		}
	}

	private static boolean isRepeating(byte[] bytes, TaskMonitor monitor) {
		byte first = bytes[0];
		for (int ii = 1; ii < bytes.length; ++ii) {
			if (monitor.isCancelled()) {
				return true;
			}
			if (bytes[ii] != first) {
				return false;
			}
		}
		return true;
	}

	private int getFeatureID(long hash) {
		if (idMap.containsKey(hash)) {
			return idMap.get(hash);
		}
		featureID++;
		idMap.put(hash, featureID);
		return featureID;
	}

	private void findDestinations(VTMatchSet matchSet, LSHMultiHash<Address> sourceDictionary,
			double threshold, TaskMonitor monitor) {
		monitor.initialize(destinationMap.size());

		for (Entry<Address, LSHCosineVectorAccum> entry : destinationMap.entrySet()) {
			if (monitor.isCancelled()) {
				return;
			}

			monitor.incrementProgress(1);
			Address destinationAddress = entry.getKey();
			LSHCosineVectorAccum vector = entry.getValue();
			Set<DominantPair<Address, LSHCosineVectorAccum>> neighbors =
				sourceDictionary.lookup(vector);
			List<VTMatchInfo> members =
				transform(matchSet, destinationAddress, vector, neighbors, threshold, monitor);

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

	private List<VTMatchInfo> transform(VTMatchSet matchSet, Address destinationAddress,
			LSHCosineVectorAccum destinationVector,
			Set<DominantPair<Address, LSHCosineVectorAccum>> neighbors, double threshold,
			TaskMonitor monitor) {
		List<VTMatchInfo> result = new ArrayList<VTMatchInfo>();

		Listing sourceListing = getSourceProgram().getListing();
		Listing destinationListing = getDestinationProgram().getListing();
		VectorCompare veccompare = new VectorCompare();

		for (DominantPair<Address, LSHCosineVectorAccum> neighbor : neighbors) {
			if (monitor.isCancelled()) {
				break;
			}

			Address sourceAddress = neighbor.first;

			LSHCosineVectorAccum sourceVector = neighbor.second;

			double similarity = sourceVector.compare(destinationVector, veccompare);

			if (similarity < threshold || Double.isNaN(similarity)) {
				continue;
			}

			double confidence =
				similarity * sourceVector.getLength() * destinationVector.getLength();

			confidence *= 10;

			int sourceLength = getDataLength(sourceListing, sourceAddress);
			int destinationLength = getDataLength(destinationListing, destinationAddress);

			VTMatchInfo match = new VTMatchInfo(matchSet);

			match.setSimilarityScore(new VTScore(similarity));
			match.setConfidenceScore(new VTScore(confidence));
			match.setSourceLength(sourceLength);
			match.setDestinationLength(destinationLength);
			match.setSourceAddress(sourceAddress);
			match.setDestinationAddress(destinationAddress);
			match.setTag(null);
			match.setAssociationType(VTAssociationType.DATA);

			result.add(match);
		}

		return result;
	}

	private static int getDataLength(Listing listing, Address address) {
		Data data = listing.getDataAt(address);
		return data.getLength();
	}

	private LSHMultiHash<Address> generateLSHMultiHash() {
		LSHMemoryModel model =
			getOptions().getEnum(SimilarDataProgramCorrelatorFactory.MEMORY_MODEL,
				SimilarDataProgramCorrelatorFactory.MEMORY_MODEL_DEFAULT);
		int L = KandL.memoryModelToL(model);
		return new LSHMultiHash<Address>(model.getK(), L);
	}

	@Override
	public String getName() {
		return SimilarDataProgramCorrelatorFactory.NAME;
	}
}
