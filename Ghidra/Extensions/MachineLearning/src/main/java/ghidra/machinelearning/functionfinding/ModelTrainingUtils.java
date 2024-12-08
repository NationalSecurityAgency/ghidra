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
package ghidra.machinelearning.functionfinding;

import java.util.*;

import org.tribuo.Example;
import org.tribuo.Feature;
import org.tribuo.classification.Label;
import org.tribuo.impl.ArrayExample;

import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * This is a utility class containing static methods used when creating training/test
 * sets to train models to recognize function starts
 */
public class ModelTrainingUtils {

	public static final int MAX_PRECEDING_CODE_UNIT_SIZE = 8;
	public static final double ZERO = 0.0d;
	public static final double ONE = 1.0d;

	//utility class
	private ModelTrainingUtils() {
	}

	/**
	 * Creates a feature vector consisting of byte-level and optionally bit-level features around 
	 * {@code address}
	 * @param program source program
	 * @param address address
	 * @param numPreBytes number of bytes to use preceding {@code address}
	 * @param numInitialBytes number of bytes to use including and after address
	 * @param includeBitFeatures whether to include bit-level features
	 * @return feature vector
	 */
	public static List<Feature> getFeatureVector(Program program, Address address, int numPreBytes,
			int numInitialBytes, boolean includeBitFeatures) {
		MemoryBlock block = program.getMemory().getBlock(address);
		byte[] preBytesArray = new byte[numPreBytes];
		byte[] initialBytesArray = new byte[numInitialBytes];
		List<Feature> trainingVector = new ArrayList<>();
		try {
			Address preStart = address.add(-numPreBytes);
			block.getBytes(preStart, preBytesArray);
			block.getBytes(address, initialBytesArray);
		}
		catch (MemoryAccessException | AddressOutOfBoundsException e) {
			//most likely an exception means that you are trying to read beyond a block
			//boundary.  This will happen occasionally when the sliding window is near the
			//begining or end of a block.  
			Msg.warn(RandomForestTrainingTask.class,
				"MemoryAccessException at " + address.toString());
			return trainingVector;
		}

		for (int i = 0; i < numPreBytes; i++) {
			int currentByte = Byte.toUnsignedInt(preBytesArray[i]);
			trainingVector.add(new Feature("pbyte_" + i, currentByte));
			if (!includeBitFeatures) {
				continue;
			}
			for (int bit = 7; bit >= 0; bit--) {
				String featureName = "pbit_" + i + "_" + bit;
				double val = ((currentByte & (1 << bit)) > 0) ? ONE : ZERO;
				trainingVector.add(new Feature(featureName, val));
			}
		}
		for (int i = 0; i < numInitialBytes; i++) {
			int currentByte = Byte.toUnsignedInt(initialBytesArray[i]);
			trainingVector.add(new Feature("ibyte_" + i, currentByte));
			if (!includeBitFeatures) {
				continue;
			}
			for (int bit = 7; bit >= 0; bit--) {
				String featureName = "ibit_" + i + "_" + bit;
				double val = ((currentByte & (1 << bit)) > 0) ? ONE : ZERO;
				trainingVector.add(new Feature(featureName, val));
			}
		}
		return trainingVector;
	}

	/**
	 * Returns an {@link AddressSet} constructed as follows: for each {@link Address} {@code addr} 
	 * in {@code addresses}, add the {@link Address} of the {@link CodeUnit} returned by 
	 * {@link Listing#getCodeUnitAfter(Address)}
	 * <p> Addresses which correspond to function starts are not added to the returned set.
	 * @param program source program
	 * @param addresses addresses to follow
	 * @param monitor monitor
	 * @return following addresses
	 * @throws CancelledException if the monitor is canceled
	 */
	public static AddressSet getFollowingAddresses(Program program, AddressSetView addresses,
			TaskMonitor monitor) throws CancelledException {
		AddressSet following = new AddressSet();
		for (Address addr : addresses.getAddresses(true)) {
			monitor.checkCancelled();
			CodeUnit cu = program.getListing().getCodeUnitAfter(addr);
			if (cu == null) {
				continue;
			}
			if (program.getFunctionManager().getFunctionAt(cu.getAddress()) != null) {
				Msg.warn(ModelTrainingUtils.class,
					"Function start following " + addr.toString() + ", skipping...");
				continue;
			}
			following.add(cu.getAddress());
		}
		return following;
	}

	/**
	 * Returns an {@link AddressSet} constructed as follows: for each {@link Address} {@code addr} 
	 * in {@code addresses}, add the {@link Address} of the {@link CodeUnit} returned by 
	 * {@link Listing#getCodeUnitBefore(Address)}
	 * <p> Addresses which correspond to function starts are not added to the returned set. 
	 * Addresses of {@link CodeUnit}s which are more than 
	 * {@link ModelTrainingUtils#MAX_PRECEDING_CODE_UNIT_SIZE} bytes away from the addresses they
	 * precede are also not added to the returned set.
	 * @param program source program
	 * @param addresses addresses to precede
	 * @param monitor monitor
	 * @return preceding addresses
	 * @throws CancelledException if the monitor is canceled
	 */
	public static AddressSet getPrecedingAddresses(Program program, AddressSetView addresses,
			TaskMonitor monitor) throws CancelledException {
		AddressSet preceding = new AddressSet();
		for (Address addr : addresses.getAddresses(true)) {
			monitor.checkCancelled();
			CodeUnit cu = program.getListing().getCodeUnitBefore(addr);
			if (cu == null) {
				continue;
			}
			if (program.getFunctionManager().getFunctionAt(cu.getAddress()) != null) {
				Msg.warn(ModelTrainingUtils.class,
					"Function start preceding " + addr.toString() + ", skipping...");
				continue;
			}
			if (addr.getOffset() - cu.getAddress().getOffset() > MAX_PRECEDING_CODE_UNIT_SIZE) {
				continue;
			}
			preceding.add(cu.getAddress());
		}
		return preceding;
	}

	/**
	 * Returns an {@link AddressSet} consisting of all {@link Address}es where data is defined
	 * in {@code program}.  Note that this includes addresses within defined data and not just
	 * addresses where defined data starts.
	 * @param program source program
	 * @param monitor task monitor
	 * @return addresses where data is defined
	 * @throws CancelledException if monitor is canceled
	 */
	public static AddressSet getDefinedData(Program program, TaskMonitor monitor)
			throws CancelledException {
		DataIterator dataIter =
			program.getListing().getDefinedData(program.getMemory().getExecuteSet(), true);
		AddressSet definedData = new AddressSet();
		for (Data d : dataIter) {
			monitor.checkCancelled();
			definedData.add(
				new AddressRangeImpl(d.getAddress(), d.getAddress().add(d.getLength() - 1)));
		}
		return definedData;
	}

	/**
	 * Generates a feature vector for every address in {@code source} and applies the {@Label}
	 * {@code label}
	 * 
	 * @param program program
	 * @param source input addresses
	 * @param label label to apply
	 * @param numPreBytes bytes before address to include
	 * @param numInitialBytes bytes after and including addresses
	 * @param includeBitFeatures whether to include bit-level features
	 * @param monitor monitor 
	 * @return list of vectors
	 * @throws CancelledException if monitor is canceled
	 */
	public static List<Example<Label>> getVectorsFromAddresses(Program program,
			AddressSetView source, Label label, int numPreBytes, int numInitialBytes,
			boolean includeBitFeatures, TaskMonitor monitor) throws CancelledException {
		List<Example<Label>> examples = new ArrayList<>();
		monitor.initialize(source.getNumAddresses());
		Iterator<Address> addressIter = source.getAddresses(true);
		while (addressIter.hasNext()) {
			monitor.checkCancelled();
			Address addr = addressIter.next();
			monitor.incrementProgress(1L);
			List<Feature> trainingVector =
				getFeatureVector(program, addr, numPreBytes, numInitialBytes, includeBitFeatures);
			if (trainingVector.isEmpty()) {
				continue;
			}
			ArrayExample<Label> vec = new ArrayExample<>(label, trainingVector);
			examples.add(vec);
		}
		return examples;
	}

}
