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

import java.math.BigInteger;
import java.util.*;
import java.util.stream.Collectors;

import org.apache.commons.lang3.StringUtils;

import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * This is a container class for the parameters that determine what data is collected for
 * training random forests to recognize function starts.
 */

public class FunctionStartRFParams {

	private List<Integer> preBytes;          //number of bytes before a function start
	private List<Integer> initialBytes;      //number of bytes after (and including) the first byte 
	private List<Integer> samplingFactors;   //how many non-starts to gather for each start gathered
	private int minFuncSize;                 //minimum size of a function to mine
	private int maxStarts;                   //maximum number of function starts to gather
	private Program trainingSource;
	private AddressSet funcEntries;
	private AddressSet funcInteriors;
	private int instructionAlignment;
	private boolean includePrecedingAndFollowing;
	private boolean includeBitFeatures;

	//the following two lists are related: they must have the same size, and the ith
	//entry in contextRegisterVals is the value of the ith element of contextRegisterNames
	private List<String> contextRegisterNames; //names of context registers we care about
	private List<BigInteger> contextRegisterVals; //values of context registers we care about

	/**
	 * Constructs a FunctionStartRFParams object, a container object for data gathering
	 * parameters to use when training a random forest to recognize function starts.  
	 * 
	 * <p> Note that {@code randomSeed} is initialized to a random value. 
	 * 
	 * <p>Use setter methods to set the fields.
	 * @param trainingSource source program
	 */
	public FunctionStartRFParams(Program trainingSource) {
		this.trainingSource = trainingSource;
		preBytes = Collections.emptyList();
		initialBytes = Collections.emptyList();
		samplingFactors = Collections.emptyList();
		contextRegisterNames = Collections.emptyList();
		contextRegisterVals = Collections.emptyList();
		instructionAlignment = trainingSource.getLanguage().getInstructionAlignment();
	}

	/**
	 * 
	 * @return the number of bytes to gather before an address
	 */
	public List<Integer> getPreBytes() {
		return preBytes;
	}

	/**
	 * 
	 * @param preBytes the number of bytes to gather before an address
	 */
	public void setPreBytes(List<Integer> preBytes) {
		this.preBytes = preBytes;
	}

	/**
	 * 
	 * @return the number of bytes to gather after (and including) an address
	 */
	public List<Integer> getInitialBytes() {
		return initialBytes;
	}

	/**
	 * 
	 * @param initialBytes the number of bytes to gather after (and including) an address
	 */
	public void setInitialBytes(List<Integer> initialBytes) {
		this.initialBytes = initialBytes;
	}

	/**
	 * 
	 * @return the minimum size a function must be to have its data gathered
	 */
	public int getMinFuncSize() {
		return minFuncSize;
	}

	/**
	 * 
	 * @param minFuncSize the minimum size a function must be to have its data gathered
	 */
	public void setMinFuncSize(int minFuncSize) {
		this.minFuncSize = minFuncSize;
	}

	/**
	 * 
	 * @return the maximum number of function starts to gather
	 */
	public int getMaxStarts() {
		return maxStarts;
	}

	/**
	 * 
	 * @param max the maximum number of function starts to gather
	 */
	public void setMaxStarts(int max) {
		maxStarts = max;
	}

	/**
	 * 
	 * @return the number of non-starts to gather per function start
	 */
	public List<Integer> getSamplingFactors() {
		return samplingFactors;
	}

	/**
	 * 
	 * @param factors the number of non-starts to gather per function start
	 */
	public void setFactors(List<Integer> factors) {
		samplingFactors = factors;
	}

	/**
	 * Returns true precisely when there is a least one context register value set.
	 * @return true if there are any context register values set
	 */
	public boolean isRestrictedByContext() {
		return !contextRegisterNames.isEmpty();
	}

	/**
	 * 
	 * @return the list of names of context registers to set before disassembly
	 */
	public List<String> getContextRegisterNames() {
		return contextRegisterNames;
	}

	/**
	 * The values to assign to the context registers.
	 * @return context register values
	 */
	public List<BigInteger> getContextRegisterVals() {
		return contextRegisterVals;
	}

	/**
	 * Parses register,value pairs if the form creg1=x,creg2=from csv and stores them.  Any 
	 * existing register,value pairs are discarded.
	 * 
	 * @param csv the list to parse
	 * @throws IllegalArgumentException if there are any parsing errors
	 */
	public void setRegistersAndValues(String csv) {
		contextRegisterNames = new ArrayList<>();
		contextRegisterVals = new ArrayList<>();
		String[] parts = csv.split(",");
		for (String part : parts) {
			String[] regValPair = part.split("=");
			if (regValPair.length != 2) {
				contextRegisterNames.clear();
				contextRegisterVals.clear();
				throw new IllegalArgumentException("Error parsing register=value string " + part);
			}
			String regName = regValPair[0].trim();
			if (trainingSource.getRegister(regName) == null) {
				contextRegisterNames.clear();
				contextRegisterVals.clear();
				throw new IllegalArgumentException(
					"Register " + regName + " not found for program " + trainingSource.getName());
			}
			contextRegisterNames.add(regName);
			BigInteger bigInt = new BigInteger(regValPair[1].trim());
			contextRegisterVals.add(bigInt);
		}
	}

	/**
	 * Parses a CSV into a sorted list of distinct integer values (duplicates are ignored).  Returns
	 * an empty list of a parse error is encountered.
	 * @param csv csv string to parse
	 * @return sorted list  
	 */
	public static List<Integer> parseIntegerCSV(String csv) {
		if (StringUtils.isBlank(csv)) {
			throw new IllegalArgumentException("Entry cannot be blank");
		}
		String trimmed = csv.trim();
		if (trimmed.startsWith(",") || trimmed.endsWith(",")) {
			throw new IllegalArgumentException("String must not begin or end with a comma");
		}
		Set<Integer> results = new HashSet<>();
		String[] parts = trimmed.split(",");
		for (String part : parts) {
			Integer i = Integer.decode(part.trim());
			if (i < 0) {
				throw new IllegalArgumentException(
					"Invalid element " + part + " - must be non-negative");
			}
			results.add(i);
		}
		return results.stream().sorted().collect(Collectors.toList());
	}

	/**
	 * Returns the {@link AddressSet} of function entries in the source program.
	 * <P>
	 * NB: Invoke {@link FunctionStartRFParams#computeFuncEntriesAndInteriors} before
	 * invoking this method.
	 * @return set of entries
	 */
	public AddressSet getFuncEntries() {
		return funcEntries;
	}

	/**
	 * Returns the {@link AddressSet} of function interiors in the source program.
	 * <P>
	 * NB: Invoke {@link FunctionStartRFParams#computeFuncEntriesAndInteriors} before
	 * invoking this method.
	 * @return set of interiors
	 */
	public AddressSet getFuncInteriors() {
		return funcInteriors;
	}

	/**
	 * Returns boolean indicating whether code units immediately preceding and
	 * following a function start should be included in the training set.
	 * @return include preceding and following
	 */
	public boolean getIncludePrecedingAndFollowing() {
		return includePrecedingAndFollowing;
	}

	/**
	 * Sets boolean indicating whether code units immediately preceding and
	 * following a function start should be included in the training set.
	 * @param b new value
	 */
	public void setIncludePrecedingAndFollowing(boolean b) {
		includePrecedingAndFollowing = b;
	}

	/**
	 * Returns boolean indicating whether to include bit-level features in the feature vectors.
	 * @return include bit level features
	 */
	public boolean getIncludeBitFeatures() {
		return includeBitFeatures;
	}

	/**
	 * Sets boolean indicating whether to include bit-level features in the feature vectors.
	 * @param b new value
	 */
	public void setIncludeBitFeatures(boolean b) {
		includeBitFeatures = b;
	}

	/**
	 * Computes the {@link AddressSet}s of function entries and bodies in the source program.  
	 * Retrieve these sets via {@link FunctionStartRFParams#getFuncEntries()} and 
	 * {@link FunctionStartRFParams#getFuncInteriors()}
	 * <p> Note: the interior of a function only contains addresses which are aligned relative
	 * to the instruction alignment of the processor
	 * @param monitor task monitor
	 * @throws CancelledException if monitor is canceled
	 */
	public void computeFuncEntriesAndInteriors(TaskMonitor monitor) throws CancelledException {
		FunctionIterator fIter = trainingSource.getFunctionManager().getFunctions(true);
		monitor.initialize(trainingSource.getFunctionManager().getFunctionCount());
		funcEntries = new AddressSet();
		funcInteriors = new AddressSet();
		while (fIter.hasNext()) {
			monitor.checkCancelled();
			Function func = fIter.next();
			monitor.incrementProgress(1);
			if (func.getBody().getNumAddresses() < minFuncSize) {
				continue;
			}
			if (isRestrictedByContext()) {
				if (!isContextCompatible(func.getEntryPoint())) {
					continue;
				}
			}
			funcEntries.add(func.getEntryPoint());
			AddressSet body = func.getBody().subtract(new AddressSet(func.getEntryPoint()));
			AddressIterator addrIter = body.getAddresses(true);
			while (addrIter.hasNext()) {
				Address addr = addrIter.next();
				if (addr.getOffset() % instructionAlignment == 0) {
					funcInteriors.add(addr);
				}
			}
		}
	}

	/**
	 * Checks whether {@code addr} is consistent with context register values
	 * supplied via {@link FunctionStartRFParams#setRegistersAndValues(String)}
	 * @param addr address to check
	 * @return is consistent with context regs
	 */
	public boolean isContextCompatible(Address addr) {
		ProgramContext context = trainingSource.getProgramContext();
		for (int i = 0; i < contextRegisterNames.size(); i++) {
			Register reg = context.getRegister(contextRegisterNames.get(i));
			BigInteger val = context.getValue(reg, addr, false);
			if (!val.equals(contextRegisterVals.get(i))) {
				return false;
			}
		}
		return true;
	}

}
