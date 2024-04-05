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
package ghidra.feature.vt.api.correlator.address;

import java.util.*;
import java.util.Map.Entry;

import ghidra.app.decompiler.*;
import ghidra.codecompare.graphanalysis.Pinning;
import ghidra.codecompare.graphanalysis.TokenBin;
import ghidra.program.model.address.*;
import ghidra.program.model.block.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.util.*;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class CodeCompareAddressCorrelation implements AddressCorrelation {
	static enum CorrelationKind {
		CODE_COMPARE, LCS, PARAMETERS;
	}

	static class CorrelationContainer {
		public static boolean USE_RANDOM_CC_COLORS = false;
		public final CorrelationKind kind;
		public final AddressRange range;

		public CorrelationContainer(CorrelationKind kind, AddressRange range) {
			this.kind = kind;
			this.range = range;
		}
	}

	private static final int TIMEOUT_SECONDS = 60;

	private final Function sourceFunction;
	private final Function destinationFunction;
	private final Program sourceProgram;
	private final Program destinationProgram;

	private Map<Address, CorrelationContainer> cachedForwardAddressMap;

	public CodeCompareAddressCorrelation(Function sourceFunction, Function destinationFunction) {
		this.sourceFunction = sourceFunction;
		this.destinationFunction = destinationFunction;
		this.sourceProgram = sourceFunction.getProgram();
		this.destinationProgram = destinationFunction.getProgram();

		DebugUtils.enable(false); // Set to "true" to enable debugging or "false" to disable.
	}

	@Override
	public AddressRange getCorrelatedDestinationRange(Address sourceAddress, TaskMonitor monitor)
			throws CancelledException {
		initialize(monitor);

		CorrelationContainer container = cachedForwardAddressMap.get(sourceAddress);
		if (container == null) {
			return null;
		}
		return container.range;
	}

	private static final Comparator<CodeUnit> CUCOMPARATOR = new Comparator<CodeUnit>() {
		@Override
		public int compare(CodeUnit o1, CodeUnit o2) {
			return o1.getAddress().compareTo(o2.getAddress());
		}
	};

	private void initialize(TaskMonitor monitor) throws CancelledException {
		if (cachedForwardAddressMap == null) {
			cachedForwardAddressMap = new HashMap<Address, CorrelationContainer>();

			HashMap<Address, Address> sourceToDestinationPairings = new HashMap<Address, Address>();
			HashMap<Address, Address> destinationToSourcePairings = new HashMap<Address, Address>();

			AddressSet sourceSet = new AddressSet();
			AddressSet destinationSet = new AddressSet();

			TreeMap<CodeUnit, TreeSet<AddressRange>> sourceMap =
				new TreeMap<CodeUnit, TreeSet<AddressRange>>(CUCOMPARATOR);
			TreeMap<CodeUnit, TreeSet<AddressRange>> destinationMap =
				new TreeMap<CodeUnit, TreeSet<AddressRange>>(CUCOMPARATOR);

			processCodeCompare(monitor, sourceToDestinationPairings, destinationToSourcePairings,
				sourceSet, destinationSet, sourceMap, destinationMap);

			// now, if we're on the same architecture, try to LCS the
			// interstices between our golden matches

			if (sourceFunction.getProgram()
					.getLanguage()
					.getProcessor()
					.equals(destinationFunction.getProgram().getLanguage().getProcessor())) {
				processLCSBlocks(monitor, sourceToDestinationPairings, sourceSet, destinationSet,
					sourceMap, destinationMap);
			}

			DebugUtils.processMap(sourceMap, sourceProgram);
			DebugUtils.processMap(destinationMap, destinationProgram);

			DebugUtils.colorize(cachedForwardAddressMap, sourceProgram, destinationProgram);
		}
	}

	private void processCodeCompare(TaskMonitor monitor,
			HashMap<Address, Address> sourceToDestinationPairings,
			HashMap<Address, Address> destinationToSourcePairings, AddressSet sourceSet,
			AddressSet destinationSet, Map<CodeUnit, TreeSet<AddressRange>> sourceMap,
			Map<CodeUnit, TreeSet<AddressRange>> destinationMap) throws CancelledException {
		// compute the mapping by means of code compare

		DecompInterface sourceDecompiler = null;
		DecompInterface destinationDecompiler = null;

		try {
			sourceDecompiler = new DecompInterface();
			destinationDecompiler = new DecompInterface();

			sourceDecompiler.openProgram(sourceProgram);
			destinationDecompiler.openProgram(destinationProgram);

			DecompileResults sourceResults =
				sourceDecompiler.decompileFunction(sourceFunction, TIMEOUT_SECONDS, monitor);
			DecompileResults destinationResults = destinationDecompiler
					.decompileFunction(destinationFunction, TIMEOUT_SECONDS, monitor);

			ClangTokenGroup sourceMarkup = sourceResults.getCCodeMarkup();
			ClangTokenGroup destinationMarkup = destinationResults.getCCodeMarkup();

			HighFunction sourceHFunc = sourceResults.getHighFunction();
			HighFunction destinationHFunc = destinationResults.getHighFunction();
			String errorMessage = "";
			if (sourceHFunc == null) {
				errorMessage += (" Source Decompiler failed to get function. " +
					sourceResults.getErrorMessage());
			}
			if (destinationHFunc == null) {
				errorMessage += (" Destination Decompiler failed to get function. " +
					destinationResults.getErrorMessage());
			}
			if (!errorMessage.isEmpty()) {
				// For now throw a RuntimeException to see what failed in the decompiler, 
				// otherwise we will just get a NullPointerException.
				throw new RuntimeException(errorMessage);
			}

			boolean matchConstantsExactly = false;
			int srcsize = sourceProgram.getLanguage().getLanguageDescription().getSize();
			int destsize = destinationProgram.getLanguage().getLanguageDescription().getSize();
			boolean sizeCollapse = (srcsize != destsize);
			Pinning pin = Pinning.makePinning(sourceHFunc, destinationHFunc, matchConstantsExactly,
				sizeCollapse, true, monitor);
			ArrayList<TokenBin> highBins = pin.buildTokenMap(sourceMarkup, destinationMarkup);

			for (TokenBin tokenBin : highBins) {
				if (tokenBin.getMatch() == null || tokenBin.getMatch().size() != tokenBin.size()) {
					continue;
				}
				boolean isSourceBin = tokenBin.getHighFunction().equals(sourceHFunc);

				for (int ii = 0; ii < tokenBin.size(); ++ii) {
					ClangToken binToken = tokenBin.get(ii);
					ClangToken sidekickToken = tokenBin.getMatch().get(ii);

					ClangToken sourceToken = isSourceBin ? binToken : sidekickToken;
					ClangToken destinationToken = isSourceBin ? sidekickToken : binToken;

					Address srcStart = sourceToken.getMinAddress();
					Address srcEnd = sourceToken.getMaxAddress();

					Address destStart = destinationToken.getMinAddress();
					Address destEnd = destinationToken.getMaxAddress();

					if (destStart == null || destEnd == null || srcStart == null ||
						srcEnd == null) {
						continue;
					}
					AddressSet sourceIntersection = sourceSet.intersectRange(srcStart, srcEnd);
					AddressSet destinationIntersection =
						destinationSet.intersectRange(destStart, destEnd);

					if (!sourceIntersection.isEmpty() || !destinationIntersection.isEmpty()) {
						continue;
					}

					DebugUtils.recordEOLComment(sourceMap, sourceProgram, srcStart, srcEnd,
						destinationProgram, destStart, destEnd);
					DebugUtils.recordEOLComment(destinationMap, destinationProgram, destStart,
						destEnd, sourceProgram, srcStart, srcEnd);

					sourceSet.addRange(srcStart, srcEnd);
					destinationSet.addRange(destStart, destEnd);

					sourceToDestinationPairings.put(srcStart, destStart);
					destinationToSourcePairings.put(destStart, srcStart);

					AddressRangeImpl range = new AddressRangeImpl(destStart, destEnd);
					CorrelationContainer container =
						new CorrelationContainer(CorrelationKind.CODE_COMPARE, range);

					// Assign container to all addresses: srcStart to srcEnd inclusive
					while (!srcStart.equals(srcEnd)) {
						cachedForwardAddressMap.put(srcStart, container);
						srcStart = srcStart.addNoWrap(1);
					}
					cachedForwardAddressMap.put(srcStart, container);
				}
			}
		}
		catch (AddressOverflowException e) {
			Msg.error(this,
				"Unexpected address overflow; token's range didn't span continguous region", e);
		}
		finally {
			if (sourceDecompiler != null) {
				sourceDecompiler.dispose();
			}
			if (destinationDecompiler != null) {
				destinationDecompiler.dispose();
			}
		}
	}

	private void processLCSBlocks(TaskMonitor monitor,
			HashMap<Address, Address> sourceToDestinationPairings, AddressSet sourceSet,
			AddressSet destinationSet, Map<CodeUnit, TreeSet<AddressRange>> sourceMap,
			Map<CodeUnit, TreeSet<AddressRange>> destinationMap) throws CancelledException {
		CodeBlockModel sourceBlockModel = new BasicBlockModel(sourceProgram);
		CodeBlockModel destinationBlockModel = new BasicBlockModel(destinationProgram);

		Listing sourceListing = sourceProgram.getListing();
		Listing destinationListing = destinationProgram.getListing();

		Set<Entry<Address, Address>> entrySet = sourceToDestinationPairings.entrySet();
		for (Entry<Address, Address> entry : entrySet) {
			Address sourceAddress = entry.getKey();
			Address destinationAddress = entry.getValue();

			CodeBlock[] sourceBlocks =
				sourceBlockModel.getCodeBlocksContaining(sourceAddress, monitor);
			CodeBlock[] destinationBlocks =
				destinationBlockModel.getCodeBlocksContaining(destinationAddress, monitor);

			if (sourceBlocks != null && destinationBlocks != null) {
				if (sourceBlocks.length == 1 && destinationBlocks.length == 1) {
					// work backwards

					CodeUnitIterator sourceCodeUnitIterator =
						sourceListing.getCodeUnits(sourceAddress, false);
					CodeUnitIterator destinationCodeUnitIterator =
						destinationListing.getCodeUnits(destinationAddress, false);

					processLCSCodeUnits(monitor, sourceSet, destinationSet, sourceMap,
						destinationMap, sourceCodeUnitIterator, destinationCodeUnitIterator);

					// now work forwards
					sourceCodeUnitIterator = sourceListing.getCodeUnits(sourceAddress, true);
					destinationCodeUnitIterator =
						destinationListing.getCodeUnits(destinationAddress, true);

					processLCSCodeUnits(monitor, sourceSet, destinationSet, sourceMap,
						destinationMap, sourceCodeUnitIterator, destinationCodeUnitIterator);
				}
			}
		}
	}

	private void processLCSCodeUnits(TaskMonitor monitor, AddressSet sourceSet,
			AddressSet destinationSet, Map<CodeUnit, TreeSet<AddressRange>> sourceMap,
			Map<CodeUnit, TreeSet<AddressRange>> destinationMap,
			CodeUnitIterator sourceCodeUnitIterator, CodeUnitIterator destinationCodeUnitIterator)
			throws CancelledException {
		// get rid of the codeUnit we already have
		if (sourceCodeUnitIterator.hasNext()) {
			sourceCodeUnitIterator.next();
		}

		// get rid of the codeUnit we already have								
		if (destinationCodeUnitIterator.hasNext()) {
			destinationCodeUnitIterator.next();
		}

		processLCS(sourceMap, destinationMap, sourceSet, destinationSet, sourceCodeUnitIterator,
			destinationCodeUnitIterator, monitor);
	}

	private void processLCS(Map<CodeUnit, TreeSet<AddressRange>> sourceMap,
			Map<CodeUnit, TreeSet<AddressRange>> destinationMap, AddressSet sourceSet,
			AddressSet destinationSet, CodeUnitIterator sourceCodeUnitIterator,
			CodeUnitIterator destinationCodeUnitIterator, TaskMonitor monitor)
			throws CancelledException {
		List<CodeUnitContainer> source = (sourceFunction != null)
				? getCodeUnits(sourceFunction, sourceSet, sourceCodeUnitIterator)
				: new ArrayList<CodeUnitContainer>();
		List<CodeUnitContainer> destination = (destinationFunction != null)
				? getCodeUnits(destinationFunction, destinationSet, destinationCodeUnitIterator)
				: new ArrayList<CodeUnitContainer>();
		CodeUnitLCS culcs = new CodeUnitLCS(source, destination);
		List<CodeUnitContainer> lcs = culcs.getLcs(monitor);
		final int lcsSize = lcs.size();
		int sourceII = 0;
		int lcsII = 0;
		int destinationII = 0;

		monitor.setMessage("Defining address ranges...");
		monitor.initialize(lcsSize);

		int sourceTransactionID = -1;
		int destinationTransactionID = -1;

		try {
			sourceTransactionID =
				sourceFunction.getProgram().startTransaction("Colorize CodeCompare");
			destinationTransactionID =
				destinationFunction.getProgram().startTransaction("Colorize CodeCompare");

			while (lcsII < lcsSize) {
				monitor.checkCancelled();
				CodeUnitContainer sourceCodeUnit = source.get(sourceII);
				CodeUnitContainer lcsCodeUnit = lcs.get(lcsII);
				CodeUnitContainer destinationCodeUnit = destination.get(destinationII);
				final boolean sourceCompare = culcs.matches(sourceCodeUnit, lcsCodeUnit);
				final boolean destinationCompare = culcs.matches(lcsCodeUnit, destinationCodeUnit);
				if (sourceCompare == destinationCompare) {
					// either they're both equal to lcs item or they're both different
					if (sourceCompare) {
						// they're both equal, define the ranges
						defineRange(sourceMap, destinationMap, sourceCodeUnit, destinationCodeUnit);
						// increment the lcs index because everything matched
						++lcsII;
					}
					// in any case, increment both the source and destination indexes
					// because they were either both the same or both different
					++sourceII;
					++destinationII;
				}
				else if (sourceCompare) {
					// destination has extra stuff (new code added)
					++destinationII;
				}
				else if (destinationCompare) {
					// source has extra stuff (old code deleted)
					++sourceII;
				}
				else {
					// can't get here!
					throw new RuntimeException("internal error");
				}

				monitor.incrementProgress(1);
			}
		}
		finally {
			if (sourceTransactionID != -1) {
				sourceFunction.getProgram().endTransaction(sourceTransactionID, true);
			}
			if (destinationTransactionID != -1) {
				destinationFunction.getProgram().endTransaction(destinationTransactionID, true);
			}
		}
		computeParamCorrelation();
	}

	private void computeParamCorrelation() {
		Parameter[] sourceParameters = sourceFunction.getParameters();
		Parameter[] destinationParameters = destinationFunction.getParameters();
		if (sourceParameters.length != destinationParameters.length) {
			return;
		}
		Map<Address, CorrelationContainer> map = new HashMap<Address, CorrelationContainer>();
		for (int i = 0; i < sourceParameters.length; i++) {
			Parameter sourceParameter = sourceParameters[i];
			Parameter destinationParameter = destinationParameters[i];
			if (!sourceParameter.isValid() || !destinationParameter.isValid()) {
				return;
			}
			VariableStorage sourceParamStorage = sourceParameter.getVariableStorage();
			VariableStorage destParamStorage = destinationParameter.getVariableStorage();
			if (!sourceParamStorage.equals(destParamStorage)) {
				return;
			}
			Address dest = sourceParamStorage.getMinAddress();
			Address src = destParamStorage.getMinAddress();
			map.put(src, new CorrelationContainer(CorrelationKind.PARAMETERS,
				new AddressRangeImpl(dest, dest)));
		}
		cachedForwardAddressMap.putAll(map);
	}

	private void defineRange(Map<CodeUnit, TreeSet<AddressRange>> sourceMap,
			Map<CodeUnit, TreeSet<AddressRange>> destinationMap, CodeUnitContainer sourceCodeUnit,
			CodeUnitContainer destinationCodeUnit) {
		Address minAddress = sourceCodeUnit.getCodeUnit().getMinAddress();
		Address maxAddress = sourceCodeUnit.getCodeUnit().getMaxAddress();
		AddressRangeImpl toRange =
			new AddressRangeImpl(destinationCodeUnit.getCodeUnit().getMinAddress(),
				destinationCodeUnit.getCodeUnit().getMaxAddress());
		CorrelationContainer container = new CorrelationContainer(CorrelationKind.LCS, toRange);

		DebugUtils.recordEOLComment(sourceMap, sourceProgram, minAddress, maxAddress,
			destinationProgram, destinationCodeUnit.getCodeUnit().getMinAddress(),
			destinationCodeUnit.getCodeUnit().getMaxAddress());
		DebugUtils.recordEOLComment(destinationMap, destinationProgram,
			destinationCodeUnit.getCodeUnit().getMinAddress(),
			destinationCodeUnit.getCodeUnit().getMaxAddress(), sourceProgram, minAddress,
			maxAddress);

		while (!minAddress.equals(maxAddress)) {
			cachedForwardAddressMap.put(minAddress, container);
			minAddress = minAddress.next();
		}
		cachedForwardAddressMap.put(maxAddress, container);
	}

	private static List<CodeUnitContainer> getCodeUnits(Function function,
			AddressSetView correlations, CodeUnitIterator codeUnits) {
		AddressSetView body = function.getBody();
		ArrayList<CodeUnitContainer> result = new ArrayList<CodeUnitContainer>();
		while (codeUnits.hasNext()) {
			CodeUnit next = codeUnits.next();
			Address address = next.getAddress();
			if (correlations.contains(address) || !body.contains(address)) {
				break;
			}
			result.add(new CodeUnitContainer(next));
		}
		return result;
	}

	@Override
	public String getName() {
		return "CodeCompareAddressCorrelator";
	}
}
