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

import java.awt.Color;
import java.util.*;
import java.util.Map.Entry;

import ghidra.app.util.viewer.listingpanel.PropertyBasedBackgroundColorModel;
import ghidra.feature.vt.api.correlator.address.CodeCompareAddressCorrelation.CorrelationContainer;
import ghidra.program.database.IntRangeMap;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;

class DebugUtils {

	private static boolean ENABLED = false;

	static void recordEOLComment(Map<CodeUnit, TreeSet<AddressRange>> map, Program fromProgram,
			Address startAddress, Address endAddress, Program toProgram, Address minAddress,
			Address maxAddress) {

		if (isEnabled()) {
			Listing listing = fromProgram.getListing();
			AddressSet addrSet = new AddressSet(startAddress, endAddress);
			CodeUnitIterator codeUnits = listing.getCodeUnits(addrSet, true);
			AddressRange range = new AddressRangeImpl(minAddress, maxAddress);

			while (codeUnits.hasNext()) {
				CodeUnit codeUnit = codeUnits.next();
				TreeSet<AddressRange> set = map.get(codeUnit);
				if (set == null) {
					set = new TreeSet<AddressRange>();
					map.put(codeUnit, set);
				}
				set.add(range);
			}
		}
	}

	static void processMap(Map<CodeUnit, TreeSet<AddressRange>> map, Program program) {
		if (isEnabled()) {
			int transactionID = -1;
			try {
				transactionID = program.startTransaction("Colorize CodeCompare");
				Set<Entry<CodeUnit, TreeSet<AddressRange>>> entrySet = map.entrySet();
				for (Entry<CodeUnit, TreeSet<AddressRange>> entry : entrySet) {
					entry.getKey().setComment(CodeUnit.EOL_COMMENT, entry.getValue().toString());
				}
			}
			finally {
				if (transactionID != -1) {
					program.endTransaction(transactionID, true);
				}
			}
		}
	}

	static void colorize(Map<Address, CorrelationContainer> map, Program sourceProgram,
			Program destinationProgram) {
		if (isEnabled()) {
			int sourceTransactionID = -1;
			int destinationTransactionID = -1;
			try {
				Listing sourceListing = sourceProgram.getListing();
				Listing destinationListing = destinationProgram.getListing();

				sourceTransactionID = sourceProgram.startTransaction("Colorize CodeCompare");
				destinationTransactionID =
					destinationProgram.startTransaction("Colorize CodeCompare");

				Set<Entry<Address, CorrelationContainer>> entrySet = map.entrySet();
				for (Entry<Address, CorrelationContainer> entry : entrySet) {
					Address sourceAddress = entry.getKey();
					CorrelationContainer container = entry.getValue();
					Color color = pickColor(container);
					colorCodeUnits(sourceProgram, color, getCodeUnit(sourceListing, sourceAddress));
					colorCodeUnits(destinationProgram, color,
						getCodeUnits(destinationListing, container.range));
				}
			}
			finally {
				if (sourceTransactionID != -1) {
					sourceProgram.endTransaction(sourceTransactionID, true);
				}
				if (destinationTransactionID != -1) {
					destinationProgram.endTransaction(destinationTransactionID, true);
				}
			}
		}
	}

	private static CodeUnit getCodeUnit(Listing listing, Address address) {
		return listing.getCodeUnitContaining(address);
	}

	private static CodeUnit[] getCodeUnits(Listing listing, AddressRange addressRange) {
		HashSet<CodeUnit> units = new HashSet<CodeUnit>();
		Address address = addressRange.getMinAddress();
		Address maxAddress = addressRange.getMaxAddress();
		while (!address.equals(maxAddress)) {
			CodeUnit codeUnit = listing.getCodeUnitContaining(address);
			units.add(codeUnit);
			try {
				address = address.addNoWrap(1);
			}
			catch (AddressOverflowException e) {
				Msg.debug(DebugUtils.class, "Woah...non-contiguous CodeBlock", e);
				break;
			}
		}
		CodeUnit codeUnit = listing.getCodeUnitContaining(maxAddress);
		units.add(codeUnit);
		return units.toArray(new CodeUnit[0]);
	}

	private static void colorCodeUnits(Program program, Color color, CodeUnit... codeUnits) {
		for (CodeUnit codeUnit : codeUnits) {
			if (codeUnit != null) {
				setBackgroundColor(program, codeUnit.getMinAddress(), codeUnit.getMaxAddress(),
					color);
			}
		}
	}

	private static void setBackgroundColor(Program program, Address min, Address max, Color c) {
		IntRangeMap map = getColorRangeMap(program, true);
		if (map != null) {
			map.setValue(min, max, c.getRGB());
		}
	}

	private static IntRangeMap getColorRangeMap(Program program, boolean create) {
		if (program == null) {
			return null;
		}
		IntRangeMap map =
			program.getIntRangeMap(PropertyBasedBackgroundColorModel.COLOR_PROPERTY_NAME);
		if (map == null && create) {
			try {
				map = program.createIntRangeMap(
					PropertyBasedBackgroundColorModel.COLOR_PROPERTY_NAME);
			}
			catch (DuplicateNameException e) {
				// can't happen since we just checked for it!
			}
		}
		return map;
	}

	private static Random RAND = new Random();

	private static Color pickColor(CorrelationContainer container) {
		float saturation;
		float brightness;
		float hue;
		switch (container.kind) {
			case CODE_COMPARE:
				if (CodeCompareAddressCorrelation.CorrelationContainer.USE_RANDOM_CC_COLORS) {
					hue = RAND.nextFloat();
				}
				else {
					hue = 0.33f;
				}
				saturation = (float) (0.5 - RAND.nextFloat() / 3.0);
				brightness = (float) (1.0 - RAND.nextFloat() / 5.0);
				break;
			case LCS:
				hue = 0.9f;
				saturation = (float) (0.5 - RAND.nextFloat() / 3.0);
				brightness = (float) (1.0 - RAND.nextFloat() / 5.0);
				break;
			case PARAMETERS:
				hue = 0.2f;
				saturation = (float) (1.0 - RAND.nextFloat() / 3.0);
				brightness = (float) (1.0 - RAND.nextFloat() / 3.0);
				break;
			default:
				hue = 0.1f;
				saturation = 1.0f;
				brightness = 1.0f;
				break;
		}
		return Color.getHSBColor(hue, saturation, brightness);
	}

	public static void enable(boolean b) {
		ENABLED = b;
	}

	private static boolean isEnabled() {
		return ENABLED;
	}
}
