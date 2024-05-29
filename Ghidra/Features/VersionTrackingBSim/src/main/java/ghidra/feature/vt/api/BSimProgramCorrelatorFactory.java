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
package ghidra.feature.vt.api;

import generic.lsh.LSHMemoryModel;
import ghidra.feature.vt.api.main.VTProgramCorrelator;
import ghidra.feature.vt.api.main.VTProgramCorrelatorAddressRestrictionPreference;
import ghidra.feature.vt.api.util.VTAbstractProgramCorrelatorFactory;
import ghidra.feature.vt.api.util.VTOptions;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;

public class BSimProgramCorrelatorFactory extends VTAbstractProgramCorrelatorFactory {
	public static final String NAME = "BSim Function Matching";
	public static final String DESC =
		"Finds function matches by using data flow and call graph similarities between the " +
			"source and destination programs.";

	public static final String MEMORY_MODEL = "Memory Model";
	public static final LSHMemoryModel MEMORY_MODEL_DEFAULT = LSHMemoryModel.LARGE;
	public static final String MEMORY_MODEL_DESC =
		"Amount of memory used to compute matches. Smaller models are slightly less accurate.";

	public static final String SEED_CONF_THRESHOLD = "Confidence Threshold for a Seed";
	public static final double SEED_CONF_THRESHOLD_DEFAULT = 10.0;
	public static final String SEED_CONF_THRESHOLD_DESC =
		"For threshold N, the probability that a seed is incorrect is approximately 1/2^(N/5+9).";

	public static final String IMPLICATION_THRESHOLD = "Confidence Threshold for a Match";
	public static final double IMPLICATION_THRESHOLD_DEFAULT = 0.0;
	public static final String IMPLICATION_THRESHOLD_DESC =
		"For threshold N, the probability that a match is incorrect is approximately 1/2^(N/5+9).";

	public static final String USE_ACCEPTED_MATCHES_AS_SEEDS = "Use Accepted Matches as Seeds";
	public static final boolean USE_ACCEPTED_MATCHES_AS_SEEDS_DEFAULT = true;
	public static final String USE_ACCEPTED_MATCHES_AS_SEEDS_DESC =
		"Already accepted matches will also be used as seeds.";

	@Override
	public int getPriority() {
		return 50;
	}

	@Override
	protected VTProgramCorrelator doCreateCorrelator(Program sourceProgram,
			AddressSetView sourceAddressSet, Program destinationProgram,
			AddressSetView destinationAddressSet, VTOptions options) {
		return new BSimProgramCorrelator(sourceProgram, sourceAddressSet, destinationProgram,
			destinationAddressSet, options);
	}

	@Override
	public VTProgramCorrelatorAddressRestrictionPreference getAddressRestrictionPreference() {
		return VTProgramCorrelatorAddressRestrictionPreference.RESTRICTION_NOT_ALLOWED;
	}

	@Override
	public VTOptions createDefaultOptions() {
		VTOptions options = new VTOptions(NAME);
		HelpLocation help = new HelpLocation("BSimCorrelator", "BSim_Correlator");

		options.setEnum(MEMORY_MODEL, MEMORY_MODEL_DEFAULT);
		options.registerOption(MEMORY_MODEL, MEMORY_MODEL_DEFAULT, help, MEMORY_MODEL_DESC);

		options.setDouble(SEED_CONF_THRESHOLD, SEED_CONF_THRESHOLD_DEFAULT);
		options.registerOption(SEED_CONF_THRESHOLD, SEED_CONF_THRESHOLD_DEFAULT, help,
			SEED_CONF_THRESHOLD_DESC);

		options.setDouble(IMPLICATION_THRESHOLD, IMPLICATION_THRESHOLD_DEFAULT);
		options.registerOption(IMPLICATION_THRESHOLD, IMPLICATION_THRESHOLD_DEFAULT, help,
			IMPLICATION_THRESHOLD_DESC);

		options.setBoolean(USE_ACCEPTED_MATCHES_AS_SEEDS, USE_ACCEPTED_MATCHES_AS_SEEDS_DEFAULT);
		options.registerOption(USE_ACCEPTED_MATCHES_AS_SEEDS, USE_ACCEPTED_MATCHES_AS_SEEDS_DEFAULT,
			help, USE_ACCEPTED_MATCHES_AS_SEEDS_DESC);

		options.setOptionsHelpLocation(help);

		return options;
	}

	@Override
	public String getDescription() {
		return DESC;
	}

	@Override
	public String getName() {
		return NAME;
	}
}
