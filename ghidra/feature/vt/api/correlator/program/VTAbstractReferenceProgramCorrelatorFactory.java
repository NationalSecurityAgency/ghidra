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

import generic.lsh.LSHMemoryModel;
import ghidra.feature.vt.api.main.VTProgramCorrelatorAddressRestrictionPreference;
import ghidra.feature.vt.api.util.VTAbstractProgramCorrelatorFactory;
import ghidra.feature.vt.api.util.VTOptions;
import ghidra.util.HelpLocation;

public abstract class VTAbstractReferenceProgramCorrelatorFactory extends
		VTAbstractProgramCorrelatorFactory {
	public static final String MEMORY_MODEL = "Memory model";
	public static final LSHMemoryModel MEMORY_MODEL_DEFAULT = LSHMemoryModel.LARGE;
	public static final String MEMORY_MODEL_DESC = "Larger memory model results in faster runtime.";

	public static final String CONFIDENCE_THRESHOLD = "Confidence threshold (info content)";
	public static final double CONFIDENCE_THRESHOLD_DEFAULT = 1;
	public static final String CONFIDENCE_THRESHOLD_DESC = "Minimum bit threshold should be > 0.0";

	public static final String SIMILARITY_THRESHOLD = "Minimum similarity threshold (score)";
	public static final String SIMILARITY_THRESHOLD_DESC = "Similarity should be between 0 and 1";
	public static final double SIMILARITY_THRESHOLD_DEFAULT = 0.5;

	public static final String REFINE_RESULTS = "Refine Results";
	public static final boolean REFINE_RESULTS_DEFAULT = true;
	public static final String REFINE_RESULTS_DESC = "Remove results that have conflicting scores.";

	private static final String helpLocationTopic = "VersionTrackingPlugin";

	// Child Classes set these:
	public String correlatorName = "CORRELATOR_NAME";
	protected String correlatorDescription = "DECRIBE_HOW_THE_CORRELATORS_MAKE_MATCHES.";
	protected String helpLocationAnchor = "Options_Panel";

	// Child Classes use these, but don't need to override
	public VTAbstractReferenceProgramCorrelatorFactory() {
		super(VTProgramCorrelatorAddressRestrictionPreference.RESTRICTION_NOT_ALLOWED);
	}

	@Override
	public VTOptions createDefaultOptions() {
		VTOptions options = new VTOptions(correlatorName);
		HelpLocation help = new HelpLocation(helpLocationTopic, helpLocationAnchor);
		options.setOptionsHelpLocation(help);

		options.registerOption(MEMORY_MODEL, MEMORY_MODEL_DEFAULT, help, MEMORY_MODEL_DESC);

		options.registerOption(CONFIDENCE_THRESHOLD, CONFIDENCE_THRESHOLD_DEFAULT, help,
			CONFIDENCE_THRESHOLD_DESC);

		options.registerOption(SIMILARITY_THRESHOLD, SIMILARITY_THRESHOLD_DEFAULT, help,
			SIMILARITY_THRESHOLD_DESC);

		options.registerOption(REFINE_RESULTS, REFINE_RESULTS_DEFAULT, help, REFINE_RESULTS_DESC);

		options.setDouble(CONFIDENCE_THRESHOLD, CONFIDENCE_THRESHOLD_DEFAULT);
		options.setDouble(SIMILARITY_THRESHOLD, SIMILARITY_THRESHOLD_DEFAULT);
		options.setEnum(MEMORY_MODEL, MEMORY_MODEL_DEFAULT);
		options.setBoolean(REFINE_RESULTS, REFINE_RESULTS_DEFAULT);
		return options;
	}

	@Override
	public String getDescription() {
		return correlatorDescription;
	}

	public void setName(String name) {
		correlatorName = name;
	}

	@Override
	public String getName() {
		return correlatorName;
	}

	@Override
	public int getPriority() {
		return 49;
	}
}
