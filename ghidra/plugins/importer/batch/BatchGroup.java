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
package ghidra.plugins.importer.batch;

import java.util.*;

import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.Loader;
import ghidra.formats.gfilesystem.FSRL;

/**
 * A group of {@link LoadSpec}s (possibly from different user added sources)
 * that have a common {@link BatchSegregatingCriteria}.
 * <p>
 * All the Apps must have the same set of {@link LoadSpec}s to be included in the same
 * BatchGroup.
 * <p>
 * Each BatchGroup has a single selected ({@link BatchGroupLoadSpec}) that applies
 * to all the Apps in the group.
 */
public class BatchGroup {
	public static class BatchLoadConfig {
		private Collection<LoadSpec> loadSpecs;
		private FSRL fsrl;
		private UserAddedSourceInfo uasi;
		private Loader loader;
		private String preferredFileName;

		BatchLoadConfig(ByteProvider provider, Collection<LoadSpec> loadSpecs, FSRL fsrl,
				UserAddedSourceInfo uasi) {
			this.loadSpecs = loadSpecs;
			this.fsrl = fsrl;
			this.uasi = uasi;

			this.loader = loadSpecs.iterator().next().getLoader();
			this.preferredFileName = loader.getPreferredFileName(provider);
		}

		public Collection<LoadSpec> getLoadSpecs() {
			return loadSpecs;
		}

		public FSRL getFSRL() {
			return fsrl;
		}

		public LoadSpec getLoadSpec(BatchGroupLoadSpec batchGroupLoadSpec) {
			for (LoadSpec loadSpec : loadSpecs) {
				if (batchGroupLoadSpec.matches(loadSpec)) {
					return loadSpec;
				}
			}
			return null;
		}

		public UserAddedSourceInfo getUasi() {
			return uasi;
		}

		public Loader getLoader() {
			return loader;
		}

		public String getPreferredFileName() {
			return preferredFileName;
		}
	}

	private final BatchSegregatingCriteria criteria;
	private List<BatchLoadConfig> batchLoadConfigs = new ArrayList<>();
	private BatchGroupLoadSpec selectedBatchGroupLoadSpec;
	private boolean enabled;

	/**
	 * Creates a new {@link BatchGroup} keyed on the specified 
	 * {@link BatchSegregatingCriteria criteria}.
	 *
	 * @param criteria {@link BatchSegregatingCriteria} of this {@link BatchGroup}.
	 */
	public BatchGroup(BatchSegregatingCriteria criteria) {
		this.criteria = criteria;
		this.selectedBatchGroupLoadSpec = criteria.getFirstPreferredLoadSpec();
		this.enabled = selectedBatchGroupLoadSpec != null;
	}

	/**
	 * Adds {@link LoadSpec}s to this group.
	 *
	 * @param provider The {@link ByteProvider}.
	 * @param loadSpecs {@link LoadSpec}s to add to this group.
	 * @param fsrl {@link FSRL} of the application's import source file.
	 * @param uasi {@link UserAddedSourceInfo}
	 */
	public void add(ByteProvider provider, Collection<LoadSpec> loadSpecs, FSRL fsrl,
			UserAddedSourceInfo uasi) {
		batchLoadConfigs.add(new BatchLoadConfig(provider, loadSpecs, fsrl, uasi));
	}

	/**
	 * Returns the selected {@link BatchGroupLoadSpec} that applies to the entire 
	 * {@link BatchGroup}.
	 *
	 * @return selected {@link BatchGroupLoadSpec} that applies to the entire {@link BatchGroup}.
	 */
	public BatchGroupLoadSpec getSelectedBatchGroupLoadSpec() {
		return selectedBatchGroupLoadSpec;
	}

	/**
	 * Sets the current {@link BatchGroupLoadSpec} for the entire group of applications.
	 *
	 * @param selectedBatchGroupLoadSpec {@link BatchGroupLoadSpec} to set
	 */
	public void setSelectedBatchGroupLoadSpec(BatchGroupLoadSpec selectedBatchGroupLoadSpec) {
		this.selectedBatchGroupLoadSpec = selectedBatchGroupLoadSpec;
	}

	/**
	 * Returns true if this group is 'enabled', which means that it has a selected
	 * {@link BatchGroupLoadSpec} and the user has chosen to mark this group as importable.
	 *
	 * @return boolean enabled status.
	 */
	public boolean isEnabled() {
		return enabled;
	}

	/**
	 * Sets the enabled status of this group.
	 *
	 * @param enabled boolean
	 */
	public void setEnabled(boolean enabled) {
		this.enabled = enabled;
	}

	/**
	 * Returns the {@link BatchSegregatingCriteria} of this group.
	 *
	 * @return {@link BatchSegregatingCriteria} of this group.
	 */
	public BatchSegregatingCriteria getCriteria() {
		return criteria;
	}

	/**
	 * Returns the number of applications in this group.
	 *
	 * @return number of applications in this group.
	 */
	public int size() {
		return batchLoadConfigs.size();
	}

	/**
	 * Returns true if there are no applications in this group.
	 *
	 * @return boolean true if there are no applications in this group.
	 */
	public boolean isEmpty() {
		return batchLoadConfigs.size() == 0;
	}

	/**
	 * Returns the list of current {@link BatchLoadConfig} in this group.
	 *
	 * @return {@link List} of {@link BatchLoadConfig} {@link BatchLoadConfig} wrappers.
	 */
	public List<BatchLoadConfig> getBatchLoadConfig() {
		return batchLoadConfigs;
	}

	/**
	 * Removes any applications that are inside the specified container file.
	 *
	 * @param fsrl {@link FSRL} of a container.
	 */
	public void removeDescendantsOf(FSRL fsrl) {
		for (Iterator<BatchLoadConfig> iterator = batchLoadConfigs.iterator(); iterator.hasNext();) {
			BatchLoadConfig ai = iterator.next();
			if (ai.fsrl.isEquivalent(fsrl) || ai.fsrl.isDescendantOf(fsrl)) {
				iterator.remove();
			}
		}
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append(criteria.toString()).append(" ->\n");
		for (BatchLoadConfig batchLoadConfig : batchLoadConfigs) {
			sb.append("    ").append(batchLoadConfig.preferredFileName).append("\n");
		}
		return sb.toString();
	}
}
