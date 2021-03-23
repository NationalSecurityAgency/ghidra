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
package ghidra.app.util.exporter;

import ghidra.app.util.opinion.PeLoader;
import ghidra.util.HelpLocation;

/**
 * An {@link Exporter} that can export programs imported with the {@link PeLoader}
 */
public class PeExporter extends AbstractLoaderExporter {

	/**
	 * Creates a new {@link PeExporter}
	 */
	public PeExporter() {
		super("PE", "exe", new HelpLocation("ExporterPlugin", "pe"));
	}

	@Override
	protected boolean supportsFileFormat(String fileFormat) {
		return PeLoader.PE_NAME.equals(fileFormat);
	}
}
