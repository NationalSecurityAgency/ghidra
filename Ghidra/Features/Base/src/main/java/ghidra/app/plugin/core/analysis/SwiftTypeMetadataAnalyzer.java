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
package ghidra.app.plugin.core.analysis;

import java.io.IOException;

import ghidra.app.services.*;
import ghidra.app.util.bin.format.swift.SwiftTypeMetadata;
import ghidra.app.util.bin.format.swift.SwiftUtils;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class SwiftTypeMetadataAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "Swift Type Metadata Analyzer";
	private static final String DESCRIPTION = "Discovers Swift type metadata records.";

	private SwiftTypeMetadata typeMetadata;

	public SwiftTypeMetadataAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		setDefaultEnablement(true);
		setPriority(AnalysisPriority.FORMAT_ANALYSIS);
	}

	@Override
	public boolean canAnalyze(Program program) {
		return SwiftUtils.isSwift(program);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		if (typeMetadata != null) {
			return true;
		}
		try {
			typeMetadata = new SwiftTypeMetadata(program, monitor, log);
			typeMetadata.markup();
		}
		catch (IOException e) {
			return false;
		}
		return true;
	}

	@Override
	public void analysisEnded(Program program) {
		typeMetadata = null;
	}
}
