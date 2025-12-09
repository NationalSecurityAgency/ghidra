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
package ghidra.app.plugin.core.analysis.objc;

import ghidra.app.services.*;
import ghidra.app.util.bin.format.objc.AbstractObjcTypeMetadata;
import ghidra.app.util.bin.format.objc.objc1.Objc1Constants;
import ghidra.app.util.bin.format.objc.objc1.Objc1TypeMetadata;
import ghidra.app.util.bin.format.objc.objc2.Objc2Constants;
import ghidra.app.util.bin.format.objc.objc2.Objc2TypeMetadata;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class ObjcTypeMetadataAnalyzer extends AbstractAnalyzer {
	private static final String NAME = "Objective-C Type Metadata Analyzer";
	private static final String DESCRIPTION = "Discovers Objective-C type metadata records.";

	private AbstractObjcTypeMetadata typeMetadata;

	public ObjcTypeMetadataAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		setDefaultEnablement(true);
		setPriority(AnalysisPriority.FORMAT_ANALYSIS);
	}

	@Override
	public boolean canAnalyze(Program program) {
		return Objc1Constants.isObjectiveC(program) || Objc2Constants.isObjectiveC2(program);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		if (typeMetadata != null) {
			return true;
		}
		try {
			if (Objc1Constants.isObjectiveC(program)) {
				typeMetadata = new Objc1TypeMetadata(program, monitor, log);
			}
			else if (Objc2Constants.isObjectiveC2(program)) {
				typeMetadata = new Objc2TypeMetadata(program, monitor, log);
			}
			if (typeMetadata != null) {
				typeMetadata.applyTo();
			}
			return true;
		}
		catch (CancelledException e) {
			throw e;
		}
		catch (Exception e) {
			return false;
		}
	}

	@Override
	public void analysisEnded(Program program) {
		if (typeMetadata != null) {
			typeMetadata.close();
			typeMetadata = null;
		}
	}
}
