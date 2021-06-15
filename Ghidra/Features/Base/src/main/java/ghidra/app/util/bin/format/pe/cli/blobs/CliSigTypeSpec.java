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
package ghidra.app.util.bin.format.pe.cli.blobs;

import java.io.IOException;

import ghidra.app.util.bin.format.pe.cli.streams.CliStreamMetadata;
import ghidra.program.model.data.DataType;
import ghidra.util.exception.InvalidInputException;

public class CliSigTypeSpec extends CliAbstractSig {

	public CliSigType type;

	public CliSigTypeSpec(CliBlob blob) throws IOException {
		super(blob);

		try {
			type = readCliType(blob.getContentsReader());
		}
		catch (InvalidInputException e) {
			type = null;
		}
	}

	@Override
	public String getContentsName() {
		return "TypeSpec";
	}

	@Override
	public String getContentsComment() {
		return "Describes a type.";
	}

	@Override
	public DataType getContentsDataType() {
		return type.getDefinitionDataType();
	}

	@Override
	public String getRepresentationCommon(CliStreamMetadata stream, boolean isShort) {
		return "TypeSpec: " + getRepresentationOf(type, stream, isShort);
	}
}
