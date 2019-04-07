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
package ghidra.app.util.bin.format.pe.cli.tables;

import ghidra.app.util.bin.format.pe.cli.CliRepresentable;
import ghidra.app.util.bin.format.pe.cli.streams.CliStreamMetadata;

/**
 * Generic Metadata table row.  Subclasses should provided implementations for the actual
 * table rows.
 */
public abstract class CliAbstractTableRow implements CliRepresentable {

	@Override
	public abstract String getRepresentation();
	
	@Override
	public String getShortRepresentation() {
		return getRepresentation();
	}
	
	@Override
	public String getRepresentation(CliStreamMetadata stream) {
		return getRepresentation();
	}
	
	@Override
	public String getShortRepresentation(CliStreamMetadata stream) {
		return getRepresentation(stream);
	}
}
