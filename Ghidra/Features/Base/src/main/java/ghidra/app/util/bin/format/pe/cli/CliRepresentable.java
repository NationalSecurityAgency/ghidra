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
package ghidra.app.util.bin.format.pe.cli;

import ghidra.app.util.bin.format.pe.cli.streams.CliStreamMetadata;

/**
 * Describes the methods necessary to get a long and short representation, with or without an metadata stream.
 * This is used in the token analyzer to cut down on duplication across modules.
 */
public interface CliRepresentable {
	public String getRepresentation();
	public String getShortRepresentation();
	public String getRepresentation(CliStreamMetadata stream);
	public String getShortRepresentation(CliStreamMetadata stream);
}
