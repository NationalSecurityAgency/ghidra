/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.app.util.bin.format.pdb;

import ghidra.app.util.bin.*;

import java.io.*;

public class GhidraPdbFactory extends PdbFactory {

	@Override
	protected PdbInfoDotNetIface doGetPdbInfoDotNetInstance(
			BinaryReader reader, int ptr) throws IOException {
		if (PdbInfoDotNet.isMatch(reader, ptr)) {
			return new PdbInfoDotNet(reader, ptr);
		}
		return null;
	}

	@Override
	protected PdbInfoIface doGetPdbInfoInstance(BinaryReader reader, int ptr)
			throws IOException {
		if (PdbInfo.isMatch(reader, ptr)) {
			return new PdbInfo(reader, ptr);
		}
		return null;
	}
}
