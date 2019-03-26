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

import java.io.*;

import ghidra.app.util.bin.*;
import ghidra.framework.*;

public class PdbFactory {
	static {
		PluggableServiceRegistry.registerPluggableService(PdbFactory.class,
				new PdbFactory());
	}

	public static PdbInfoDotNetIface getPdbInfoDotNetInstance(
			BinaryReader reader, int ptr) throws IOException {
		PdbFactory factory = PluggableServiceRegistry
				.getPluggableService(PdbFactory.class);
		return factory.doGetPdbInfoDotNetInstance(reader, ptr);
	}

	public static PdbInfoIface getPdbInfoInstance(BinaryReader reader, int ptr)
			throws IOException {
		PdbFactory factory = PluggableServiceRegistry
				.getPluggableService(PdbFactory.class);
		return factory.doGetPdbInfoInstance(reader, ptr);
	}

	protected PdbInfoDotNetIface doGetPdbInfoDotNetInstance(
			BinaryReader reader, int ptr) throws IOException {
		return null;
	}

	protected PdbInfoIface doGetPdbInfoInstance(BinaryReader reader, int ptr)
			throws IOException {
		return null;
	}
}
