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
package ghidra.app.util.bin.format.macos.cfm;

import ghidra.app.util.bin.*;
import ghidra.program.model.data.DataType;
import ghidra.util.exception.DuplicateNameException;

import java.io.IOException;

/**
 * If the fragment is an application, appStackSize indicates 
 * the application stack size. 
 * Typically appStackSize has the value kDefaultStackSize.
 */
public class CFragUsage1Union implements StructConverter {
	public final static int kDefaultStackSize = 0;

	private int appStackSize;

	public CFragUsage1Union(BinaryReader reader) throws IOException {
		appStackSize = reader.readNextInt();
	}

	public int getAppStackSize() {
		return appStackSize;
	}

	public DataType toDataType() throws DuplicateNameException, IOException {
		return StructConverterUtil.toDataType(getClass());
	}
}
