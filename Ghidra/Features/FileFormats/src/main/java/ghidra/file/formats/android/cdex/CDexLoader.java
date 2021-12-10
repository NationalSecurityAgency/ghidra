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
package ghidra.file.formats.android.cdex;

import java.io.IOException;
import java.util.*;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.opinion.*;
import ghidra.file.formats.android.dex.DexHeaderFactory;
import ghidra.file.formats.android.dex.format.DexConstants;
import ghidra.file.formats.android.dex.format.DexHeader;

public class CDexLoader extends DexLoader {

	@Override
	public String getName() {
		return CDexConstants.NAME;
	}

	@Override
	public LoaderTier getTier() {
		return LoaderTier.UNTARGETED_LOADER;
	}

	@Override
	public int getTierPriority() {
		return 100;
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		BinaryReader reader = new BinaryReader(provider, true);
		try {
			byte[] magicBytes = provider.readBytes(0, CDexConstants.MAGIC.length());
			if (CDexConstants.MAGIC.equals(new String(magicBytes))) {
				DexHeader header = DexHeaderFactory.getDexHeader(reader);//should be CDEX
				if (CDexConstants.MAGIC.equals(new String(header.getMagic()))) {
					List<QueryResult> queries =
						QueryOpinionService.query(getName(), DexConstants.MACHINE, null);
					for (QueryResult result : queries) {
						loadSpecs.add(new LoadSpec(this, 0, result));
					}
					if (loadSpecs.isEmpty()) {
						loadSpecs.add(new LoadSpec(this, 0, true));
					}
				}
			}
		}
		catch (Exception e) {
			//ignore
		}
		return loadSpecs;
	}

	@Override
	public boolean supportsLoadIntoProgram() {
		return true;
	}

	@Override
	protected String getMemoryBlockName() {
		return ".cdex";
	}

	@Override
	protected String getMonitorMessagePrimary() {
		return "CDEX Loader: creating cdex memory";
	}

	@Override
	protected String getMonitorMessageSecondary() {
		return "CDEX Loader: creating method byte code";
	}

}
