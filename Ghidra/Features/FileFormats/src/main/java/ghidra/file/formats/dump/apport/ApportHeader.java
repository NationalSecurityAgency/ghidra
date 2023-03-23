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
package ghidra.file.formats.dump.apport;

import java.io.IOException;
import java.util.*;

import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.StructConverter;
import ghidra.file.formats.dump.DumpFileReader;
import ghidra.program.model.data.*;
import ghidra.util.task.TaskMonitor;

public class ApportHeader implements StructConverter {

	public final static String NAME = "APPORT_HEADER";

	private Map<String,String> map = new HashMap<>();
	private Map<String,Map<String,String>> smaps = new HashMap<>();
	private Map<Integer, Integer> lineLens = new HashMap<>();
	private Map<Integer, String> keys = new HashMap<>();
	private String signature;

	protected DumpFileReader reader;
	protected long index;
	
	private TaskMonitor monitor;
	private int lineCount = 0;
	private int memoryRegionOffset;


	ApportHeader(DumpFileReader reader, long index, TaskMonitor monitor) throws IOException {
		this.reader = reader;
		this.index = index;
		this.monitor = monitor;
		parse();
	}

	protected void parse() throws IOException {
		if (lineCount > 0) {
			return;
		}
		reader.setPointerIndex(index);

		List<Integer> lineEnds = new ArrayList<>();
		List<String> lines = new ArrayList<>();
		ByteProvider provider = reader.getByteProvider();
		byte [] bytes = new byte[(int) reader.length()];
		int idx = 0;
		monitor.setMessage("Parsing file");
		monitor.initialize(reader.length());
		for (int i = 0; i < reader.length(); i++) {
			byte b = provider.readByte(i);
			if (b == '\n') {
				String l = new String(bytes, 0, idx);
				lines.add(l);
				lineEnds.add(i);
				idx = 0;
				lineLens.put(lineCount, l.length());
				lineCount++;
				monitor.setProgress(i);
			} else {
				bytes[idx++] = b;
			}
			if (monitor.isCancelled()) {
				break;
			}
		}
		
		String key = "";
		boolean useSubMap = false;
		Map<String,String> submap = null;
		int sub = 0;
		monitor.setMessage("Parsing entries");
		monitor.initialize(lineEnds.size());
		for (int i = 0; i < lineEnds.size(); i++) {
			monitor.setProgress(i);
			if (monitor.isCancelled()) {
				break;
			}
			String line = lines.get(i);
			if (line.startsWith("CoreDump")) {
				memoryRegionOffset = lineEnds.get(i);
			}
			int sep = line.indexOf(":");
			if (sep < 0 || line.substring(0,sep).contains(" ")) {
				String subkey = key+"["+sub+"]";
				keys.put(i, subkey);
				if (useSubMap) {
					submap.put(subkey, line);
					if (line.length() < 100 && line.contains(": ")) {
						String [] split = line.split(": ");
						submap.put(split[0], split[1]);
					}
				} 
				sub++;
			} else {
				key = line.substring(0, sep);
				String value = line.substring(sep+1).trim();
				keys.put(i, key);
				useSubMap = value.equals("") || value.equals("base64");
				if (useSubMap) {
					submap = new HashMap<>();
					smaps.put(key, submap);
				} else {
					map.put(key, value);
					submap = null;
				}
				sub = 0;
			}
		}
	}

	/**
	 * @see ghidra.app.util.bin.StructConverter#toDataType()
	 */
	public DataType toDataType() {
		StructureDataType struct = new StructureDataType(NAME, 0);
		for (int i = 0; i < lineCount; i++) {
			Integer length = lineLens.get(i);
			if (length < 0) {
				break;
			}
			String key = keys.get(i);
			StringDataType str = new StringDataType();
			Map<String, String> smap = smaps.get(key);
			struct.add(str, length+1, key, null);
			if (key.equals("CoreDump")) {
				break;
			}
			if (smap != null) {
				Structure substruct = new StructureDataType(key, 0);
				for (String skey : smap.keySet()) {
					length = lineLens.get(++i);
					str = new StringDataType();
					substruct.add(str, length+1, skey, null);
				}
				struct.add(substruct, substruct.getDisplayName(), null);	
			}
		}

		struct.setCategoryPath(new CategoryPath("/APDMP"));

		return struct;
	}

	public String getSignature() {
		return signature;
	}

	public void setSignature(String signature) {
		this.signature = signature;
	}

	public int getLineCount() {
		return lineCount;
	}

	public String getMachineImageType() {
		return map.get("Architecture");
	}

	public MemoryInfo getMemoryInfo(int i) {
		Map<String, String> procMap = smaps.get("ProcMaps");
		return new MemoryInfo(procMap.get("ProcMaps["+i+"]"));
	}

	public int getMemoryRegionCount() {
		return smaps.get("ProcMaps").size();
	}

	public int getMemoryRegionOffset() {
		return memoryRegionOffset;
	}

	public String getBlob(int i) {
		Map<String, String> cd = smaps.get("CoreDump");
		return cd.get("CoreDump["+i+"]");
	}

	public int getBlobCount() {
		Map<String, String> cd = smaps.get("CoreDump");
		return cd.size();
	}

}
