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
package ghidra.file.formats.android.multidex;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import ghidra.file.formats.android.dex.DexHeaderFactory;
import ghidra.file.formats.android.dex.format.DexHeader;
import ghidra.file.formats.android.dex.format.MethodIDItem;
import ghidra.file.formats.android.dex.util.DexUtil;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.ExternalManager;
import ghidra.program.model.symbol.ExternalReference;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * Links multidex APKs together
 * via the "method_lookup" section using
 * external references.
 */
public final class MultiDexLinker {

	private List<Program> programs;
	private Map<Program, DexHeader> dexMap = new HashMap<>();
	private Map<DexHeader, Map<ClassMethodPrototype, Integer>> cmpMap = new HashMap<>();
	private Map<Program, List<Address>> changeMap = new HashMap<>();

	private class ClassMethodPrototype {
		private final String className;
		private final String methodName;
		private final String prototype;

		ClassMethodPrototype(String className, String methodName, String prototype) {
			this.className = className;
			this.methodName = methodName;
			this.prototype = prototype;
		}

		@Override
		public boolean equals(Object obj) {
			if (obj instanceof ClassMethodPrototype) {
				ClassMethodPrototype cmp = (ClassMethodPrototype) obj;
				return cmp.className.equals(className) &&
					cmp.methodName.equals(methodName) &&
					cmp.prototype.equals(prototype);
			}
			return super.equals(obj);
		}

		@Override
		public int hashCode() {
			return className.hashCode() + methodName.hashCode() + prototype.hashCode();
		}
	}

	private class ProgramAddress {
		private final Program program;
		private final Address address;

		ProgramAddress(Program program, Address address) {
			this.program = program;
			this.address = address;
		}

		@Override
		public boolean equals(Object obj) {
			if (obj instanceof ProgramAddress) {
				ProgramAddress pa = (ProgramAddress) obj;
				return this.program.equals(pa.program) && this.address.equals(pa.address);
			}
			return super.equals(obj);
		}

		@Override
		public int hashCode() {
			return program.hashCode() + address.hashCode();
		}
	}

	public MultiDexLinker(List<Program> programs) {
		this.programs = new ArrayList<>(programs);//create copy of list
	}

	public void link(TaskMonitor monitor) throws CancelledException, IOException,
			MemoryAccessException, InvalidInputException, DuplicateNameException {

		Objects.requireNonNull(monitor);
		cacheHeaderInfo(monitor);
		linkPrograms(monitor);
	}

	public void clear(TaskMonitor monitor) throws CancelledException {
		Objects.requireNonNull(monitor);
		programs.clear();
		dexMap.clear();
		for (DexHeader header : cmpMap.keySet()) {
			monitor.checkCancelled();
			cmpMap.get(header).clear();
		}
		cmpMap.clear();
		changeMap.clear();
	}

	public List<Address> getChangeList(Program program) {
		return Objects.requireNonNull(changeMap.get(program));
	}

	private void linkPrograms(TaskMonitor monitor) throws CancelledException, MemoryAccessException,
			InvalidInputException, DuplicateNameException, IOException {

		monitor.setMaximum(programs.size());
		monitor.setProgress(1);
		for (Program program : programs) {
			monitor.checkCancelled();
			monitor.incrementProgress(1);
			monitor.setMessage(program.getName());

			DexHeader dexHeader = dexMap.get(program);

			List<Address> changeList = new ArrayList<>();
			changeMap.put(program, changeList);

			int transaction = program.startTransaction("multi-dex");
			try {
				ReferenceManager referenceManager = program.getReferenceManager();
				ExternalManager externalManager = program.getExternalManager();

				MemoryBlock methodLookupBlock = program.getMemory().getBlock("method_lookup");
				AddressSet methodLookupRange =
					new AddressSet(methodLookupBlock.getStart(), methodLookupBlock.getEnd());

				DataIterator dataIterator =
					program.getListing().getDefinedData(methodLookupRange, true);

				while (dataIterator.hasNext()) {
					Data data = dataIterator.next();

					monitor.checkCancelled();
					monitor.setMessage(program.getName() + " " + data.getMinAddress());

					if (program.getMemory().getInt(data.getMinAddress()) != -1) {
						continue;//internally linked, ignore
					}

					if (isExternalReferenceResolved(program, data, monitor)) {
						continue;
					}

					int methodIndex =
						(int) data.getMinAddress().subtract(methodLookupBlock.getStart()) / 4;

					MethodIDItem methodIDItem = dexHeader.getMethods().get(methodIndex);
					String className =
						DexUtil.convertTypeIndexToString(dexHeader, methodIDItem.getClassIndex());
					String prototype = DexUtil.convertPrototypeIndexToString(dexHeader,
						methodIDItem.getProtoIndex());
					String methodName =
						DexUtil.convertToString(dexHeader, methodIDItem.getNameIndex());

					ProgramAddress pa =
						findInOtherProgram(program, className, prototype, methodName, monitor);

					if (pa == null) {
						continue;
					}

					if (externalManager.getExternalLibraryPath(pa.program.getName()) == null) {
						externalManager.setExternalPath(pa.program.getName(),
							pa.program.getDomainFile().getPathname(), true);
					}

					referenceManager.addExternalReference(data.getMinAddress(),
						pa.program.getName(), null, pa.address, SourceType.ANALYSIS, 0,
						RefType.EXTERNAL_REF);

					changeList.add(data.getMinAddress());
				}
			}
			finally {
				program.endTransaction(transaction, true);
			}
		}
	}

	private ProgramAddress findInOtherProgram(Program program, String className,
			String prototype, String methodName, TaskMonitor monitor)
			throws CancelledException, IOException, MemoryAccessException {

		ClassMethodPrototype cmp =
			new ClassMethodPrototype(className, methodName, prototype);

		for (Program otherProgram : programs) {
			monitor.checkCancelled();

			if (otherProgram.equals(program)) {
				continue;
			}

			DexHeader otherDexHeader = dexMap.get(otherProgram);

			Map<ClassMethodPrototype, Integer> map = cmpMap.get(otherDexHeader);

			Integer otherMethodIndex = map.get(cmp);

			if (otherMethodIndex != null) {
				Address otherAddress = DexUtil.toLookupAddress(program, otherMethodIndex);

				if (otherProgram.getMemory().getInt(otherAddress) != -1) {
					return new ProgramAddress(otherProgram, otherAddress);
				}
			}
		}
		return null;
	}

	private void cacheHeaderInfo(TaskMonitor monitor) throws CancelledException, IOException {
		monitor.setMaximum(programs.size());
		monitor.setProgress(1);
		for (Program program : programs) {
			monitor.checkCancelled();
			monitor.incrementProgress(1);
			monitor.setMessage("Caching DEX header for " + program.getName() + "...");

			DexHeader dexHeader = DexHeaderFactory.getDexHeader(program);
			dexMap.put(program, dexHeader);

			Map<ClassMethodPrototype, Integer> map = new HashMap<>();
			cmpMap.put(dexHeader, map);

			int index = 0;
			for (MethodIDItem item : dexHeader.getMethods()) {
				monitor.checkCancelled();

				String className =
					DexUtil.convertTypeIndexToString(dexHeader, item.getClassIndex());

				String methodName = DexUtil.convertToString(dexHeader, item.getNameIndex());

				String prototype =
					DexUtil.convertPrototypeIndexToString(dexHeader, item.getProtoIndex());

				ClassMethodPrototype cmp =
					new ClassMethodPrototype(className, methodName, prototype);

				map.put(cmp, index);
				++index;
			}
		}
	}

	private boolean isExternalReferenceResolved(Program program, Data data, TaskMonitor monitor)
			throws CancelledException {

		ExternalManager externalManager = program.getExternalManager();
		Reference[] referencesFrom = data.getReferencesFrom();
		for (Reference reference : referencesFrom) {
			monitor.checkCancelled();
			if (reference instanceof ExternalReference) {
				ExternalReference extref = (ExternalReference) reference;
				ExternalLocation externalLocation = extref.getExternalLocation();
				if (externalManager.getExternalLibraryPath(
					externalLocation.getLibraryName()) != null) {
					return true;//already resolved
				}
			}
		}
		return false;
	}
}
