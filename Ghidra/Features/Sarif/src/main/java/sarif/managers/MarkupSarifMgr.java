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
package sarif.managers;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import com.google.gson.JsonArray;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFormatException;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Library;
import ghidra.program.model.listing.Program;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Equate;
import ghidra.program.model.symbol.EquateTable;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.ExternalManager;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.RefTypeFactory;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskMonitor;
import sarif.SarifProgramOptions;
import sarif.export.SarifWriterTask;
import sarif.export.ref.SarifEquateRefWriter;
import sarif.export.ref.SarifReferenceWriter;

/**
 * SARIF manager for all references ("markup" for operand substitution).
 */
public class MarkupSarifMgr extends SarifMgr {

	public static String KEY = "REFERENCES";

	private ReferenceManager refManager;
	private EquateTable equateTable;

	MarkupSarifMgr(Program program, MessageLog log) {
		super(KEY, program, log);
		refManager = program.getReferenceManager();
		equateTable = program.getEquateTable();
	}

	////////////////////////////
	// SARIF READ CURRENT DTD //
	////////////////////////////

	@Override
	public boolean read(Map<String, Object> result, SarifProgramOptions options, TaskMonitor monitor)
			throws CancelledException {
		String tagName = (String) result.get("Message");
		boolean overwrite = options == null || options.isOverwriteReferenceConflicts();
		if (tagName.equals("Ref.Memory")) {
			processMemoryReference(result, overwrite);
		} else if (tagName.equals("Ref.Shifted")) {
			processShiftedReference(result, overwrite);
		} else if (tagName.equals("Ref.Register")) {
			processRegisterReference(result, overwrite);
		} else if (tagName.equals("Ref.Stack")) {
			if (options == null || options.isFunctions()) { // TODO && !ignoreStackReferences) {
				processStackReference(result, overwrite);
			}
		} else if (tagName.equals("Ref.External")) {
			if (options == null || options.isExternalLibraries()) {
				processExtLibraryReference(result, overwrite);
			}
		} else if (tagName.equals("Ref.Equate")) {
			processEquateReference(result, overwrite);
		}
		return true;
	}

	private RefType getRefType(int type) {
		return RefTypeFactory.get((byte) type);
	}

	/**
	 * @param result
	 * @param language
	 * @param overwrite
	 */
	private void processMemoryReference(Map<String, Object> result, boolean overwrite) {
		try {
			Address fromAddr = getLocation(result);
			if (fromAddr == null) {
				throw new AddressFormatException("Incompatible Memory Reference FROM Address");
			}

			String toAddrStr = (String) result.get("to");
			if (toAddrStr == null) {
				throw new RuntimeException("TO_ADDRESS attribute missing for MEMORY_REFERENCE element");
			}
			Address toAddr = parseAddress(factory, toAddrStr);
			if (toAddr == null) {
				throw new AddressFormatException("Incompatible Memory Reference TO Address: " + toAddrStr);
			}

			int opIndex = CodeUnit.MNEMONIC;
			if (result.get("opIndex") != null) {
				opIndex = (int) (double) result.get("opIndex");
			}

			boolean primary = false;
			if (result.get("primary") != null) {
				primary = (boolean) result.get("primary");
			}

			Address baseAddr = null;
			if (result.get("base") != null) {
				baseAddr = parseAddress(factory, (String) result.get("base"));
			}

			if (!overwrite) {
				Reference[] existingMemRefs = refManager.getReferencesFrom(fromAddr, opIndex);
				if (existingMemRefs != null && existingMemRefs.length != 0 && !existingMemRefs[0].isMemoryReference()) {
					log.appendMsg("Reference already exists from [" + fromAddr + "] to [" + toAddr
							+ "] on operand [" + opIndex + "]");
					return;
				}
			}

			int index = Integer.parseInt((String) result.get("index"));
			RefType refType = getRefType(index);

			SourceType sourceType = getSourceType((String) result.get("sourceType"));
			ReferenceManager refMgr = program.getReferenceManager();
			Reference ref;
			if (baseAddr != null) {
				long offset = (long) (double) result.get("offset");
				// long offset = toAddr.subtract(baseAddr);
				ref = refMgr.addOffsetMemReference(fromAddr, toAddr, toAddr.equals(baseAddr), offset, refType,
						sourceType, opIndex);
			} else {
				ref = refMgr.addMemoryReference(fromAddr, toAddr, refType, sourceType, opIndex);
			}
			refMgr.setPrimary(ref, primary);

		} catch (Exception e) {
			log.appendException(e);
		}
	}

	/**
	 * @param result
	 * @param language
	 * @param overwrite
	 */
	private void processRegisterReference(Map<String, Object> result, boolean overwrite) {
		try {
			Address fromAddr = getLocation(result);
			if (fromAddr == null) {
				throw new AddressFormatException("Incompatible Memory Reference FROM Address");
			}

			String toAddrStr = (String) result.get("to");
			if (toAddrStr == null) {
				throw new RuntimeException("TO_ADDRESS attribute missing for REGISTER_REFERENCE element");
			}
			Address toAddr = parseAddress(factory, toAddrStr);
			if (toAddr == null) {
				throw new AddressFormatException("Incompatible Register Reference TO Address: " + toAddrStr);
			}
			Register[] registers = program.getLanguage().getRegisters(toAddr);
			Register reg = registers[0];

			int opIndex = CodeUnit.MNEMONIC;
			if (result.get("opIndex") != null) {
				opIndex = (int) (double) result.get("opIndex");
			}

			boolean primary = false;
			if (result.get("primary") != null) {
				primary = (boolean) result.get("primary");
			}

			if (!overwrite) {
				Reference[] existingRefs = refManager.getReferencesFrom(fromAddr, opIndex);
				if (existingRefs != null && existingRefs.length != 0) {
					log.appendMsg("Memory reference already existed from [" + fromAddr + "] to [" + toAddr
							+ "] on operand [" + opIndex + "]");
					return;
				}
			}

			int index = Integer.parseInt((String) result.get("index"));
			RefType refType = getRefType(index);

			SourceType sourceType = getSourceType((String) result.get("sourceType"));
			ReferenceManager refMgr = program.getReferenceManager();
			Reference ref = refMgr.addRegisterReference(fromAddr, opIndex, reg, refType, sourceType);
			refMgr.setPrimary(ref, primary);

		} catch (Exception e) {
			log.appendException(e);
		}
	}

	private void processStackReference(Map<String, Object> result, boolean overwrite) {
		try {
			Address addr = getLocation(result);
			if (addr == null) {
				throw new AddressFormatException("Incompatible Stack Reference Address");
			}
			int opIndex = CodeUnit.MNEMONIC;
			if (result.get("opIndex") != null) {
				opIndex = (int) (double) result.get("opIndex");
			}
			CodeUnit cu = listing.getCodeUnitContaining(addr);
			if (cu == null) {
				log.appendMsg("No codeunit at " + addr);
				return;
			}
			if (!overwrite) {
				Reference[] existingRefs = refManager.getReferencesFrom(addr, opIndex);
				if (existingRefs != null && existingRefs.length != 0) {
					log.appendMsg("Reference already exists from [" + addr + "] on operand [" + opIndex + "]");
					return;
				}
			}
			Reference ref = cu.getPrimaryReference(opIndex);
			if (ref != null) {
				if (!overwrite) {
					return;
				}
			}

			int offset = (int) (double) result.get("offset");
			int index = Integer.parseInt((String) result.get("index"));
			RefType refType = getRefType(index);

			SourceType sourceType = getSourceType((String) result.get("sourceType"));
			refManager.addStackReference(addr, opIndex, offset, refType, sourceType);

		} catch (Exception e) {
			log.appendException(e);
		}
	}

	private void processShiftedReference(Map<String, Object> result, boolean overwrite) {
		try {
			Address addr = getLocation(result);
			if (addr == null) {
				throw new AddressFormatException("Incompatible Shifted Reference Address");
			}
			int opIndex = CodeUnit.MNEMONIC;
			if (result.get("opIndex") != null) {
				opIndex = (int) (double) result.get("opIndex");
			}
			CodeUnit cu = listing.getCodeUnitContaining(addr);
			if (cu == null) {
				log.appendMsg("No codeunit at " + addr);
				return;
			}
			if (!overwrite) {
				Reference[] existingRefs = refManager.getReferencesFrom(addr, opIndex);
				if (existingRefs != null && existingRefs.length != 0) {
					log.appendMsg("Reference already exists from [" + addr + "] on operand [" + opIndex + "]");
					return;
				}
			}
			Reference ref = cu.getPrimaryReference(opIndex);
			if (ref != null) {
				if (!overwrite) {
					return;
				}
			}

			int shift = (int) (double) result.get("shift");
			long value = (long) (double) result.get("value");
			Address toAddr = addr.getNewAddress(value);
			int index = Integer.parseInt((String) result.get("index"));
			RefType refType = getRefType(index);

			SourceType sourceType = getSourceType((String) result.get("sourceType"));
			refManager.addShiftedMemReference(addr, toAddr, shift, refType, sourceType, opIndex);

		} catch (Exception e) {
			log.appendException(e);
		}
	}

	private void processExtLibraryReference(Map<String, Object> result, boolean overwrite) {
		try {
			Address addr = getLocation(result);
			if (addr == null) {
				throw new AddressFormatException("Incompatible External Reference Address");
			}
			int opIndex = CodeUnit.MNEMONIC;
			if (result.get("opIndex") != null) {
				opIndex = (int) (double) result.get("opIndex");
			}

			String namespacePath = (String) result.get("name");
			String label = (String) result.get("libLabel");
			String libAddress = (String) result.get("libAddr");
			Address libAddr = libAddress != null ? factory.getAddress(libAddress) : null;
			String libExtAddress = (String) result.get("libExtAddr");
			String origImport = (String) result.get("origImport");
			// boolean isClass = (boolean) result.get("isClass");
			boolean isFunction = (boolean) result.get("isFunction");

			if (label == null && libAddr == null) {
				log.appendMsg("External library reference for address " + addr
						+ " does not have a label or an external address specified. External reference will not be created");
				return;
			}
			CodeUnit cu = listing.getCodeUnitContaining(addr);
			if (cu == null) {
				log.appendMsg("No codeunit at " + addr);
				return;
			}
			Reference ref = cu.getExternalReference(opIndex);
			if (ref != null) {
				if (!overwrite) {
					return;
				}
				program.getReferenceManager().delete(ref);
			}

			RefType refType = null;
			String rt = (String) result.get("kind");
			if (rt != null) {
				int index = Integer.parseInt((String) result.get("index"));
				refType = getRefType(index);
			} else {
				refType = RefType.EXTERNAL_REF;
			}

			SourceType sourceType = getSourceType((String) result.get("sourceType"));
			ExternalLocation extLoc = externalMap.get(libExtAddress);
			if (extLoc == null) {
				extLoc = addExternal(label, namespacePath, libAddr, sourceType, origImport, isFunction);
				externalMap.put(libExtAddress, extLoc);
			}
			if (origImport != null && !origImport.equals(extLoc.getOriginalImportedName())) {
				log.appendMsg("Retrieving incorrect external location - known bug");
			}
			refManager.addExternalReference(addr, opIndex, extLoc, sourceType, refType);
		} catch (Exception e) {
			log.appendException(e);
		}
	}

	// This seems like this should be unnecessary but external classes are not
	// listen under ExternalLocations
	// (Possible forcing locations to be written per-reference means this is no
	// longer called, but...
	private ExternalLocation addExternal(String name, String namespacePath, Address address, SourceType sourceType,
			String name0, boolean isFunction) throws InvalidInputException, IOException {
		Namespace p = walkNamespace(program.getGlobalNamespace(), namespacePath + "::", address, sourceType, true);
		Library lib = getLibrary(p);
		ExternalLocation loc;
		ExternalManager extManager = program.getExternalManager();
		if (isFunction) {
			if (name0 != null) {
				loc = extManager.addExtFunction(lib == null ? p : lib, name0, address, sourceType, false);
				loc.setName(p, name, sourceType);
			} else {
				loc = extManager.addExtFunction(p, name, address, sourceType, true);
			}
		} else {
			if (name0 != null) {
				loc = extManager.addExtLocation(lib == null ? p : lib, name0, address, sourceType, false);
				loc.setName(p, name, sourceType);
			} else {
				loc = extManager.addExtLocation(p, name, address, sourceType, true);
			}
		}
		return loc;
	}

	private Library getLibrary(Namespace p) {
		if (p instanceof Library lib) {
			return lib;
		}
		Namespace parent = p.getParentNamespace();
		return parent == null ? null : getLibrary(parent);
	}

	/**
	 * @param result
	 * @param language
	 * @param overwrite
	 */
	private void processEquateReference(Map<String, Object> result, boolean overwrite) {
		try {
			Address addr = getLocation(result);
			if (addr == null) {
				throw new AddressFormatException("Incompatible Equate Reference Address");
			}

			if (listing.isUndefined(addr, addr)) {
				log.appendMsg("BAD EQUATE REFERENCE: defined code unit not found at " + addr);
				return;
			}

			CodeUnit cu = listing.getCodeUnitContaining(addr);
			if (cu == null) {
				log.appendMsg("No codeunit at " + addr);
				return;
			}

			String equateName = (String) result.get("name");

			int opIndex = CodeUnit.MNEMONIC;

			List<Scalar> instrScalars = new LinkedList<Scalar>();
			if (result.get("OpIndex") != null) {
				opIndex = (int) (double) result.get("opIndex");
				if (opIndex != CodeUnit.MNEMONIC) {
					Scalar tempScalar = cu.getScalar(opIndex);
					if (tempScalar != null) {
						instrScalars.add(tempScalar);
					} else if (cu instanceof Instruction) {
						Instruction instr = (Instruction) cu;
						Object[] opObjects = instr.getOpObjects(opIndex);
						for (int i = 0; i < opObjects.length; i++) {
							if (opObjects[i] instanceof Scalar) {
								instrScalars.add((Scalar) opObjects[i]);
							}
						}

						if (instrScalars.size() == 0) {
							log.appendMsg("BAD EQUATE REFERENCE: operand " + "[" + opIndex + "] at address " + "["
									+ addr + "] is not a scalar.");
							return;
						}
					}
				}
			}

			long value = 0;
			if (result.get("value") != null) {
				value = (long) result.get("value");
				Scalar matchingScalar = null;
				Iterator<Scalar> itr = instrScalars.iterator();
				while (matchingScalar == null && itr.hasNext()) {
					matchingScalar = itr.next();
					if (matchingScalar.getSignedValue() != value) {
						matchingScalar = null;
					}
				}

				if (matchingScalar == null) {
					log.appendMsg("BAD EQUATE REFERENCE: equate [" + equateName + "] value [0x"
							+ Long.toHexString(value) + "]" + " does not match scalar on operand [" + opIndex
							+ "] at address [" + addr + "]");
					return;
				}
			} else if (instrScalars.size() > 0) {
				// use scalar value as default - seems like a bad idea
				Msg.warn(this, "NO VALUE SPECIFIED");
				value = instrScalars.get(0).getSignedValue();
			} else {
				log.appendMsg("BAD EQUATE REFERENCE: either the VALUE or OPERAND_INDEX must be specified");
				return;
			}

			Equate equate = equateTable.getEquate(equateName);
			if (equate != null) {
				if (value != equate.getValue()) {
					log.appendMsg("BAD EQUATE REFERENCE: equate [" + equateName + "] value [0x"
							+ Long.toHexString(value) + "] conflicts with existing equate value [0x"
							+ Long.toHexString(equate.getValue()) + "].");
					return;
				}
			} else {
				try {
					equate = equateTable.createEquate(equateName, value);
				} catch (DuplicateNameException e) {
					throw new AssertException("Got duplicate name while creating equate " + equateName);
				} catch (InvalidInputException e) {
					log.appendMsg("Invalid name for equate " + equateName);
					return;
				}
			}

			Equate existingEquate = equateTable.getEquate(addr, opIndex, equate.getValue());
			if (existingEquate != null && overwrite) {
				existingEquate.removeReference(addr, opIndex);
			}
			equate.addReference(addr, opIndex);
		} catch (Exception e) {
			log.appendException(e);
		}
	}

	/////////////////////////////
	// SARIF WRITE CURRENT DTD //
	/////////////////////////////

	void write(JsonArray results, AddressSetView set, TaskMonitor monitor) throws IOException, CancelledException {
		if (set == null) {
			set = program.getMemory();
		}

		monitor.setMessage("Exporting References...");
		AddressIterator iter = refManager.getReferenceSourceIterator(set, true);
		List<Address> request = new ArrayList<>();
		while (iter.hasNext()) {
			request.add(iter.next());
		}
		writeAsSARIF(program, request, results);
		writeAsSARIF(program, set, results);
	}

	public static void writeAsSARIF(Program program, List<Address> request, JsonArray results) throws IOException {
		SarifReferenceWriter writer = new SarifReferenceWriter(program.getReferenceManager(), request, null);
		new TaskLauncher(new SarifWriterTask("References", writer, results), null);
	}

	public static void writeAsSARIF(Program program, AddressSetView set, JsonArray results) throws IOException {
		SarifEquateRefWriter ewriter = new SarifEquateRefWriter(program.getEquateTable(), set, null);
		new TaskLauncher(new SarifWriterTask("References", ewriter, results), null);
	}

}
