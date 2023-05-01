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
package pdbquery;

import java.util.Map;

import ghidra.app.script.GhidraScript;
import ghidra.app.util.bin.format.pdb2.pdbreader.*;
import ghidra.app.util.bin.format.pdb2.pdbreader.symbol.AbstractMsSymbol;
import ghidra.app.util.bin.format.pdb2.pdbreader.type.AbstractMsType;
import ghidra.app.util.bin.format.pdb2.pdbreader.type.PrimitiveMsType;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Helper class with static query methods available to PdbQuery set of scripts.  The methods
 * in this class allow the user to query particular components inside of a PDB.
 */
public class PdbQuery {

	/**
	 * Returns the specified PDB data type record.
	 * @param script the script for which we are working
	 * @param pdb the PDB containing the record
	 * @param number the data type record number
	 * @return the data type record
	 */
	public static AbstractMsType getDataTypeRecord(GhidraScript script, AbstractPdb pdb,
			int number) {
		TypeProgramInterface tpi = pdb.getTypeProgramInterface();
		if (tpi == null) {
			println(script, "PDB does not contain a TPI... aborting search.");
			return null;
		}
		if (number < 0 || number >= tpi.getTypeIndexMaxExclusive()) {
			println(script, "Record number (" + number + ") out of range (" + 0 + " - " +
				tpi.getTypeIndexMaxExclusive() + ")");
			return null;
		}
		if (number < tpi.getTypeIndexMin()) {
			// Created on the fly and is not cached.  Moreover, it can add yet-unseen records to
			// the PDB... so this might not be desired... Also... the record number could represent
			// what is typically a "type" or an "item" and that cannot be distingushed here...
			// there is not conflict between primitive type and primitive items... they come from
			// the same pool, but we might return what is an item record in the request for a type
			// record or vice versa.  TODO: investigate all of these issues this further; might
			// need to eliminate this report or add a lot more code.
			return new PrimitiveMsType(pdb, number);
		}
		RecordNumber recordNumber = RecordNumber.typeRecordNumber(number);
		AbstractMsType typeRecord = pdb.getTypeRecord(recordNumber);
		return typeRecord;
	}

	/**
	 * Returns the specified PDB item record.
	 * @param script the script for which we are working
	 * @param pdb the PDB containing the record
	 * @param number the item record number
	 * @return the item record
	 */
	public static AbstractMsType getItemTypeRecord(GhidraScript script, AbstractPdb pdb,
			int number) {
		TypeProgramInterface ipi = pdb.getItemProgramInterface();
		if (ipi == null) {
			println(script, "PDB does not contain an IPI... aborting search.");
			return null;
		}
		if (number < 0 || number >= ipi.getTypeIndexMaxExclusive()) {
			println(script, "Record number (" + number + ") out of range (" + 0 + " - " +
				ipi.getTypeIndexMaxExclusive() + ")");
			return null;
		}
		if (number < ipi.getTypeIndexMin()) {
			// Created on the fly and is not cached.  Moreover, it can add yet-unseen records to
			// the PDB... so this might not be desired... Also... the record number could represent
			// what is typically a "type" or an "item" and that cannot be distingushed here...
			// there is not conflict between primitive type and primitive items... they come from
			// the same pool, but we might return what is an item record in the request for a type
			// record or vice versa.  TODO: investigate all of these issues this further; might
			// need to eliminate this report or add a lot more code.
			return new PrimitiveMsType(pdb, number);
		}
		RecordNumber recordNumber = RecordNumber.itemRecordNumber(number);
		AbstractMsType typeRecord = pdb.getTypeRecord(recordNumber);
		return typeRecord;
	}

	/**
	 * Searches PDB data type records that contain the search string.  Outputs results to the
	 * console
	 * @param script the script for which we are working
	 * @param pdb the PDB to search
	 * @param searchString the search string
	 * @throws CancelledException upon user cancellation
	 */
	public static void searchDataTypes(GhidraScript script, AbstractPdb pdb, String searchString)
			throws CancelledException {
		TypeProgramInterface tpi = pdb.getTypeProgramInterface();
		if (tpi == null) {
			println(script, "PDB does not contain a TPI... aborting search.");
		}

		StringBuilder results = new StringBuilder();
		results.append('\n');

		int num = tpi.getTypeIndexMaxExclusive() - tpi.getTypeIndexMin();
		TaskMonitor monitor = script.getMonitor();
		monitor.initialize(num);
		println(script, "Searching " + num + " PDB data type components...");
		for (int indexNumber = tpi.getTypeIndexMin(); indexNumber < tpi
				.getTypeIndexMaxExclusive(); indexNumber++) {
			monitor.checkCancelled();
			RecordNumber recordNumber = RecordNumber.typeRecordNumber(indexNumber);
			AbstractMsType typeRecord = pdb.getTypeRecord(recordNumber);
			String recordString = typeRecord.toString();
			if (recordString.contains(searchString)) {
				results.append("Data number " + indexNumber + ":\n");
				results.append(recordString);
				results.append('\n');
			}
			monitor.incrementProgress(1);
		}
		println(script, results.toString());
	}

	/**
	 * Searches PDB item records that contain the search string.  Outputs results to the
	 * console
	 * @param script the script for which we are working
	 * @param pdb the PDB to search
	 * @param searchString the search string
	 * @throws CancelledException upon user cancellation
	 */
	public static void searchItemTypes(GhidraScript script, AbstractPdb pdb, String searchString)
			throws CancelledException {
		TypeProgramInterface ipi = pdb.getItemProgramInterface();
		if (ipi == null) {
			println(script, "PDB does not contain an IPI... aborting search.");
			return;
		}

		StringBuilder results = new StringBuilder();
		results.append('\n');

		int num = ipi.getTypeIndexMaxExclusive() - ipi.getTypeIndexMin();
		TaskMonitor monitor = script.getMonitor();
		monitor.initialize(num);
		println(script, "Searching " + num + " PDB item type components...");
		for (int indexNumber = ipi.getTypeIndexMin(); indexNumber < ipi
				.getTypeIndexMaxExclusive(); indexNumber++) {
			monitor.checkCancelled();
			RecordNumber recordNumber = RecordNumber.itemRecordNumber(indexNumber);
			AbstractMsType typeRecord = pdb.getTypeRecord(recordNumber);
			String recordString = typeRecord.toString();
			if (recordString.contains(searchString)) {
				results.append("Item number " + indexNumber + ":\n");
				results.append(recordString);
				results.append('\n');
			}
			monitor.incrementProgress(1);
		}
		println(script, results.toString());
	}

	/**
	 * Searches PDB symbol records that contain the search string.  Outputs results to the
	 * console
	 * @param script the script for which we are working
	 * @param pdb the PDB to search
	 * @param searchString the search string
	 * @throws CancelledException upon user cancellation
	 */
	public static void searchSymbols(GhidraScript script, AbstractPdb pdb, String searchString)
			throws CancelledException {

		PdbDebugInfo debugInfo = pdb.getDebugInfo();
		if (debugInfo == null) {
			return;
		}

		StringBuilder results = new StringBuilder();
		results.append('\n');

		int numModules = debugInfo.getNumModules();
		TaskMonitor monitor = script.getMonitor();
		int numSymbols = 0;
		for (int module = 0; module <= numModules; module++) {
			monitor.checkCancelled();
			try {
				Map<Long, AbstractMsSymbol> symbols = debugInfo.getModuleSymbolsByOffset(module);
				numSymbols += symbols.size();
			}
			catch (PdbException e) {
				// just skip the module... logging this in the next loop.
			}
		}

		monitor.initialize(numSymbols);
		println(script, "Searching " + numSymbols + " PDB symbol components...");
		for (int module = 0; module <= numModules; module++) {
			monitor.checkCancelled();
			try {
				Map<Long, AbstractMsSymbol> symbols = debugInfo.getModuleSymbolsByOffset(module);
				numSymbols += symbols.size();
				for (Map.Entry<Long, AbstractMsSymbol> entry : symbols.entrySet()) {
					monitor.checkCancelled();
					AbstractMsSymbol symbol = entry.getValue();
					String symbolString = symbol.toString();
					if (symbolString.contains(searchString)) {
						results.append("Module " + module + ", Offset " + entry.getKey() + ":\n");
						results.append(symbolString);
						results.append('\n');
					}
					monitor.incrementProgress(1);
				}
			}
			catch (PdbException e) {
				Msg.debug(PdbQuery.class, "Skipping module " + module + " due to exception.");
			}
		}
		println(script, results.toString());
	}

	/**
	 * Method for outputting a message to the console (if script is not null); otherwise outputs
	 * the message to Msg.info()
	 * @param script the script
	 * @param message the message to output to the console
	 */
	private static void println(GhidraScript script, String message) {
		if (script != null) {
			script.println(message);
		}
		else {
			Msg.info(PdbQuery.class, message);
		}
	}

}
