// Labels model-specific PIC Special Function Registers (SFRs). Requires the Microchip MPLAB XC16 
// Compiler to be installed (https://www.microchip.com/mplab/compilers). The SFR information is 
// parsed from "Linker Script" files (https://sourceware.org/binutils/docs/ld/Scripts.html).
// @category PIC

import java.io.*;
import java.util.Map;
import java.util.Map.Entry;
import java.util.TreeMap;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSpace;
import util.CollectionUtils;

public class LabelPICSpecialFunctionRegisters extends GhidraScript {

	@Override
	public void run() throws Exception {
		AddressSpace ram = currentProgram.getAddressFactory().getAddressSpace("ram");
		File supportDir = askDirectory("Select Microchip xc16 support directory", "Select");
		Map<String, File> linkerScriptMap = findLinkerScriptFiles(supportDir);
		if (linkerScriptMap.isEmpty()) {
			printerr("Failed to find any Linker Script files!");
			return;
		}
		String choice = askChoice("Processor", "Select processor",
			CollectionUtils.asList(linkerScriptMap.keySet()), null);
		File linkerScriptFile = linkerScriptMap.get(choice);
		for (Entry<Integer, String> entry : parseSfrValues(linkerScriptFile).entrySet()) {
			int addr = entry.getKey();
			String name = entry.getValue();
			printf("Creating label 0x%04x -> %s\n", addr, name);
			createLabel(ram.getAddress(addr), name, true);
		}
	}

	/**
	 * Finds any Linker Script files nested in the given Microchip xc16 support directory
	 * 
	 * @param supportDir The Microchip xc16 support directory
	 * @return A sorted {@link Map} of processor names to Linker Script files
	 */
	private Map<String, File> findLinkerScriptFiles(File supportDir) {
		Map<String, File> linkerScriptMap = new TreeMap<>();

		File[] familyDirs = supportDir.listFiles();
		if (familyDirs == null) {
			printerr("Error finding processor family directories");
			return linkerScriptMap;
		}
		for (File familyDir : familyDirs) {
			String familyName = familyDir.getName();
			if (familyName.equals("generic") || familyName.equals("templates")) {
				continue;
			}
			File linkerScriptDir = new File(familyDir, "gld");
			if (!linkerScriptDir.isDirectory()) {
				continue;
			}
			File[] linkerScriptFiles = linkerScriptDir.listFiles();
			if (linkerScriptFiles == null) {
				printerr("Error listing Linker Script files at: " + linkerScriptDir);
				return linkerScriptMap;
			}
			for (File linkerScriptFile : linkerScriptFiles) {
				String linkerScriptName = linkerScriptFile.getName();
				String processorNamePrefix = "";
				if (familyName.startsWith("dsPIC")) {
					processorNamePrefix = familyName.substring(0, 5);
				}
				else if (familyName.startsWith("PIC")) {
					processorNamePrefix = familyName.substring(0, 3);
				}
				String processorNameSuffix = linkerScriptName.substring(1, linkerScriptName.length() - 4);
				String processorName = processorNamePrefix + processorNameSuffix;
				linkerScriptMap.put(processorName, linkerScriptFile);
			}
		}

		return linkerScriptMap;
	}

	/**
	 * Parses the given Linker Script file to extract a {@link Map} of Special Function Register 
	 * addresses to names
	 * 
	 * @param linkerScriptFile The Linker Script file to parse
	 * @return A sorted {@link Map} of Special Function Register addresses to names
	 * @throws IOException if there was an I/O related issue
	 */
	private Map<Integer, String> parseSfrValues(File linkerScriptFile) throws IOException {
		Map<Integer, String> sfrMap = new TreeMap<>();
		try (BufferedReader reader = new BufferedReader(new FileReader(linkerScriptFile))) {
			String line;
			boolean inSfrSection = false;
			while ((line = reader.readLine()) != null) {
				line = line.trim();
				if (line.isEmpty()) {
					continue;
				}
				if (line.contains("Equates for SFR") && !inSfrSection) {
					reader.readLine();               // end of comment line
					reader.readLine();               // blank line
					line = reader.readLine().trim(); // first SFR line
					inSfrSection = true;
				}
				if (inSfrSection) {
					String[] parts = line.split("\\s+");
					if (parts.length == 3 && parts[1].equals("=")) {
						String registerName = parts[0];
						String registerAddr = parts[2].substring(0, parts[2].length() - 1);
						sfrMap.putIfAbsent(Integer.decode(registerAddr), registerName);
					}
					else {
						break;
					}
				}
			}
		}
		return sfrMap;
	}
}
