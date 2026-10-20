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
package ghidra.app.util.sourcelanguage;

import java.io.IOException;
import java.util.*;

import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.lang3.StringUtils;

import generic.jar.ResourceFile;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.sourcelanguage.SourceLanguageDataArchive.DataArchiveRule;
import ghidra.app.util.sourcelanguage.SourceLanguageSpecExtension.SpecExtensionRule;
import ghidra.program.database.SpecExtension;
import ghidra.program.database.SpecExtension.DocInfo;
import ghidra.program.model.lang.LanguageDescription;
import ghidra.program.model.listing.Program;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.classfinder.ExtensionPoint;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * A service for applying source language-related {@link ExtensionPoint}s to a {@link Program}
 */
public class SourceLanguageService {
	
	/**
	 * Finds any {@link SourceLanguage}s that 
	 * {@link SourceLanguage#existsIn(Program, TaskMonitor) exist in} the given program, and
	 * returns their {@link SourceLanguageID}s.
	 * <p>
	 * NOTE: This method does a fresh scan using 
	 * {@link SourceLanguage#existsIn(Program, TaskMonitor)} and does not check 
	 * {@link Program#getSourceLanguageIDs()}, so it may be slow.
	 * 
	 * @param program The {@link Program}
	 * @param log The error log
	 * @param monitor The {@link TaskMonitor}
	 * @return The {@link SourceLanguageID}s of the found {@link SourceLanguage}s
	 * @throws CancelledException if the user cancelled the operation
	 */
	public static Set<SourceLanguageID> find(Program program, MessageLog log, TaskMonitor monitor)
			throws CancelledException {
		Set<SourceLanguageID> foundSet = new HashSet<>();
		for (SourceLanguage sourceLanguage : ClassSearcher.getInstances(SourceLanguage.class)) {
			monitor.checkCancelled();
			SourceLanguageID id = sourceLanguage.getID();
			if (foundSet.contains(id)) {
				continue;
			}
			try {
				if (sourceLanguage.existsIn(program, monitor)) {
					foundSet.add(id);
				}
			}
			catch (IOException e) {
				log.appendMsg("Problem checking for %s in %s: %s".formatted(id, program.getName(),
					e.getMessage()));
			}
		}
		return foundSet;
	}

	/**
	 * Adds any {@link SourceLanguageSpecExtension}s that are compatible with the given set of 
	 * {@link SourceLanguageID}s to the {@link Program}
	 * 
	 * @param program The {@link Program}
	 * @param sourceLanguageIDs The {@link SourceLanguageID}s
	 * @param log The error log
	 * @param monitor The {@link TaskMonitor}
	 */
	public static void addSpecExtensions(Program program, Set<SourceLanguageID> sourceLanguageIDs,
			MessageLog log, TaskMonitor monitor) {
		for (SourceLanguageSpecExtension slse : ClassSearcher
				.getInstances(SourceLanguageSpecExtension.class)) {
			if (!sourceLanguageIDs.contains(slse.getCompatibleSourceLanguage())) {
				continue;
			}
			for (SpecExtensionRule rule : slse.getSpecExtensionRules(program, log, monitor)) {
				try {
					processSpecExtensionRule(rule, program, log, monitor);
				}
				catch (Exception e) {
					log.appendMsg("Failed to process spec extension: " + e.getMessage());
				}
			}
		}
	}

	/**
	 * Processes a single {@link SpecExtensionRule} and adds the spec extension it defines to the 
	 * given {@link Program}
	 * 
	 * @param rule The {@link SpecExtensionRule} to process
	 * @param program The {@link Program}
	 * @param log The error log
	 * @param monitor The {@link TaskMonitor}
	 * @return True if a spec extension was added to the {@link Program}; otherwise, false
	 * @throws Exception if there was a problem processing the {@link SpecExtensionRule}
	 */
	private static boolean processSpecExtensionRule(SpecExtensionRule rule, Program program,
			MessageLog log, TaskMonitor monitor) throws Exception {
		LanguageDescription desc = program.getLanguageCompilerSpecPair().getLanguageDescription();
		String programProcessor = desc.getProcessor().toString();
		String programEndian = desc.getEndian().toString();
		String programSize = Integer.toString(desc.getSize());
		String programVariant = desc.getVariant();
		String programFormat = program.getExecutableFormat();

		if (!rule.processor().equals(programProcessor)) {
			return false;
		}
		if (!StringUtils.isEmpty(rule.endian()) && !rule.endian().equals(programEndian)) {
			return false;
		}
		if (!StringUtils.isEmpty(rule.size()) && !rule.size().equals(programSize)) {
			return false;
		}
		if (!StringUtils.isEmpty(rule.variant()) && !rule.variant().equals(programVariant)) {
			return false;
		}
		if (!CollectionUtils.isEmpty(rule.formats()) &&
			rule.formats().stream().noneMatch(programFormat::equals)) {
			return false;
		}

		SpecExtension specExtension = new SpecExtension(program);
		String xml = rule.contents();
		DocInfo docInfo = specExtension.testExtensionDocument(xml);
		if (SpecExtension.getCompilerSpecExtension(program, docInfo) == null) {
			specExtension.addReplaceCompilerSpecExtension(xml, monitor);
		}
		return true;
	}

	/**
	 * Adds any {@link SourceLanguageDataArchive}s that are compatible with the given set of
	 * {@link SourceLanguageID}s to the {@link Program}
	 * 
	 * @param program The {@link Program}
	 * @param sourceLanguageIDs The {@link SourceLanguage}
	 * @param log The error log
	 * @param monitor The {@link TaskMonitor}
	 * @return The number of data archives that were added to the {@link Program}
	 */
	public static List<ResourceFile> getDataArchives(Program program,
			Set<SourceLanguageID> sourceLanguageIDs, MessageLog log, TaskMonitor monitor) {
		List<ResourceFile> ret = new ArrayList<>();
		for (SourceLanguageDataArchive slda : ClassSearcher
				.getInstances(SourceLanguageDataArchive.class)) {
			if (!sourceLanguageIDs.contains(slda.getCompatibleSourceLanguage())) {
				continue;
			}
			for (DataArchiveRule rule : slda.getDataArchiveRules(program, log, monitor)) {
				try {
					ResourceFile file = processDataArchiveRule(rule, program, log, monitor);
					if (file != null) {
						ret.add(file);
					}
				}
				catch (Exception e) {
					log.appendMsg("Failed to process data archive: " + e.getMessage());
				}
			}
		}
		return ret;
	}

	/**
	 * Processes a single {@link DataArchiveRule} and returns the data archive file if the archive
	 * should be applied to the program
	 * 
	 * @param rule The {@link DataArchiveRule} to process
	 * @param program The {@link Program}
	 * @param log The error log
	 * @param monitor The {@link TaskMonitor}
	 * @return The data archive file that should be applied to the program, or {@code null} if 
	 *   it should not be applied
	 * @throws Exception if there was a problem processing the {@link DataArchiveRule}
	 */
	private static ResourceFile processDataArchiveRule(DataArchiveRule rule, Program program,
			MessageLog log, TaskMonitor monitor) throws Exception {
		LanguageDescription desc = program.getLanguageCompilerSpecPair().getLanguageDescription();
		String programProcessor = desc.getProcessor().toString();
		String programEndian = desc.getEndian().toString();
		String programSize = Integer.toString(desc.getSize());
		String programVariant = desc.getVariant();
		String programFormat = program.getExecutableFormat();

		if (!StringUtils.isEmpty(rule.processor()) && !rule.processor().equals(programProcessor)) {
			return null;
		}
		if (!StringUtils.isEmpty(rule.endian()) && !rule.endian().equals(programEndian)) {
			return null;
		}
		if (!StringUtils.isEmpty(rule.size()) && !rule.size().equals(programSize)) {
			return null;
		}
		if (!StringUtils.isEmpty(rule.variant()) && !rule.variant().equals(programVariant)) {
			return null;
		}
		if (!CollectionUtils.isEmpty(rule.formats()) &&
			rule.formats().stream().noneMatch(programFormat::equals)) {
			return null;
		}
		
		return rule.dataArchiveFile();
	}
}
