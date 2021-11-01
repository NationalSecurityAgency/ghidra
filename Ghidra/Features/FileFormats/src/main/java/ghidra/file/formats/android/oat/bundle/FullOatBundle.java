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
package ghidra.file.formats.android.oat.bundle;

import java.io.IOException;
import java.util.*;

import org.apache.commons.io.FilenameUtils;

import ghidra.app.util.bin.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.file.formats.android.art.*;
import ghidra.file.formats.android.dex.DexHeaderFactory;
import ghidra.file.formats.android.dex.format.DexHeader;
import ghidra.file.formats.android.oat.OatHeader;
import ghidra.file.formats.android.vdex.*;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class FullOatBundle implements OatBundle {

	private Program oatProgram;
	private OatHeader oatHeader;
	private VdexHeader vdexHeader;
	private ArtHeader artHeader;
	private List<DexHeader> dexHeaders = new ArrayList<>();
	private Map<Integer, DexHeader> dexHeadersMap = new HashMap<>();

	private boolean isLittleEndian;

	FullOatBundle(Program oatProgram, OatHeader oatHeader, TaskMonitor monitor,
			MessageLog log) {

		this.oatProgram = oatProgram;
		this.oatHeader = oatHeader;

		this.isLittleEndian = !oatProgram.getLanguage().isBigEndian();

		loadVdexHeader(oatProgram, monitor, log);
		loadDexHeaders(oatProgram, monitor, log);
		loadArtHeader(oatProgram, monitor, log);
	}

	@Override
	public void close() {
		oatProgram = null;
		oatHeader = null;
		vdexHeader = null;
		artHeader = null;
		dexHeaders.clear();
		dexHeadersMap.clear();
	}

	@Override
	public DexHeader getDexHeaderByChecksum(int checksum) {
		for (DexHeader dexHeader : dexHeaders) {
			if (dexHeader.getChecksum() == checksum) {
				return dexHeader;
			}
		}
		if (vdexHeader != null) {
			for (int i = 0; i < vdexHeader.getDexChecksums().length; ++i) {
				if (vdexHeader.getDexChecksums()[i] == checksum) {
					//first check in VDEX, then check for DEX
					if (vdexHeader.getDexHeaderList().size() > i) {
						return vdexHeader.getDexHeaderList().get(i);
					}
					//get from map by classesN.dex index
					return dexHeadersMap.get(i);
				}
			}
		}
		return null;//could NOT find matching dex header, probably not imported yet
	}

	public ArtHeader getArtHeader() {
		return artHeader;
	}

	@Override
	public OatHeader getOatHeader() {
		return oatHeader;
	}

	public List<DexHeader> getDexHeaders() {
		return dexHeaders;
	}

	public VdexHeader getVdexHeader() {
		return vdexHeader;
	}

	private void loadVdexHeader(Program oatProgram, TaskMonitor monitor, MessageLog log) {
		monitor.setMessage("Loading VDEX headers...");

		String baseName = FilenameUtils.removeExtension(oatProgram.getName());
		String vdexProgramName = baseName + VDEX;

		DomainFile domainFile = oatProgram.getDomainFile();
		DomainFolder parentFolder = domainFile.getParent();

		//first, look in current project for VDEX file....
		if (lookInProjectFolder(HeaderType.VDEX, parentFolder, 
			vdexProgramName, monitor, log)) {
			return;
		}
		if (lookInProjectFolder(HeaderType.VDEX, parentFolder.getParent(), 
			vdexProgramName, monitor, log)) {
			return;
		}
	}

	private void loadDexHeaders(Program oatProgram, TaskMonitor monitor, MessageLog log) {
		monitor.setMessage("Loading DEX headers...");

		DomainFolder odexApkFolder = getOdexApkOrJarFolder();
		if (odexApkFolder != null) {
			for (DomainFile file : odexApkFolder.getFiles()) {
				if (monitor.isCancelled()) {
					break;
				}
				if (file.getName().startsWith(CLASSES) && file.getName().endsWith(DEX)) {
					lookInProjectFolder(HeaderType.DEX, odexApkFolder, file.getName(),
						monitor, log);
				}
			}
		}

		DomainFolder apkOrJarFolder = getApkOrJarFolder();
		if (apkOrJarFolder != null) {
			for (DomainFile file : apkOrJarFolder.getFiles()) {
				if (monitor.isCancelled()) {
					break;
				}
				if (file.getName().startsWith(CLASSES) && file.getName().endsWith(DEX)) {
					lookInProjectFolder(HeaderType.DEX, apkOrJarFolder, file.getName(),
						monitor, log);
				}
			}
		}

		DomainFolder appVdexFolder = getAppVdexFolder();
		if (appVdexFolder != null) {
			for (DomainFile file : appVdexFolder.getFiles()) {
				if (monitor.isCancelled()) {
					break;
				}
				if (file.getName().startsWith(CDEX)) {
					lookInProjectFolder(HeaderType.CDEX, appVdexFolder, file.getName(),
						monitor, log);
				}
			}
		}
	}

	private void loadArtHeader(Program oatProgram, TaskMonitor monitor, MessageLog log) {
		monitor.setMessage("Loading ART headers...");

		String baseName = FilenameUtils.removeExtension(oatProgram.getName());
		String artProgramName = baseName + ART;

		DomainFile domainFile = oatProgram.getDomainFile();
		DomainFolder parentFolder = domainFile.getParent();

		//first, look in current project for ART file....
		if (lookInProjectFolder(HeaderType.ART, parentFolder,
			artProgramName, monitor, log)) {
			return;
		}
		if (lookInProjectFolder(HeaderType.ART, parentFolder.getParent(),
			artProgramName, monitor, log)) {
			return;
		}
	}

	/**
	 * Looks in the specified project folder for a program with the specified name.
	 * If found, then create a header of the specified type.
	 * @param type the FileType
	 * @param parentFolder the project folder
	 * @param programName the program name
	 * @param monitor the task monitor
	 * @param log the message log
	 */
	private boolean lookInProjectFolder(HeaderType type, DomainFolder parentFolder,
			String programName,
			TaskMonitor monitor, MessageLog log) {

		DomainFile child = parentFolder.getFile(programName);
		if (child != null) {
			Program program = null;
			try {
				program = (Program) child.getDomainObject(this, true, true, monitor);
				ByteProvider provider =
					new MemoryByteProvider(program.getMemory(), program.getMinAddress());
				return makeHeader(type, programName, provider, monitor);
			}
			catch (Exception e) {
				log.appendMsg("Unable to locate matching: " + type);
			}
			finally {
				if (program != null) {
					program.release(this);
				}
			}
		}
		return false;
	}

	private int getDexIndex(String dexName) {
		try {
			if (dexName.startsWith(CLASSES) && dexName.endsWith(DEX)) {
				String indexString =
					dexName.substring(CLASSES.length(), dexName.length() - DEX.length());
				if (indexString.length() == 0) {//this case is where name is "classes.dex"
					return 0;
				}
				//this case handles classes2.dex, classes3.dex, ... classesN.dex 
				return Integer.parseInt(indexString) - 1;//must subtract one since Android starts counting at 1!!
			}
		}
		catch (Exception e) {
			//ignore
		}
		return -1;
	}

	private DomainFolder getApkOrJarFolder() {
		String baseName = FilenameUtils.removeExtension(oatProgram.getName());

		DomainFile domainFile = oatProgram.getDomainFile();
		String pathName = domainFile.getPathname();
		if (pathName.matches(".*/[^/]*/[^/]*")) {
			DomainFolder parentFolder = domainFile.getParent();//APP_DIR/oat/platform/
			parentFolder = parentFolder.getParent();//APP_DIR/oat/
			parentFolder = parentFolder.getParent();//APP_DIR/

			if (parentFolder.getFolder(baseName + APK) != null) {
				return parentFolder.getFolder(baseName + APK);//APP_DIR/APP.apk/
			}
			else if (parentFolder.getFolder(baseName + JAR) != null) {
				return parentFolder.getFolder(baseName + JAR);//APP_DIR/APP.jar/
			}
		}
		return null;
	}

	private DomainFolder getAppVdexFolder() {
		String baseName = FilenameUtils.removeExtension(oatProgram.getName());
		DomainFile domainFile = oatProgram.getDomainFile();
		DomainFolder parentFolder = domainFile.getParent();
		return parentFolder.getFolder(baseName + VDEX);
	}

	/**
	 * ODEX files can contain APKs or JARs.
	 */
	private DomainFolder getOdexApkOrJarFolder() {
		String baseName = FilenameUtils.removeExtension(oatProgram.getName());
		DomainFile domainFile = oatProgram.getDomainFile();
		DomainFolder parentFolder = domainFile.getParent();
		parentFolder = parentFolder.getFolder(baseName + ODEX);//APP_DIR.odex/
		if (parentFolder != null) {
			if (parentFolder.getFolder(baseName + APK) != null) {
				return parentFolder.getFolder(baseName + APK);//APP_DIR/APP.apk/
			}
			else if (parentFolder.getFolder(baseName + JAR) != null) {
				return parentFolder.getFolder(baseName + JAR);//APP_DIR/APP.jar/
			}
		}
		return null;
	}

	private boolean makeHeader(HeaderType type, String programName, ByteProvider provider,
			TaskMonitor monitor) throws IOException, UnsupportedVdexVersionException,
			CancelledException, UnsupportedArtVersionException {

		BinaryReader reader = new BinaryReader(provider, isLittleEndian);
		switch (type) {
			case ART: {
				ArtHeader artHeader = ArtFactory.newArtHeader(reader);
				this.artHeader = artHeader;
				return true;
			}
			case CDEX:
			case DEX: {
				DexHeader dexHeader = DexHeaderFactory.getDexHeader(reader, true);
				dexHeaders.add(dexHeader);
				dexHeadersMap.put(getDexIndex(programName), dexHeader);
				return true;
			}
			case VDEX: {
				VdexHeader vdexHeader = VdexFactory.getVdexHeader(reader);
				vdexHeader.parse(reader, monitor);
				this.vdexHeader = vdexHeader;
				return true;
			}
		}
		return false;
	}

}
