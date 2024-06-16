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
package ghidra.macosx.plugins;

import java.io.IOException;
import java.util.List;

import docking.action.builder.ActionBuilder;
import ghidra.app.CorePluginPackage;
import ghidra.app.context.ProgramLocationActionContext;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.macho.MachException;
import ghidra.app.util.bin.format.macho.MachHeader;
import ghidra.app.util.bin.format.macho.commands.SegmentCommand;
import ghidra.app.util.bin.format.macho.dyld.*;
import ghidra.app.util.opinion.DyldCacheExtractLoader;
import ghidra.app.util.opinion.DyldCacheUtils.SplitDyldCache;
import ghidra.file.formats.ios.dyldcache.DyldCacheFileSystem;
import ghidra.formats.gfilesystem.*;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.plugin.importer.ImporterUtilities;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskMonitor;

/**
 * A {@link Plugin} that adds an action to build up a DYLD Cache from extracted components
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.COMMON,
	shortDescription = "DYLD Cache Builder",
	description = "This plugin provides actions for adding DYLD Cache components to the program"
)
//@formatter:on
public class DyldCacheBuilderPlugin extends Plugin {

	/**
	 * Creates a new {@link DyldCacheBuilderPlugin}
	 * 
	 * @param tool The {@link PluginTool} that will host/contain this {@link Plugin}
	 */
	public DyldCacheBuilderPlugin(PluginTool tool) {
		super(tool);
	}

	@Override
	protected void init() {
		super.init();

		String actionName = "Add To Program";
		new ActionBuilder(actionName, getName())
				.withContext(ProgramLocationActionContext.class)
				.enabledWhen(p -> p.getProgram()
						.getExecutableFormat()
						.equals(DyldCacheExtractLoader.DYLD_CACHE_EXTRACT_NAME))
				.onAction(plac -> TaskLauncher.launchModal(actionName,
					monitor -> addMissingDyldCacheComponent(plac.getLocation(), monitor)))
				.popupMenuPath("References", actionName)
				.popupMenuGroup("Add")
				.helpLocation(new HelpLocation("ImporterPlugin", "Add_To_Program"))
				.buildAndInstall(tool);
	}

	/**
	 * Attempts to add the DYLD Cache component that resides at the given {@link ProgramLocation}'s
	 * "referred to" address
	 * 
	 * @param location The {@link ProgramLocation} where the action took place
	 * @param monitor A {@link TaskMonitor}
	 */
	private void addMissingDyldCacheComponent(ProgramLocation location, TaskMonitor monitor) {
		Program program = location.getProgram();
		Address refAddress = location.getRefAddress();
		if (refAddress == null) {
			Msg.showInfo(this, null, name, "No referenced address selected");
			return;
		}
		if (refAddress.getAddressSpace().isExternalSpace()) {
			Msg.showInfo(this, null, name, "External locations are not currently supported");
			return;
		}
		if (program.getMemory().contains(refAddress)) {
			Msg.showInfo(this, null, name, "Referenced address already exists in memory");
			return;
		}

		try (FileSystemRef fsRef = openDyldCache(program, monitor)) {
			DyldCacheFileSystem fs = (DyldCacheFileSystem) fsRef.getFilesystem();
			SplitDyldCache splitDyldCache = fs.getSplitDyldCache();
			long refAddr = refAddress.getOffset();
			String fsPath = findInDylibSegment(refAddr, splitDyldCache);
			if (fsPath == null) {
				fsPath = findInStubs(refAddr, splitDyldCache);
			}
			if (fsPath == null) {
				fsPath = findInDyldData(refAddr, splitDyldCache);
			}
			if (fsPath != null) {
				ImporterUtilities.showAddToProgramDialog(fs.getFSRL().appendPath(fsPath), program,
					tool, monitor);
			}
			else {
				Msg.showInfo(this, null, name,
					"Address %s not found in %s".formatted(refAddress, fs.toString()));
			}
		}
		catch (CancelledException e) {
			// Do nothing
		}
		catch (MachException | IOException e) {
			Msg.showError(this, null, name, e.getMessage(), e);
		}
	}

	/**
	 * Attempts to open the given {@link Program}'s originating {@link DyldCacheFileSystem}
	 * 
	 * @param program The {@link Program}
	 * @param monitor A {@link TaskMonitor}
	 * @return A {@link FileSystemRef file system reference} to the open {@link DyldCacheFileSystem}
	 * @throws IOException if an FSRL or IO-related error occurred
	 * @throws CancelledException if the user cancelled the operation
	 */
	private FileSystemRef openDyldCache(Program program, TaskMonitor monitor)
			throws IOException, CancelledException {
		FSRL fsrl = FSRL.fromProgram(program);
		if (fsrl == null) {
			throw new IOException("The program does not have an FSRL property");
		}
		String requiredProtocol = DyldCacheFileSystem.DYLD_CACHE_FSTYPE;
		if (!fsrl.getFS().getProtocol().equals(requiredProtocol)) {
			throw new IOException("The program's FSRL protocol is '%s' but '%s' is required"
					.formatted(fsrl.getFS().getProtocol(), requiredProtocol));
		}
		FSRLRoot fsrlRoot = fsrl.getFS();
		return FileSystemService.getInstance().getFilesystem(fsrlRoot, monitor);
	}

	/**
	 * Attempts to find the given address in the DYLD Cache's DYLIB segments
	 * 
	 * @param addr The address to find
	 * @param splitDyldCache The {@link SplitDyldCache}
	 * @return The path of the DYLIB within the {@link DyldCacheFileSystem} that contains the given
	 *   address, or null if the address was not found
	 * @throws MachException if there was an error parsing a DYLIB header
	 * @throws IOException if an IO-related error occurred
	 */
	private String findInDylibSegment(long addr, SplitDyldCache splitDyldCache)
			throws MachException, IOException {
		for (int i = 0; i < splitDyldCache.size(); i++) {
			DyldCacheHeader dyldCacheHeader = splitDyldCache.getDyldCacheHeader(i);
			ByteProvider provider = splitDyldCache.getProvider(i);
			for (DyldCacheImage mappedImage : dyldCacheHeader.getMappedImages()) {
				MachHeader machHeader = new MachHeader(provider,
					mappedImage.getAddress() - dyldCacheHeader.getBaseAddress());
				for (SegmentCommand segment : machHeader.parseSegments()) {
					if (segment.contains(addr)) {
						return mappedImage.getPath();
					}
				}
			}
		}
		return null;
	}

	/**
	 * Attempts to find the given address in the DYLD Cache's text stubs
	 * 
	 * @param addr The address to find
	 * @param splitDyldCache The {@link SplitDyldCache}
	 * @return The path of the text stub within the {@link DyldCacheFileSystem} that contains the 
	 *   given address, or null if the address was not found
	 */
	private String findInStubs(long addr, SplitDyldCache splitDyldCache) {
		for (int i = 0; i < splitDyldCache.size(); i++) {
			String dyldCacheName = splitDyldCache.getName(i);
			DyldCacheHeader dyldCacheHeader = splitDyldCache.getDyldCacheHeader(i);
			for (DyldCacheMappingAndSlideInfo mappingInfo : dyldCacheHeader
					.getCacheMappingAndSlideInfos()) {
				if (mappingInfo.contains(addr) && mappingInfo.isTextStubs()) {
					return DyldCacheFileSystem.getStubPath(dyldCacheName);
				}
			}
		}
		return null;
	}

	/**
	 * Attempts to find the given address in the DYLD data
	 * 
	 * @param addr The address to find
	 * @param splitDyldCache The {@link SplitDyldCache}
	 * @return The path of the Dyld data within the {@link DyldCacheFileSystem} that contains the 
	 *   given address, or null if the address was not found
	 */
	private String findInDyldData(long addr, SplitDyldCache splitDyldCache) {
		for (int i = 0; i < splitDyldCache.size(); i++) {
			String dyldCacheName = splitDyldCache.getName(i);
			if (dyldCacheName.endsWith(".dylddata")) {
				DyldCacheHeader dyldCacheHeader = splitDyldCache.getDyldCacheHeader(i);
				List<DyldCacheMappingAndSlideInfo> mappingInfos =
					dyldCacheHeader.getCacheMappingAndSlideInfos();
				for (int j = 0; j < mappingInfos.size(); j++) {
					DyldCacheMappingAndSlideInfo mappingInfo = mappingInfos.get(j);
					if (mappingInfo.contains(addr)) {
						return DyldCacheFileSystem.getDyldDataPath(dyldCacheName, j);
					}
				}
			}
		}
		return null;
	}
}
