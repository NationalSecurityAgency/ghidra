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
package help.validator;

import java.io.IOException;
import java.nio.file.*;
import java.util.*;
import java.util.Map.Entry;

import generic.jar.ResourceFile;
import ghidra.framework.Application;
import help.HelpBuildUtils;
import help.validator.links.*;
import help.validator.location.HelpModuleCollection;
import help.validator.model.*;

public class JavaHelpValidator {
	private static boolean debug;

	/** Files that are generated and may not exist at validation time */
	private static Set<String> EXCLUDED_FILE_NAMES = createExcludedFileSet();

	private static Set<String> createExcludedFileSet() {
		Set<String> set = new HashSet<>();

		// The expected format is the help path, without an extension (this helps catch multiple
		// references with anchors)
		set.add("help/topics/Misc/Tips");
		set.add("docs/WhatsNew");
		set.add("docs/README_PDB");

		return set;
	}

	private String moduleName;
	private HelpModuleCollection help;

	public JavaHelpValidator(String moduleName, HelpModuleCollection help) {
		this.moduleName = moduleName;
		this.help = help;
	}

	private void validateInternalFileLinks(LinkDatabase linkDatabase) {
		validateHelpDirectoryInternalLinks(help, linkDatabase);
	}

	private void validateHelpDirectoryInternalLinks(HelpModuleCollection helpCollection,
			LinkDatabase linkDatabase) {

		debug("validating internal help links for module: " + helpCollection);

		// resolve all links that can be found (any unresolved links are either external or bad)
		// Link resolution issues:
		// -Can't find file
		// -Found file, can't find internal anchor        
		List<InvalidLink> unresolvedLinks = new ArrayList<>();
		Collection<HREF> helpDirHREFs = helpCollection.getAllHREFs();
		debug("\tHREF count: " + helpDirHREFs.size());
		for (HREF href : helpDirHREFs) {
			if (href.isRemote()) {
				continue; // don't try to validate remote refs--let them go through as-is
			}
			Path referenceFileHelpPath = href.getReferenceFileHelpPath();
			HelpFile helpFile = helpCollection.getHelpFile(referenceFileHelpPath);
			validateHREFHelpFile(href, helpFile, unresolvedLinks);
		}

		//
		// now resolve all image links
		// 
		Collection<IMG> helpDirIMGs = helpCollection.getAllIMGs();
		debug("\tIMG count: " + helpDirIMGs.size());
		for (IMG img : helpDirIMGs) {
			validateIMGFile(img, unresolvedLinks);
		}

		linkDatabase.addUnresolvedLinks(unresolvedLinks);

		// 
		// check for duplicate anchor references
		//
		Map<HelpFile, Map<String, List<AnchorDefinition>>> duplicateAnchors =
			helpCollection.getDuplicateAnchorsByFile();
		debug("\tHelp files with duplicate anchors: " + duplicateAnchors.size());
		for (Entry<HelpFile, Map<String, List<AnchorDefinition>>> entry : duplicateAnchors.entrySet()) {
			HelpFile helpFile = entry.getKey();
			Map<String, List<AnchorDefinition>> list = entry.getValue();
			linkDatabase.addDuplicateAnchors(
				new DuplicateAnchorCollectionByHelpFile(helpFile, list));
		}

		Map<HelpTopic, List<AnchorDefinition>> duplicateAnchorsByTopic =
			helpCollection.getDuplicateAnchorsByTopic();
		debug("\tHelp topics with duplicate anchors: " + duplicateAnchorsByTopic.size());
		Set<Entry<HelpTopic, List<AnchorDefinition>>> entrySet = duplicateAnchorsByTopic.entrySet();
		for (Entry<HelpTopic, List<AnchorDefinition>> entry : entrySet) {
			linkDatabase.addDuplicateAnchors(
				new DuplicateAnchorCollectionByHelpTopic(entry.getKey(), entry.getValue()));
		}
	}

	private void validateIMGFile(IMG img, List<InvalidLink> unresolvedLinks) {
		// 
		// Try to resolve the given image link
		//
		if (img.isRemote()) {
			return; // don't even try to verify a remote URL
		}

		if (img.isRuntime()) {

			//
			// The tool will load this image at runtime--don't perform normal validation
			// (runtime means an icon to be loaded from a Java file)
			// 
			if (img.isInvalid()) {
				unresolvedLinks.add(new InvalidRuntimeIMGFileInvalidLink(img));
				return;
			}
			return;
		}

		Path imagePath = img.getImageFile();
		if (imagePath == null) {
			unresolvedLinks.add(new NonExistentIMGFileInvalidLink(img));
			return;
		}

		//
		// Look first in the help system, then in the modules' resources
		//
		Path testPath = findPathInHelp(img);
		if (testPath == null) {
			// not in a help dir; perhaps the image lives in module's resource dir?
			testPath = findPathInModules(img);
		}

		if (testPath == null) {
			unresolvedLinks.add(new NonExistentIMGFileInvalidLink(img));
			return;
		}

		// O.K., file exists, but is the case correct
		if (!caseMatches(img, testPath)) {
			unresolvedLinks.add(new IncorrectIMGFilenameCaseInvalidLink(img));
		}
	}

	private Path findPathInHelp(IMG img) {

		Path imagePath = img.getImageFile();
		for (Path helpDir : help.getHelpRoots()) {
			Path toCheck = makePath(helpDir, imagePath);
			if (toCheck != null) {
				return toCheck;
			}
		}

		return null;
	}

	private Path findPathInModules(IMG img) {

		String rawSrc = img.getSrcAttribute();
		Collection<ResourceFile> moduleRoots = Application.getModuleRootDirectories();
		for (ResourceFile root : moduleRoots) {
			ResourceFile resourceDir = new ResourceFile(root, "src/main/resources");
			Path toCheck = makePath(resourceDir, rawSrc);
			if (toCheck != null) {
				return toCheck;
			}
		}

		return null;
	}

	private Path makePath(ResourceFile dir, String imgSrc) {

		if (!dir.exists()) {
			return null;
		}

		Path dirPath = Paths.get(dir.getAbsolutePath());
		Path imagePath = Paths.get(imgSrc);

		Path imageFileFS = HelpBuildUtils.toFS(dirPath, imagePath);
		Path toCheck = dirPath.resolve(imageFileFS);
		if (Files.exists(toCheck)) {
			return toCheck;
		}
		return null;
	}

	private Path makePath(Path helpDir, Path imagePath) {

		Path imageFileFS = HelpBuildUtils.toFS(helpDir, imagePath);
		imageFileFS = removeRedundantHelp(helpDir, imageFileFS);
		Path toCheck = helpDir.resolve(imageFileFS);
		if (Files.exists(toCheck)) {
			return toCheck;
		}
		return null;
	}

	private boolean caseMatches(IMG img, Path path) {

		// validate case (some platforms are case-sensitive)
		Path realPath;
		try {
			realPath = path.toRealPath(); // gets the actual filesystem name
		}
		catch (IOException e) {
			return false;
		}

		String realFilename = realPath.getFileName().toString();
		Path imagePath = img.getImageFile();
		String imageFilename = imagePath.getFileName().toString();

		if (realFilename.equals(imageFilename)) {
			return true;
		}

		return false;
	}

	private Path removeRedundantHelp(Path root, Path p) {
		if (p.startsWith("help")) {
			// this is the 'help system syntax'; may need to chop off 'help'
			if (root.endsWith("help")) {
				p = p.subpath(1, p.getNameCount());
			}
		}
		return p;
	}

	private void validateHREFHelpFile(HREF href, HelpFile helpFile,
			List<InvalidLink> unresolvedLinks) {

		if (helpFile == null) {
			if (isExcludedHREF(href)) {
				return; // ignore calls made to the the API as being invalid
			}
			unresolvedLinks.add(new MissingFileInvalidLink(href));
			return;
		}

		// we have found a help file, make sure the anchor is there
		String anchorName = href.getAnchorName();
		if (anchorName == null) {
			return; // no anchor to validate
		}
		if (!helpFile.containsAnchor(anchorName)) {
			unresolvedLinks.add(new MissingAnchorInvalidLink(href));
		}
	}

	private boolean isExcludedHREF(HREF href) {

		String path = href.getRefString();
		return isExcludedPath(path);
	}

	private boolean isExcludedPath(String path) {
		if (path.indexOf("/docs/api/") != -1) {
			// exclude all api files
			return true;
		}

		// strip off the extension
		int index = path.lastIndexOf(".");
		if (index != -1) {
			path = path.substring(0, index);
		}

		return EXCLUDED_FILE_NAMES.contains(path);
	}

	private void validateExternalFileLinks(LinkDatabase linkDatabase) {

		Collection<InvalidLink> unresolvedLinks = linkDatabase.getUnresolvedLinks();
		debug("validating " + unresolvedLinks.size() + " unresolved external links");

		// Link resolution issues:
		// -Can't find file
		// -Found file, can't find internal anchor
		// -Found file (and anchor if present), but module is an illegal dependency

		Set<InvalidLink> remainingInvalidLinks = new TreeSet<>();
		for (Iterator<InvalidLink> iterator = unresolvedLinks.iterator(); iterator.hasNext();) {
			InvalidLink link = iterator.next();
			if (!(link instanceof InvalidHREFLink)) {
				continue;
			}

			InvalidHREFLink invalidHREFLink = (InvalidHREFLink) link;
			if (invalidHREFLink instanceof MissingAnchorInvalidLink) {
				remainingInvalidLinks.add(link);
				continue;
			}

			HelpFile referencedHelpFile = linkDatabase.resolveLink(link);
			if (referencedHelpFile != null) {
				iterator.remove();
			}
		}

		linkDatabase.addUnresolvedLinks(remainingInvalidLinks);
	}

	private void validateExternalImageFileLinks(LinkDatabase linkDatabase) {
		Collection<InvalidLink> unresolvedLinks = linkDatabase.getUnresolvedLinks();
		debug("validating " + unresolvedLinks.size() + " unresolved external image links");

		// Link resolution issues:
		// -Can't find file
		// -Found file, but module is an illegal dependency
		Set<InvalidLink> remainingInvalidLinks = new TreeSet<>();
		for (InvalidLink link : unresolvedLinks) {
			if (link instanceof NonExistentIMGFileInvalidLink) {
				remainingInvalidLinks.add(link);
				continue;
			}
		}

		linkDatabase.addUnresolvedLinks(remainingInvalidLinks);
	}

	private void validateTOCItemIDs(LinkDatabase linkDatabase) {
		debug("Validating TOC item IDs...");
		List<InvalidLink> unresolvedLinks = new ArrayList<>();

		Collection<TOCItem> items = help.getInputTOCItems();

		debug("\tvalidating " + items.size() + " TOC item references for module: " + moduleName);
		for (TOCItem item : items) {
			if (!item.validate(linkDatabase)) {
				if (item instanceof TOCItemReference) {
					TOCItemReference reference = (TOCItemReference) item;
					unresolvedLinks.add(new MissingTOCDefinitionInvalidLink(help, reference));
				}
				else {
					String targetPath = item.getTargetAttribute();
					if (!isExcludedPath(targetPath)) {
						unresolvedLinks.add(new MissingTOCTargetIDInvalidLink(help, item));
					}
				}
			}
		}

		//
		// Note: we have to validate the target links of the TOC file here, *after* we 
		//       validate the links, as until then, references aren't resolved
		// 
		Collection<HREF> TOC_HREFs = help.getTOC_HREFs();
		debug("\tvalidating TOC links: " + TOC_HREFs.size());
		for (HREF href : TOC_HREFs) {
			Path referenceFileHelpPath = href.getReferenceFileHelpPath();
			HelpFile helpFile = linkDatabase.resolveFile(referenceFileHelpPath);
			validateHREFHelpFile(href, helpFile, unresolvedLinks);
		}

		linkDatabase.addUnresolvedLinks(unresolvedLinks);

		debug("\tfinished validating TOC item IDs...");
	}

	public Collection<InvalidLink> validate(LinkDatabase linkDatabase) {
		// validate internal links for each help file
		validateInternalFileLinks(linkDatabase);

		// validate external links
		validateExternalFileLinks(linkDatabase);
		validateExternalImageFileLinks(linkDatabase);

		validateTOCItemIDs(linkDatabase);

		return linkDatabase.getUnresolvedLinks();
	}

//==================================================================================================
// Static Methods
//==================================================================================================

	private static void debug(String message) {
		if (debug) {
			flush();
			System.out.println("[" + JavaHelpValidator.class.getSimpleName() + "] " + message);
		}
	}

	private static void flush() {
		System.out.flush();
		System.out.println();
		System.out.flush();
		System.err.flush();
		System.err.println();
		System.err.flush();
	}

	public void setDebugEnabled(boolean debug) {
		JavaHelpValidator.debug = debug;
	}
}
