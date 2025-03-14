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
package ghidra.app.util.bin.format.golang.rtti;

import static org.junit.Assert.*;

import java.io.*;
import java.lang.ProcessBuilder.Redirect;
import java.nio.file.StandardCopyOption;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.FilenameUtils;
import org.junit.Before;
import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.app.util.bin.format.golang.GoVer;
import ghidra.app.util.bin.format.golang.GoVerRange;
import ghidra.framework.Application;
import ghidra.framework.OperatingSystem;
import ghidra.util.MD5Utilities;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import utilities.util.FileUtilities;
import utility.function.Dummy;

/**
 * Methods to generate an api snapshot file for the golang symbol analyzer.
 * <p>
 * Depends on several external tools and sets of files to operate correctly.
 * <p>
 * <ul>
 * 	<li>Executables in the path:
 * 	<ul>
 * 		<li>git</li>
 * 		<li>go</li>
 * 		<li>go-api-parser</li>
 * 		<li>jd (json diff tool - http://github.com/josephburnett/jd)</li>
 * 	</ul>
 * 	</li>
 * 	<li>Golang git repo in $HOME/git/go</li>
 * 	<li>Go apisnapshot persistent storage dir: $HOME/go-api-snapshots (go1.NN.PP.json)</li>
 * 	<li>Results placed in:
 * 	<ul>
 * 		<li>minorver snapshots: Ghidra/Features/Base/data/typeinfo/golang/go1.NN.0.json</li>
 * 		<li>patchverdiffs: Ghidra/Features/Base/data/typeinfo/golang/patchverdiffs/go1.NN.NN.json.diff</li>
 * 	</ul>
 * 	</li>
 * </ul>
 */
public class GoApiSnapshotGeneratorTest extends AbstractGenericTest {
	private static final Pattern GO_VER_PATTERN = Pattern.compile("^go(\\d\\.\\d+(\\.\\d+)?)$");
	private static final File HOMEDIR = new File(System.getProperty("user.home"));

	/**
	 * Path to a golang git repo
	 */
	private static final File GOLANG_REPO_DIR = new File(HOMEDIR, "git/go");

	/**
	 * Path to a directory that will persistently store the snapshot files.  (its not reasonable
	 * to generate them each time as they can take several minutes each depending on the machine
	 * running the process, multiplied by the total number of minor.patch versions)
	 */
	private static final File APISNAPSHOT_FULL_JSONS_DIR = new File(HOMEDIR, "go-api-snapshots");

	private TaskMonitor monitor = TaskMonitor.DUMMY;

	private File workDir;
	private File systemGOROOT;
	private File golangGhidraTypeInfoDir;
	private File noretFuncsFile;
	private File diffsDir;

	@Before
	public void setup() throws IOException {
		workDir = createTempDirectory("goapisnapshotgenerator");
		systemGOROOT = getGOROOT();
		golangGhidraTypeInfoDir =
			Application.getModuleDataSubDirectory("typeinfo/golang").getFile(false);
		diffsDir = new File(golangGhidraTypeInfoDir, "patchverdiffs");
		noretFuncsFile =
			Application.getModuleDataFile("GolangFunctionsThatDoNotReturn").getFile(true);
	}

	static JsonPatch generateJsonDiff(File jsonFile1, File jsonFile2, File destFile)
			throws IOException {
		// Execute the json diff tool, producing a native "jd" formatted diff result on stdout
		// Produces an exit value of 1 when a non-empty diff is successfully created
		Process process = new ProcessBuilder("jd", jsonFile1.getPath(), jsonFile2.getPath())
				.redirectOutput(destFile)
				.redirectError(Redirect.DISCARD)
				.start();

		try {
			int exitValue = process.waitFor();
			if (exitValue != 1 /* 0 would be empty diff */) {
				throw new IOException("process exited with: " + exitValue);
			}
			JsonPatch jsonPatch = JsonPatch.read(destFile);
			return jsonPatch;
		}
		catch (InterruptedException e) {
			process.destroyForcibly();
			throw new IOException("Failed to finish", e);
		}
	}

	static File getJsonFilename(File dir, GoVer ver) {
		return new File(dir, "go%s.json".formatted(ver.toString()));
	}

	static File getDiffFilename(File dir, GoVer ver) {
		File f = getJsonFilename(dir, ver);
		return new File(f.getParentFile(), f.getName() + ".diff");
	}

	List<GoVer> getGoRepoVers(GoVerRange validRange) throws IOException {
		Set<GoVer> vers = new HashSet<>();

		execGitCmd(GOLANG_REPO_DIR, line -> {
			Matcher m = GO_VER_PATTERN.matcher(line);
			if (m.matches()) {
				GoVer goVer = GoVer.parse(m.group(1));
				if (!goVer.isInvalid() && validRange.contains(goVer)) {
					vers.add(goVer);
				}
			}
		}, "tag", "-l");

		List<GoVer> results = new ArrayList<>(vers);
		Collections.sort(results);
		return results;
	}

	/**
	 * Executes a git command.
	 * 
	 * @param gitRepoDir path to a git repo
	 * @param outputConsumer optional string consumer
	 * @param args git args
	 * @throws IOException if failure
	 */
	static void execGitCmd(File gitRepoDir, Consumer<String> outputConsumer, String... args)
			throws IOException {
		outputConsumer = Dummy.ifNull(outputConsumer);
		List<String> cmdArgs = new ArrayList<>(List.of("git", "-C", gitRepoDir.getPath()));
		cmdArgs.addAll(List.of(args));

		Process gitCmdProcess = new ProcessBuilder(cmdArgs) // git -C repodir blahblah
				.redirectError(Redirect.DISCARD)
				.start();
		BufferedReader inputReader = gitCmdProcess.inputReader();

		String line;
		while ((line = inputReader.readLine()) != null) {
			outputConsumer.accept(line);
		}

		try {
			int exitValue = gitCmdProcess.waitFor();
			if (exitValue != 0) {
				throw new IOException("Git error: %d [%s]".formatted(exitValue, cmdArgs));
			}
		}
		catch (InterruptedException e) {
			throw new IOException(e);
		}
	}

	/**
	 * Executes a go tool command, feeding the output of the command to the consumer.
	 *  
	 * @param goRoot optional path to a go install.  If null, go tool will be searched for in
	 * the OS's PATH
	 * @param cwd optional path to the working directory for the cmd
	 * @param outputConsumer string consumer
	 * @param args for the go tool command
	 * @throws IOException if failure
	 */
	static void execGoCmd(File goRoot, File cwd, Consumer<String> outputConsumer,
			String... args) throws IOException {
		File goToolBinary = null;
		if (goRoot != null) {
			goToolBinary = normalizeExecutablePath(new File(goRoot, "bin/go"));
		}
		else {
			goToolBinary = findInOSPathEnv("go");
		}
		if (goToolBinary == null || !goToolBinary.isFile()) {
			throw new IOException("missing go tool binary");
		}
		List<String> cmdArgs = new ArrayList<>();
		cmdArgs.add(goToolBinary.getPath());
		cmdArgs.addAll(List.of(args));

		ProcessBuilder goCmd = new ProcessBuilder(cmdArgs).redirectError(Redirect.DISCARD);
		if (cwd != null) {
			goCmd.directory(cwd);
		}

		if (goRoot != null) {
			Map<String, String> env = goCmd.environment();
			env.put("GOROOT", goRoot.getPath());
		}

		Process goCmdProcess = goCmd.start();
		BufferedReader inputReader = goCmdProcess.inputReader();

		String line;
		while ((line = inputReader.readLine()) != null) {
			outputConsumer.accept(line);
		}

		try {
			int exitValue = goCmdProcess.waitFor();
			if (exitValue != 0) {
				throw new IOException("Go cmd error: %d [%s]".formatted(exitValue, cmdArgs));
			}
		}
		catch (InterruptedException e) {
			throw new IOException(e);
		}
	}

	/**
	 * Returns the GOROOT value of whatever go tool is found in the current PATH
	 * 
	 * @return GOROOT path
	 * @throws IOException if failure
	 */
	static File getGOROOT() throws IOException {
		AtomicReference<String> val = new AtomicReference<String>();
		execGoCmd(null, null, val::set, "env", "GOROOT");
		String gorootStr = val.get();
		File result;
		return gorootStr != null && (result = new File(gorootStr)).isDirectory() ? result : null;
	}

	/**
	 * Returns the tag name for a specific go version.  (some minor .0 vers omit the .0 from the
	 * tag name)
	 * 
	 * @param goRepoDir go git repo dir
	 * @param ver go ver
	 * @return tag name
	 * @throws IOException if failure
	 */
	static String getGoRepoTagName(File goRepoDir, GoVer ver) throws IOException {
		if (ver.getPatch() == 0) {
			Set<String> matchingTags = new HashSet<>();
			String shortTagName = "go%d.%d".formatted(ver.getMajor(), ver.getMinor());
			execGitCmd(goRepoDir, line -> matchingTags.add(line), "tag", "-l", shortTagName);
			if (matchingTags.contains(shortTagName)) {
				return shortTagName;
			}
		}
		return "go%s".formatted(ver.toString());
	}

	static File findInOSPathEnv(String name) throws IOException {
		for (String pathEntry : System.getenv("PATH").split(File.pathSeparator)) {
			File path = new File(pathEntry);
			File testFile = normalizeExecutablePath(new File(path, name));
			if (testFile != null) {
				return testFile;
			}
		}
		throw new IOException(
			"Unable to find '%s' in PATH %s".formatted(name, System.getenv("PATH")));
	}

	static File normalizeExecutablePath(File f) throws IOException {
		if (OperatingSystem.CURRENT_OPERATING_SYSTEM == OperatingSystem.WINDOWS &&
			!FilenameUtils.getExtension(f.getName()).equals("exe")) {
			f = new File(f.getParentFile(), f.getName() + ".exe");
		}
		return f.isFile() ? f.getCanonicalFile() : null;
	}

	static void forEachFile(File resourceFile, CheckedConsumer<File, IOException> consumer)
			throws IOException {
		if (!resourceFile.isDirectory()) {
			return;
		}

		File[] files = resourceFile.listFiles();
		if (files == null) {
			return;
		}
		for (File child : files) {
			consumer.accept(child);
		}
	}

	static void recurseDir(File dir, CheckedConsumer<File, IOException> fileConsumer)
			throws IOException {
		forEachFile(dir, f -> {
			if (f.isFile()) {
				fileConsumer.accept(f);
			}
			else if (f.isDirectory()) {
				recurseDir(f, fileConsumer);
			}
		});
	}

	interface CheckedConsumer<T, E extends Throwable> {
		void accept(T t) throws E;
	}

	/**
	 * Build a frankenstein goroot directory using the guts of a go install (liveGoRoot) and
	 * the src directory from a specific tagged version of a go git repo directory.
	 * 
	 * @param goRepoDir path to a golang git repo
	 * @param liveGoRoot path to an installed golang instance
	 * @param ver go version to checkout from the git repo and copy to the new directory
	 * @return path to newly created goroot directory (under the workDir)
	 * @throws IOException if failure
	 */
	File createVersionedGoRoot(GoVer ver)
			throws IOException {
		String verTagName = getGoRepoTagName(GOLANG_REPO_DIR, ver);

		execGitCmd(GOLANG_REPO_DIR, null, "checkout", "-q", verTagName);

		File newGoRoot = new File(workDir, "goroot%s".formatted(ver));
		Msg.info(this, "Creating new GOROOT " + newGoRoot);

		FileUtilities.deleteDir(newGoRoot);
		FileUtilities.checkedMkdirs(newGoRoot);

		FileFilter notSrcDir = (f) -> {
			boolean isSrcDir = f.getParentFile().equals(systemGOROOT) && f.getName().equals("src");
			return !isSrcDir;
		};

		Msg.info(this, "Copying live GOROOT to versioned...");
		FileUtils.copyDirectory(systemGOROOT, newGoRoot, notSrcDir, true,
			StandardCopyOption.COPY_ATTRIBUTES);

		File repoSrcDir = new File(GOLANG_REPO_DIR, "src");
		File newSrcDir = new File(newGoRoot, "src");
		Msg.info(this, "Copying versioned src/...");
		FileUtils.copyDirectory(repoSrcDir, newSrcDir, null, true,
			StandardCopyOption.COPY_ATTRIBUTES);

		Msg.info(this, "Downloading mod dependencies...");
		recurseDir(newSrcDir, f -> {
			if (f.getName().equals("go.sum")) {
				Msg.info(this, "go mod download " + f.getParent());
				execGoCmd(newGoRoot, f.getParentFile(), null, "mod", "download", "-x");
			}
		});

		return newGoRoot;
	}

	/**
	 * This Junit test method will create any missing api snapshot files, as reflected by the
	 * golang versions present in the go git repo directory, and the current set of .json files
	 * in the persistent go-api-snapshots dir.
	 * <p>
	 * Usage will typically be:
	 * <ol>
	 * 	<li>Use git to bring GOLANG_REPO_DIR up to date with upstream golang:<br>
	 * 	<pre>git-repo-dir$ git fetch</pre>
	 * 	<li>Uncomment the @Test annotation to allow this test to run
	 * 	<li>Run this test
	 * 	<li>Refresh the Eclipse package explorer tree to see new files in the Features Base/data dir
	 * </ol>
	 * <p>
	 * Any tags in the golang git repo named go1.NN.PP will be used to create 
	 * new go1.NN.PP.json files and will be placed in the go-api-snapshot dir, and mirrored to 
	 * the data/typeinfo/golang and data/typeinfo/golang/patchverdiffs directory as
	 * needed.
	 * <p>
	 * Creating a snapshot file involves switching the golang git repo to the necessary tag,
	 * creating a temp goroot directory with the go/src/ directory from the git repo, and executing
	 * the go-api-parser tool that will use golang's built-in compiler/parser tool to parse all
	 * *.go source files under the go/src/ directory. 
	 * 
	 * @throws IOException if failure
	 */
	//@Test
	public void generateMissingSnapshotFiles() throws IOException {
		assertTrue("Missing Golang repo dir", GOLANG_REPO_DIR.isDirectory());
		assertTrue("Golang repo dir isn't git repo",
			new File(GOLANG_REPO_DIR, ".git").isDirectory());

		FileUtilities.checkedMkdirs(APISNAPSHOT_FULL_JSONS_DIR);
		FileUtilities.checkedMkdirs(golangGhidraTypeInfoDir);
		FileUtilities.checkedMkdirs(diffsDir);

		Set<GoVer> outOfRangeGoVers = new HashSet<>();
		List<GoVer> goVers = getGoRepoVers(GoVerRange.parse("1.15.0-"));
		Map<GoVer, List<GoVer>> goPatchVersMap = getGoMinorToPatchInfo(goVers);
		for (GoVer goMinorVer : goPatchVersMap.keySet().stream().sorted().toList()) {
			Msg.info(this, "Checking minor ver: " + goMinorVer);
			File jsonMinorVerFile = getJsonFilename(APISNAPSHOT_FULL_JSONS_DIR, goMinorVer);
			boolean rebuildAll = false;
			if (!jsonMinorVerFile.isFile()) {
				generateSnapshot(goMinorVer, jsonMinorVerFile);
				rebuildAll = true;
			}
			File jsonMinorVerDataFile = getJsonFilename(golangGhidraTypeInfoDir, goMinorVer); // the file seen by the Eclipse project
			if (!isFileEqual(jsonMinorVerFile, jsonMinorVerDataFile)) {
				// publish the go1.nn.0.json file from the persistent snapshots dir to the eclipse project dir
				FileUtilities.copyFile(jsonMinorVerFile, jsonMinorVerDataFile, false, monitor);
			}
			if (!GoRttiMapper.SUPPORTED_VERSIONS.contains(goMinorVer)) {
				outOfRangeGoVers.add(goMinorVer);
			}

			for (GoVer patchVer : goPatchVersMap.get(goMinorVer)) {
				if (patchVer.getPatch() == 0) {
					continue;
				}
				Msg.info(this, "  patch ver: " + patchVer);
				boolean rebuildPatchDiff = rebuildAll;
				File jsonPatchVerFile = getJsonFilename(APISNAPSHOT_FULL_JSONS_DIR, patchVer);
				if (!jsonPatchVerFile.isFile()) {
					generateSnapshot(patchVer, jsonPatchVerFile);
					rebuildPatchDiff = true;
				}
				File jsonPatchDiffFile = getDiffFilename(diffsDir, patchVer);
				if (rebuildPatchDiff || !jsonPatchDiffFile.isFile()) {
					Msg.info(this, "    generating diff %s -> %s".formatted(goMinorVer, patchVer));
					generateJsonDiff(jsonMinorVerFile, jsonPatchVerFile, jsonPatchDiffFile);
				}
				if (!GoRttiMapper.SUPPORTED_VERSIONS.contains(patchVer)) {
					outOfRangeGoVers.add(patchVer);
				}

			}
		}
		Msg.info(this, "Finished generateMisingSnapshotFiles");
		if (!outOfRangeGoVers.isEmpty()) {
			Msg.warn(this, "Golang SUPPORTED_VERSIONS might need updating: " + outOfRangeGoVers);
		}
	}

	Map<GoVer, List<GoVer>> getGoMinorToPatchInfo(List<GoVer> goVers) {
		return goVers.stream().collect(Collectors.groupingBy(v -> v.withPatch(0)));
	}

	boolean isFileEqual(File f1, File f2) throws IOException {
		if (!f1.isFile() || !f2.isFile()) {
			return false;
		}
		if (f1.length() != f2.length()) {
			return false;
		}
		return MD5Utilities.getMD5Hash(f1).equals(MD5Utilities.getMD5Hash(f2));
	}

	/**
	 * Generates an api snapshot of a specific golang version.
	 * <p>
	 * Note: this can take several minutes to complete.
	 * 
	 * @param ver go version (that must be present as a tag in the go git repo)
	 * @param destJsonFile json file to create with results of the snapshot 
	 * @throws IOException if failure
	 */
	void generateSnapshot(GoVer ver, File destJsonFile) throws IOException {
		Msg.info(this, "Generating golang api snapshot for " + ver);
		File newGoRoot = createVersionedGoRoot(ver);
		File newBinDir = new File(newGoRoot, "bin");
		File srcDir = new File(newGoRoot, "src");
		File logFile = new File(newGoRoot, "goapiparser.log");

		ProcessBuilder procBuilder = new ProcessBuilder("go-api-parser", // cmd, args follow 
			"-get_cgo", "-src=" + srcDir, "-out=" + destJsonFile, "-version=go" + ver.toString(),
			"-noret", noretFuncsFile.getPath()).directory(newGoRoot);
		Map<String, String> env = procBuilder.environment();
		env.put("GOROOT", newGoRoot.getPath());
		env.put("PATH", newBinDir.getPath());
		procBuilder.redirectErrorStream(true);
		procBuilder.redirectOutput(logFile);
		Process proc = procBuilder.start();
		try {
			Msg.info(GoApiSnapshotGeneratorTest.class, "Waiting for go-api-parser...");
			int exitResult = proc.waitFor();
			Msg.info(GoApiSnapshotGeneratorTest.class, "Finished: " + exitResult + ", " + logFile);
		}
		catch (InterruptedException e) {
			throw new IOException(e);
		}
		finally {
			String logText = FileUtilities.getText(logFile);
			Msg.info(GoApiSnapshotGeneratorTest.class, logText);

			Msg.info(GoApiSnapshotGeneratorTest.class, "Cleaning up tmp goroot " + newGoRoot);
			FileUtils.deleteDirectory(newGoRoot);
			Msg.info(GoApiSnapshotGeneratorTest.class, "Finished deleting goroot");
		}
	}

}
