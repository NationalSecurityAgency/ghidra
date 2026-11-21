# AGENTS.md

Instructions for coding agents in this repository. The sources are [README.md](README.md),
[DevGuide.md](DevGuide.md) and [CONTRIBUTING.md](CONTRIBUTING.md). If this file and those files
disagree, those files are correct.

## Build

- Use JDK 25 (`application.java.min` in `Ghidra/application.properties`) and a Python version that
  `application.python.supported` in the same file lists, with pip.
- On Linux and macOS, install GCC or Clang, and make.
- Use `./gradlew` if Gradle 9.1.0 or later is not installed.
- Run Gradle in a UTF-8 locale, for example `export LC_ALL=C.UTF-8`.
  Some jar files have non-ASCII file names, and `buildGhidra` fails in the `C` or `POSIX` locale.
- Download the build dependencies into the repository one time:
  ```
  ./gradlew -I gradle/support/fetchDependencies.gradle
  ```
- Build Ghidra into `build/dist/` in an uncompressed form. This is enough to run and test a change:
  ```
  ./gradlew assembleAll
  ```
  `./gradlew buildGhidra` runs `assembleAll` and then compresses the result into a zip file.
- After a change to a `.slaspec` or `.sinc` file, compile the Sleigh files:
  ```
  ./gradlew sleighCompile
  ```
- If the compilation fails after a `git pull` for no clear cause, run `./gradlew clean`.

## Test

- Decompiler data tests are XML files in `Ghidra/Features/Decompiler/src/decompile/datatests/`.
  Run `./gradlew sleighCompile` first, then:
  ```
  cd Ghidra/Features/Decompiler/src/decompile/cpp
  make decomp_test_dbg
  ./decomp_test_dbg -sleighpath ../../../../../.. datatests
  ```
  Add file names (for example `ccmp.xml`) after `datatests` to run only those tests.
- `make decomp_test_dbg` links the zlib and libbfd libraries. Install their development files first.
- Before a Gradle build, run `make reallyclean` in that `cpp` directory.
  The `ip` task stops the build at each file that `make` wrote there.
- For the Java unit tests and integration tests, read "Running tests" in DevGuide.md.
- To run one test class of `src/test`:
  ```
  ./gradlew :<Module>:test --tests '<fully.qualified.Class>'
  ```
  For `src/test.slow`, use `:<Module>:integrationTest` instead of `:<Module>:test`.
- Gradle shows `BUILD SUCCESSFUL` when a test fails (`ignoreFailures = true` in
  `gradle/javaTestProject.gradle`). Read the results in `build/test-results/` of the module.

## IP lines

The `ip` task stops the build if a file has no IP line.

- A source file has its IP line in its first four lines, for example ` * IP: GHIDRA`.
  Copy the header of a nearby file of the same type.
- Each other new file needs one line in the `certification.manifest` of its module, in alphabetical order:
  ```
  src/decompile/datatests/example.xml||GHIDRA||||END|
  ```
  This applies to data tests (`.xml`), documents and data files.
- A new file in the repository root needs its line in `certification.local.manifest`.
- Check one module, for example the Decompiler:
  ```
  ./gradlew :Decompiler:ip
  ```

## Pull requests

- Make the smallest change that gives the result. Do not change indentation that the change does not need.
- Put each independent change in a separate pull request.
- Do not rename, repackage or refactor code without approval from the Ghidra team.
- Do not make "find and replace" changes or changes of code style only.
- Do not update jars or other third-party libraries. Open an issue for a library that you need.
- Do not add binary files that you generated.
- Make sure that the change compiles and runs in the development environment.
- Squash the commits to one commit that describes the change.
- Do not start a title or a commit message line with `#`.
- Do not put an issue number in the title. If the change fixes an open issue, write "Fixes #xxx" in the description.
- Do not open an issue for your own pull request. The pull request is enough.
- To update a branch, rebase it onto `master` and force-push. Do not merge `master` into it.
- Put the author name in the Git commit, not in the source code.
- Put GPL code only in the top-level `GPL/` directory, as a standalone module.
- Tag a pull request for the Debugger with "Debugger".
- Examine each AI suggestion for correctness and for the legal requirements in CONTRIBUTING.md.
