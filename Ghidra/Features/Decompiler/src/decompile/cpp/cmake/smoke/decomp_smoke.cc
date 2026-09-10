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
// Smoke test for the decomp library.
//
//   decomp_smoke --check-capabilities
//       Initialize the library the way startDecompilerLibrary does and check
//       that the capability singletons registered from static initializers
//       are present: architectures "xml" and "raw", languages "c-language"
//       and "java-language".  "bfd" must be present exactly when the build
//       compiled the libbfd loader (GHIDRA_DECOMP_SMOKE_EXPECT_BFD).
//       A plain static archive drops these objects; this test proves the
//       whole-archive link of ghidra::decomp.
//
//   decomp_smoke --version
//       Print the decompiler interface version.

#include "architecture.hh"
#include "printlanguage.hh"

#include <cstring>
#include <iostream>

#ifndef GHIDRA_DECOMP_SMOKE_EXPECT_BFD
#define GHIDRA_DECOMP_SMOKE_EXPECT_BFD 0
#endif

namespace {

using namespace ghidra;
using std::cerr;
using std::cout;

int checkCapabilities(void)

{
  AttributeId::initialize();
  ElementId::initialize();
  CapabilityPoint::initializeAll();
  ArchitectureCapability::sortCapabilities();

  int failures = 0;
  const char *archs[] = { "xml", "raw" };
  for(int i=0;i<2;++i) {
    bool present = ArchitectureCapability::getCapability(archs[i]) != (ArchitectureCapability *)0;
    cout << "architecture " << archs[i] << ": " << (present ? "present" : "MISSING") << endl;
    if (!present)
      failures += 1;
  }
  const char *langs[] = { "c-language", "java-language" };
  for(int i=0;i<2;++i) {
    bool present = PrintLanguageCapability::findCapability(langs[i]) != (PrintLanguageCapability *)0;
    cout << "language " << langs[i] << ": " << (present ? "present" : "MISSING") << endl;
    if (!present)
      failures += 1;
  }
  bool bfd = ArchitectureCapability::getCapability("bfd") != (ArchitectureCapability *)0;
  bool expectBfd = GHIDRA_DECOMP_SMOKE_EXPECT_BFD != 0;
  cout << "architecture bfd: " << (bfd ? "present" : "absent")
       << " (expected " << (expectBfd ? "present" : "absent") << ")" << endl;
  if (bfd != expectBfd)
    failures += 1;

  PrintLanguageCapability *def = PrintLanguageCapability::getDefault();
  cout << "default language: " << (def != (PrintLanguageCapability *)0 ? def->getName() : string("MISSING")) << endl;
  if (def == (PrintLanguageCapability *)0)
    failures += 1;

  if (failures == 0)
    cout << "capabilities: ok" << endl;
  else
    cout << "capabilities: " << failures << " check(s) failed" << endl;
  return failures == 0 ? 0 : 1;
}

} // End anonymous namespace

int main(int argc,char **argv)

{
  using namespace ghidra;
  using std::cerr;
  using std::cout;

  if (argc == 2 && strcmp(argv[1],"--check-capabilities") == 0)
    return checkCapabilities();
  if (argc == 2 && strcmp(argv[1],"--version") == 0) {
    cout << ArchitectureCapability::getMajorVersion() << '.' << ArchitectureCapability::getMinorVersion() << endl;
    return 0;
  }
  cerr << "USAGE: " << argv[0] << " --check-capabilities | --version" << endl;
  return 2;
}
