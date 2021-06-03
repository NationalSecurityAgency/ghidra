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
#include <iostream>
#include <cstdlib>

#include "libdecomp.hh"

class IfcLoadFile : public IfaceDecompCommand {
public:
  virtual void execute(istream &s);
};

class IfcAddpath : public IfaceDecompCommand {
public:
  virtual void execute(istream &s);
};

class IfcSave : public IfaceDecompCommand {
public:
  virtual void execute(istream &s);
};

class IfcRestore : public IfaceDecompCommand {
public:
  virtual void execute(istream &s);
};

void IfcLoadFile::execute(istream &s)

{
  string filename,target;

  if (dcp->conf != (Architecture *)0) 
    throw IfaceExecutionError("Load image already present");
  s >> filename;
  if (!s.eof()) {		// If there are two parameters
    target = filename;		// Second is filename, first is target
    s >> filename;
  }
  else
    target = "default";

  ArchitectureCapability *capa = ArchitectureCapability::findCapability(filename);
  if (capa == (ArchitectureCapability *)0)
    throw IfaceExecutionError("Unable to recognize imagefile "+filename);
  dcp->conf = capa->buildArchitecture(filename,target,status->optr);
				// Attempt to open file and discern
				// the processor architecture  
  DocumentStorage store;	// temporary storage for xml docs

#ifdef CPUI_RULECOMPILE
  if (dcp->experimental_file.size() != 0) {
    *status->optr << "Trying to parse " << dcp->experimental_file << " for experimental rules" << endl;
    try {
      Element *root = store.openDocument(dcp->experimental_file)->getRoot();
      if (root->getName() == "experimental_rules")
	store.registerTag(root);
      else
	*status->optr << "Wrong tag type for experimental rules: "+root->getName() << endl;
    }
    catch(XmlError &err) {
      *status->optr << err.explain << endl;
      *status->optr << "Skipping experimental rules" << endl;
    }
  }
#endif
  string errmsg;
  bool iserror = false;
  try {
    dcp->conf->init(store);
  } catch(XmlError &err) {
    errmsg = err.explain;
    iserror = true;
  } catch(LowlevelError &err) {
    errmsg = err.explain;
    iserror = true;
  }
  if (iserror) {
    *status->optr << errmsg << endl;
    *status->optr << "Could not create architecture" << endl;
    delete dcp->conf;
    dcp->conf = (Architecture *)0;
    return;
  }
  if (capa->getName() == "xml")		// If file is xml
    dcp->conf->readLoaderSymbols("::"); // Read in loader symbols
#ifdef OPACTION_DEBUG
  dcp->conf->setDebugStream(status->optr);
#endif
  *status->optr << filename << " successfully loaded: " << dcp->conf->getDescription() << endl;
}

void IfcAddpath::execute(istream &s)

{
  string newpath;

  s >> newpath;
  if (newpath.empty())
    throw IfaceParseError("Missing path name");
  SleighArchitecture::specpaths.addDir2Path(newpath);
}

static string savefile;

void IfcSave::execute(istream &s)

{				// Save state to filename specified on command line
  ofstream fs;

  s >> ws;
  if (!s.eof())
    s >> savefile;

  if (savefile.size()==0)
    throw IfaceParseError("Missing savefile name");

  fs.open( savefile.c_str() );
  if (!fs)
    throw IfaceExecutionError("Unable to open file: "+savefile);

  dcp->conf->saveXml(fs);
  fs.close();
}

void IfcRestore::execute(istream &s)

{				// Restore saved state
  s >> savefile;
  if (savefile.size()==0)
    throw IfaceParseError("Missing file name");

  DocumentStorage store;
  Document *doc = store.openDocument(savefile);
  store.registerTag(doc->getRoot());
  dcp->clearArchitecture();	// Clear any old architecture
  ArchitectureCapability *capa = ArchitectureCapability::findCapability(doc);
  if (capa == (ArchitectureCapability *)0)
    throw IfaceExecutionError("Could not find savefile tag");
  dcp->conf = capa->buildArchitecture("","",status->optr);
  try {
    dcp->conf->restoreXml(store);
  } catch(LowlevelError &err) {
    throw IfaceExecutionError(err.explain);
  } catch(XmlError &err) {
    throw IfaceExecutionError(err.explain);
  }
  
#ifdef OPACTION_DEBUG
  dcp->conf->setDebugStream(status->optr);
#endif
  *status->optr << savefile << " successfully loaded: " << dcp->conf->getDescription() << endl;
}

int main(int argc,char **argv)

{
  const char *initscript = (const char *)0;

  {
    vector<string> extrapaths;
    int4 i = 1;
    while ((i < argc) && (argv[i][0] == '-')) {
      if (argv[i][1] == 'i')
	initscript = argv[++i];
      else if (argv[i][1] == 's')
	extrapaths.push_back(argv[++i]);
      i += 1;
    }

    string ghidraroot = FileManage::discoverGhidraRoot(argv[0]);
    if (ghidraroot.size() == 0) {
      const char *sleighhomepath = getenv("SLEIGHHOME");
      if (sleighhomepath == (const char*) 0) {
	if (extrapaths.empty()) {
	  cerr << "Could not discover root of Ghidra installation" << endl;
	  exit(1);
	}
      }
      else
	ghidraroot = sleighhomepath;
    }
    startDecompilerLibrary(ghidraroot.c_str(), extrapaths);
  }

  IfaceStatus *status;
  try {
    status = new IfaceTerm("[decomp]> ",cin,cout); // Set up interface
  } catch(IfaceError &err) {
    cerr << "Interface error during setup: " << err.explain << endl;
    exit(1);
  }
  IfaceCapability::registerAllCommands(status);	// Register commands for decompiler and all modules

  // Extra commands specific to the console application
  status->registerCom(new IfcLoadFile(),"load","file");
  status->registerCom(new IfcAddpath(),"addpath");
  status->registerCom(new IfcSave(),"save");
  status->registerCom(new IfcRestore(),"restore");

  if (initscript != (const char *)0) {
    status->pushScript(initscript,"init> ");
    status->setErrorIsDone(true);
  }

  mainloop(status);
  int4 retval = status->isInError() ? 1 : 0;

#ifdef CPUI_STATISTICS
  IfaceDecompData *decompdata = (IfaceDecompData *)status->getData("decompile");
  decompdata->conf->stats->printResults(cout);
#endif

  try {
    delete status;
  } catch(IfaceError &err) {
    cerr << err.explain << endl;
  }

  shutdownDecompilerLibrary();

  exit(retval);
}

