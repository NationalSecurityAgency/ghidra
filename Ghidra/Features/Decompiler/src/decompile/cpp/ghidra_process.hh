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
/// \file ghidra_process.hh
/// \brief The formal commands that can be issued to the decompiler by the Ghidra client

#ifndef __GHIDRA_PROCESS__
#define __GHIDRA_PROCESS__

#include "capability.hh"
#include "ghidra_arch.hh"
#include "typegrp_ghidra.hh"
#include "grammar.hh"
#include "paramid.hh"
#include <iostream>
#include <csignal>

class GhidraCommand;

/// \brief Registration point and dispatcher for commands sent to the decompiler
///
/// This is the base class for \b command \b capabilities (sets of commands).
/// All sets register their commands with a static \b commandmap. This
/// class provides the method readCommand(), which does the work of parsing
/// a command from the stream and dispatching to the correct GhidraCommand object.
class GhidraCapability : public CapabilityPoint {
protected:
  static map<string,GhidraCommand *> commandmap;	///< The central map from \e name to Ghidra command
  string name;						///< Identifier for capability and associated commands
public:
  const string &getName(void) const { return name; }	///< Get the capability name
  static int4 readCommand(istream &sin,ostream &out);	///< Dispatch a Ghidra command
  static void shutDown(void);				///< Release all GhidraCommand resources
};

/// \brief The core decompiler commands capability
///
/// This class is instantiated as a singleton and registers all the basic
/// decompiler commands that the Ghidra client can issue.
class GhidraDecompCapability : public GhidraCapability {
  static GhidraDecompCapability ghidraDecompCapability;		///< Singleton instance
  GhidraDecompCapability(void) { name = "decomp"; }		///< Construct the singleton
  GhidraDecompCapability(const GhidraDecompCapability &op2);	///< Not implemented
  GhidraDecompCapability &operator=(const GhidraDecompCapability &op2);	///< Not implemented
public:
  virtual void initialize(void);
};

/// \brief Base class for a \e command to the decompiler as issued by a Ghidra client.
///
/// A command object is provided i/o streams to the client, and the action of the command
/// is performed by calling the doit() method. This wraps the main sequence of methods:
///   - loadParameters()
///   - rawAction()
///   - sendResult()
///
/// At a minimum, loadParameters() will read an id to select the active ArchitectureGhidra object,
/// and sendResult() will send back any accumulated warning/error messages.
class GhidraCommand {
protected:
  istream &sin;				///< The input stream from the Ghidra client
  ostream &sout;			///< The output stream to the Ghidra client
  ArchitectureGhidra *ghidra;		///< The Architecture on which to perform the command
  int4 status;				///< Meta-command to system (0=wait for next command, 1=terminate process)
  virtual void loadParameters(void);	///< Read parameters directing command execution
  virtual void sendResult(void);	///< Send results of the command (if any) back to the Ghidra client
public:
  GhidraCommand(void) : sin(cin),sout(cout) {
    ghidra = (ArchitectureGhidra *)0; 
  }					///< Construct given i/o streams
  virtual ~GhidraCommand(void) {}	///< Destructor

  /// \brief Perform the action of the command
  ///
  /// Configuration is assumed to have happened, and \b this object can immediately begin
  /// examining and manipulating data under the active Architecture object to perform the command.
  virtual void rawAction(void)=0;
  int4 doit(void);			///< Configure and execute the command, then send back results
};

/// \brief Command to \b register a new Program (executable) with the decompiler
///
/// An id is assigned to the program, and an Architecture object for the program
/// is created and initialized. This must be issued before any other command.
/// The command expects four XML document parameters:
///   - The processor specification
///   - The compiler specification
///   - The stripped down \<sleigh> tag describing address spaces for the program
///   - The \<coretypes> tag describing the built-in datatypes for the program
class RegisterProgram : public GhidraCommand {
  string pspec;				///< Processor specification to configure with
  string cspec;				///< Compiler specification to configure with
  string tspec;				///< Configuration (address-spaces) for the Translate object
  string corespec;			///< A description of core data-types for the TypeFactory object
  virtual void loadParameters(void);
  virtual void sendResult(void);
public:
  int4 archid;				///< Resulting id of the program to send back
  virtual void rawAction(void);
};

/// \brief Command to \b release all resources associated with a Program (executable) in the decompiler
///
/// The command frees the ArchitectureGhidra object (recursively affecting all resources)
/// associated with the program.  A \e termination meta-command is issued for this process.
/// The command expects a single string parameter encoding the id of the program.
class DeregisterProgram : public GhidraCommand {
  int4 inid;				///< The id of the Architecture being terminated
  virtual void loadParameters(void);
  virtual void sendResult(void);
public:
  int4 res;				///< The meta-command being issued to send back
  virtual void rawAction(void);
};

/// \brief Command to \b flush all symbols associated with a Program (executable)
///
/// Clear out any Symbol, Scope, Datatype, and Funcdata objects that have accumulated
/// in the symbol table. This lets the decompiler keep a light-weight sync between
/// its view of symbols and the Ghidra client's. Subsequent decompilation will simply
/// (re)fetch any symbols as needed.
/// The command expects a single string parameter encoding the id of the program to flush.
class FlushNative : public GhidraCommand {
  virtual void sendResult(void);
public:
  int4 res;				///< Success status returned to the client (0=success)
  virtual void rawAction(void);
};

/// \brief Command to \b decompile a specific function.
///
/// The command expects 2 string parameters: the encoded integer id of the program,
/// and an \<addr> tag describing the entry point address of the function to decompile.
/// The function follows flow from the entry point up to RETURN ops or other boundaries
/// of the function.  The control-flow and data-flow structures are built and transformed
/// according to the current configuration of the Architecture and the active \e root Action.
/// Symbols, data-types and p-code are fetched as needed from the client and cached in
/// the Architecture object. XML Documents containing source code results, data-flow and
/// control-flow structures, symbol information, etc., are sent back to the client.
class DecompileAt : public GhidraCommand {
  Address addr;				///< The entry point address of the function to decompile
  virtual void loadParameters(void);
public:
  virtual void rawAction(void);
};

/// \brief Command to \b structure a control-flow graph.
///
/// An arbitrary control-flow is sent as a \<block> tag, with nested
/// \<block>, \<bhead>, and \<edge> sub-tags. The decompiler structures the
/// control-flow using standard \e structured \e code elements:  if/else, loops,
/// switches, etc.  The resulting structure information is returned to the
/// client as an XML document.
///
/// The command expects 2 string parameters.  The first is the encoded integer id
/// of a program in which we assume the control-flow graph lives.  The second is
/// the XML description of the control-flow.
class StructureGraph : public GhidraCommand {
  BlockGraph ingraph;				///< The control-flow graph to structure
  virtual void loadParameters(void);
public:
  virtual void rawAction(void);
};

/// \brief Command to \b set the \e root Action used by the decompiler or \b toggle output components.
///
/// The command expects 3 string parameters, the encoded integer id of the program
/// being decompiled, the \e root action name, and the name of the output \e printing configuration.
/// If the \e root action name is empty, no change is made to the \e root action.  If the \e printing
/// name is empty, no change is made to what gets output.
/// The \e root action name can be:
///   - decompile   -- The main decompiler action
///   - normalize   -- Decompilation tuned for normalization
///   - jumptable   -- Simplify just enough to recover a jump-table
///   - paramid     -- Simplify enough to recover function parameters
///   - register    -- Perform one analysis pass on registers, without stack variables
///   - firstpass   -- Construct the initial raw syntax tree, with no simplification
///
/// The \e printing configuration can be:
///   - tree               -- Send data-flow and control-flow structures
///   - notree             -- Do \e not send data-flow and control-flow
///   - c                  -- Send recovered source code
///   - noc                -- Do \e not send recovered source code
///   - parammeasures      -- Send parameter measures
///   - noparammeasures    -- Do \e not send parameter measures
///   - jumpload           -- Send addresses of jump-table entries, when recovering switch destinations
///   - nojumpload         -- Do \e not send addresses of jump-table entries
///
/// The command returns a single character message, 't' or 'f', indicating whether the
/// action succeeded.
class SetAction : public GhidraCommand {
  string actionstring;			///< The \e root Action to switch to
  string printstring;			///< The \e printing output configuration to toggle
  virtual void loadParameters(void);
  virtual void sendResult(void);
public:
  bool res;				///< Set to \b true if the configuration action was successful
  virtual void rawAction(void);
};

/// \brief Command to \b toggle \b options within the decompiler
///
/// The decompiler supports configuration of a variety of named options that affect
/// everything from how code is transformed to how it is displayed (See ArchOption).
/// The command expects 2 string parameters: the encoded integer id of the program,
/// and an XML document containing an \<optionslist> tag.  The \<optionslist> tag
/// contains one child tag for each option to be configured.
/// The command returns a single character message, 't' or 'f', indicating whether the
/// configuration succeeded.
class SetOptions : public GhidraCommand {
  Document *doc;			///< The XML option document
  virtual void loadParameters(void);
  virtual void sendResult(void);
public:
  SetOptions(void);
  virtual ~SetOptions(void);
  bool res;				///< Set to \b true if the option change succeeded
  virtual void rawAction(void);
};

#ifdef __REMOTE_SOCKET__
extern void connect_to_console(Funcdata *fd);
#endif

#endif
