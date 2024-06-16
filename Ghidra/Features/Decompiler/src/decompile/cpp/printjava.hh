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
/// \file printjava.hh
/// \brief Classes supporting the java-language back-end to the decompiler

#ifndef __PRINTJAVA_HH__
#define __PRINTJAVA_HH__

#include "printc.hh"

namespace ghidra {

/// \brief Factory and static initializer for the "java-language" back-end to the decompiler
///
/// The singleton adds itself to the list of possible back-end languages for the decompiler
/// and it acts as a factory for producing the PrintJava object for emitting java-language tokens.
class PrintJavaCapability : public PrintLanguageCapability {
  static PrintJavaCapability printJavaCapability;		///< The singleton instance
  PrintJavaCapability(void);					///< Singleton constructor
  PrintJavaCapability(const PrintJavaCapability &op2);		///< Not implemented
  PrintJavaCapability &operator=(const PrintJavaCapability &op);	///< Not implemented
public:
  virtual PrintLanguage *buildLanguage(Architecture *glb);
};

/// \brief The java-language token emitter
///
/// This builds heavily on the c-language PrintC emitter.  Most operator tokens, the format of
/// function prototypes, and code structuring are shared.  Specifics of the java constant pool are handled
/// through the overloaded opCpoolRefOp().
///
/// Java data-types are mapped into the decompiler's data-type system in a specific way. The primitives
/// \b int, \b long, \b short, \b byte, \b boolean, \b float, and \b double all map directly. The
/// \b char primitive is treated as a 2 byte unsigned integer. A TypeStruct object holds the field
/// layout for a java class, then java objects get mapped as follows:
///   - Class reference = pointer to TYPE_UINT
///   - Array of \b int, \b long, \b short, or \b byte = pointer to TYPE_INT
///   - Array of \b float or \b double = pointer to TYPE_FLOAT
///   - Array of \b boolean = pointer to TYPE_BOOL
///   - Array of class objects = pointer to TYPE_PTR
///
/// There are some adjustments to the printing of data-types and LOAD/STORE expressions
/// to account for this mapping.
class PrintJava : public PrintC {
  static OpToken instanceof;				///< The \b instanceof keyword
  static bool isArrayType(const Datatype *ct);		///< Does the given data-type reference a java array
  static bool needZeroArray(const Varnode *vn);		///< Do we need '[0]' syntax.
  void resetDefaultsPrintJava(void);			///< Set options that are specific to Java
  virtual void printUnicode(ostream &s,int4 onechar) const;
public:
  PrintJava(Architecture *g,const string &nm="java-language");	///< Constructor
  virtual void resetDefaults(void);
  virtual void docFunction(const Funcdata *fd);
  virtual void pushTypeStart(const Datatype *ct,bool noident);
  virtual void pushTypeEnd(const Datatype *ct);
  virtual bool doEmitWideCharPrefix(void) const { return false; }
  virtual void adjustTypeOperators(void);
  virtual void opLoad(const PcodeOp *op);
  virtual void opStore(const PcodeOp *op);
  virtual void opCallind(const PcodeOp *op);
  virtual void opCpoolRefOp(const PcodeOp *op);
};

} // End namespace ghidra
#endif
