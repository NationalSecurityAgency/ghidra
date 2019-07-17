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
/// \file xml_arch.hh
/// \brief Extension to read executables based on an XML format
#include "sleigh_arch.hh"
#include "loadimage_xml.hh"

/// \brief Extension for building an XML format capable Architecture
class XmlArchitectureCapability : public ArchitectureCapability {
  static XmlArchitectureCapability xmlArchitectureCapability;		///< The singleton instance
  XmlArchitectureCapability(void);					///< Singleton
  XmlArchitectureCapability(const XmlArchitectureCapability &op2);	///< Not implemented
  XmlArchitectureCapability &operator=(const XmlArchitectureCapability &op2);	///< Not implemented
public:
  virtual Architecture *buildArchitecture(const string &filename,const string &target,ostream *estream);
  virtual bool isFileMatch(const string &filename) const;
  virtual bool isXmlMatch(Document *doc) const;
};

/// \brief An Architecture that loads executables using an XML format
class XmlArchitecture : public SleighArchitecture {
  long adjustvma;					///< The amount to adjust the virtual memory address
  virtual void buildLoader(DocumentStorage &store);
  // virtual void resolveArchitecture(void);   		///< Inherit SleighArchitecture's version
  virtual void postSpecFile(void);
public:
  virtual void saveXml(ostream &s) const;
  virtual void restoreXml(DocumentStorage &store);
  XmlArchitecture(const string &fname,const string &targ,ostream *estream);	///< Constructor
  virtual ~XmlArchitecture(void) {}
};
