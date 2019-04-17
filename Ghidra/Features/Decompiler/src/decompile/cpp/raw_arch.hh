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
/// \file raw_arch.hh
/// \brief Bare bones capability for treating a file as a raw executable image
#include "sleigh_arch.hh"
#include "loadimage.hh"

/// \brief Extension point for building an Architecture that reads in raw images
class RawBinaryArchitectureCapability : public ArchitectureCapability {
  static RawBinaryArchitectureCapability rawBinaryArchitectureCapability;	///< The singleton instance
  RawBinaryArchitectureCapability(void);					///< Singleton
  RawBinaryArchitectureCapability(const RawBinaryArchitectureCapability &op2);	///< Not implemented
  RawBinaryArchitectureCapability &operator=(const RawBinaryArchitectureCapability &op2);	///< Not implemented
public:
  virtual ~RawBinaryArchitectureCapability(void);
  virtual Architecture *buildArchitecture(const string &filename,const string &target,ostream *estream);
  virtual bool isFileMatch(const string &filename) const;
  virtual bool isXmlMatch(Document *doc) const;
};

/// \brief Architecture that reads its binary as a raw file
class RawBinaryArchitecture : public SleighArchitecture {
  long adjustvma;					///< What address byte 0 of the raw file gets treated as
  virtual void buildLoader(DocumentStorage &store);
  virtual void resolveArchitecture(void);
  virtual void postSpecFile(void);
public:
  virtual void saveXml(ostream &s) const;
  virtual void restoreXml(DocumentStorage &store);
  RawBinaryArchitecture(const string &fname,const string &targ,ostream *estream);	///< Constructor
  virtual ~RawBinaryArchitecture(void) {}
};

