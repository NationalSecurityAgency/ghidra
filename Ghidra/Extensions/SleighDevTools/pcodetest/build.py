## ###
#  IP: GHIDRA
# 
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#  
#       http://www.apache.org/licenses/LICENSE-2.0
#  
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
##
import os
import shutil
import subprocess
import sys
import pwd
import grp
import re

class BuildUtil(object):

    def __init__(self):
        self.log = False
        self.name = False
        self.num_errors = 0
        self.num_warnings = 0

    def run(self, cmd, stdout=False, stderr=False, verbose=True):
        if isinstance(cmd, basestring):
            if stdout and stderr:
                cmd += ' 1>%s 2>%s' % (stdout, stderr)
            elif stdout and not stderr:
                cmd += ' 1>%s 2>&1' % (stdout)
            elif not stdout and stderr:
                cmd += ' 2>%s' % (stderr)
            if verbose: self.log_info(cmd)
            os.system(cmd)
        else:
            str = ' '.join(cmd);
            if stdout:
                f = file(stdout, 'w+')
                str += ' 1>%s 2>&1' % (stdout)
            else:
                f = subprocess.PIPE
            if verbose: self.log_info(str)
            try:
                sp = subprocess.Popen(cmd, stdout=f, stderr=subprocess.PIPE)
            except OSError as e:
                self.log_err("Command: " + str)
                self.log_err(e.message)
                return 0,e.message#raise
            if stdout: f.close()
            out, err = sp.communicate()
            # print 'run returned %d bytes stdout and %d bytes stderr' % (len(out) if out else 0, len(err) if err else 0)
            return out, err

    def isdir(self, dname):
        return os.path.isdir(dname)

    def getcwd(self):
        return os.getcwd()

    def basename(self, fname):
        return os.path.basename(fname)

    def dirname(self, fname):
        return os.path.dirname(fname)

    def getmtime(self, fname):
        return os.path.getmtime(fname)

    def isfile(self, fname):
        return os.path.isfile(fname)

    def getenv(self, var, dflt):
        return os.getenv(var, dflt)

    def pw_name(self, fname):
        return pwd.getpwuid(os.stat(fname).st_uid).pw_name

    def gr_name(self, fname):
        return grp.getgrgid(os.stat(fname).st_gid).gr_name

    def isatty(self):
        return os.isatty(sys.stdin.fileno())

    def is_readable_file(self, fname):
        if not self.isfile(fname):
            self.log_warn('%s does not exist' % fname)
            return False
        if os.stat(fname).st_size == 0:
            self.log_warn('%s is empty' % fname)
            return False
        if os.access(fname, os.R_OK) == 0:
            self.log_warn('%s is not readable' % fname)
            return False
        return True

    def is_executable_file(self, fname):
        if not self.is_readable_file(fname): return False
        if os.access(fname, os.X_OK) == 0:
            self.log_warn('%s is not executable' % fname)
            return False
        return True

    # export a file to a directory
    def export_file(self, fname, dname,):
        try:
            if not os.path.isdir(dname):
                self.makedirs(dname)
            if os.path.isfile(fname):
                self.copy(fname, dname, verbose=True)
            elif os.path.isdir(fname):
                self.copy(fname, dname, dir=True, verbose=True)
        except IOError as e:
            self.log_err('Error occurred exporting %s to %s' % (fname, dname))
            self.log_err("Unexpected error: %s" % str(e))

    def rmtree(self, dir, verbose=True):
        if verbose: self.log_info('rm -r %s' % dir)
        shutil.rmtree(dir)

    def makedirs(self, dir, verbose=True):
        if verbose: self.log_info('mkdir -p %s' % dir)
        try: os.makedirs(dir)
        except: pass

    # copy a file to a directory
    def copy(self, fname, dname, verbose=True, dir=False):
        if not dir:
            if verbose: self.log_info('cp -av %s %s' % (fname, dname))
            shutil.copy(fname, dname)
        else:
            if verbose: self.log_info('cp -avr %s %s' % (fname, dname))
            if os.path.exists(dname):
                shutil.rmtree(dname)
            shutil.copytree(fname, dname)

    def chdir(self, dir, verbose=True):
        if verbose: self.log_info('cd %s' % dir)
        os.chdir(dir)

    def remove(self, fname, verbose=True):
        if verbose: self.log_info('rm -f %s' % fname)
        try: os.remove(fname)
        except: pass

    def environment(self, var, val, verbose=True):
        if verbose: self.log_info('%s=%s' % (var, val))
        os.environ[var] = val

    def unlink(self, targ, verbose=True):
        if verbose: self.log_info('unlink %s' % targ)
        os.unlink(targ)

    def symlink(self, src, targ, verbose=True):
        if verbose: self.log_info('ln -s %s %s' % (src, targ))
        if os.path.islink(targ):
            os.unlink(targ)
        os.symlink(src, targ)

    def build_dir(self, root, kind, what):
        return root + "/" + re.sub(r'[^a-zA-Z0-9_-]+', '_', 'build-%s-%s' % (kind, what))

    def log_prefix(self, kind, what):
        return kind.upper() + ' ' + what

    def open_log(self, root, kind, what, chdir=False):
        build_dir = self.build_dir(root, kind, what)

        # Get the name of the log file
        logFile = '%s/log.txt' % build_dir

        self.log_info('%s LOGFILE %s' % (self.log_prefix(kind, what), logFile))

        try: self.rmtree(build_dir, verbose=False)
        except: pass
        self.makedirs(build_dir, verbose=False)
        self.log_open(logFile)
        if chdir: self.chdir(build_dir)

    def log_open(self, name):
        if self.log: self.log_close()
        self.log = open(name, 'w')
        self.name = name

    def log_close(self):
        if self.log:
            if self.num_errors > 0:
                print '# ERROR: There were errors, see %s' % self.name
            elif self.num_warnings > 0:
                print '# WARNING: There were warnings, see %s' % self.name
            self.log.close()
        self.log = False
        self.name = False
        self.num_errors = 0
        self.num_warnings = 0

    def log_pr(self, prefix, what):
        if isinstance(what, basestring):
            log_string = prefix + what
        else:
            log_string = prefix + repr(what)

        if self.log:
            self.log.write(log_string + '\n')
            self.log.flush()
        else:
            print log_string
            sys.stdout.flush()

    def log_err(self, what):
        self.log_pr('# ERROR: ', what)
        self.num_errors += 1

    def log_warn(self, what):
        self.log_pr('# WARNING: ', what)
        self.num_warnings += 1

    def log_info(self, what):
        self.log_pr('# INFO: ', what)
        
    # create a file with size, type, and symbol info
    # the function is here because it is useful and has no dependencies

    def mkinfo(self, fname):
        ifdefs = { 'i8':'HAS_LONGLONG', 'u8':'HAS_LONGLONG', 'f4':'HAS_FLOAT', 'f8':'HAS_DOUBLE' }

        sizes = [
            'char', 'signed char', 'unsigned char',
            'short', 'signed short', 'unsigned short',
            'int', 'signed int', 'unsigned int',
            'long', 'signed long', 'unsigned long',
            'long long', 'signed long long', 'unsigned long long',
            'float', 'double', 'float', 'long double',
            'i1', 'i2', 'i4', 'u1', 'u2', 'u4', 'i8', 'u8', 'f4', 'f8']

        syms = [
            '__AVR32__', '__AVR_ARCH__', 'dsPIC30', '__GNUC__', '__has_feature', 'INT4_IS_LONG',
            '__INT64_TYPE__', '__INT8_TYPE__', '__llvm__', '_M_ARM_FP', '__MSP430__', '_MSV_VER',
            '__SDCC', '__SIZEOF_DOUBLE__', '__SIZEOF_FLOAT__', '__SIZEOF_SIZE_T__', '__TI_COMPILER_VERSION__',
            '__INT8_TYPE__', '__INT16_TYPE__', '__INT32_TYPE__', '__INT64_TYPE__', '__UINT8_TYPE__',
            '__UINT16_TYPE__', '__UINT32_TYPE__', '__UINT64_TYPE__', 'HAS_FLOAT', 'HAS_DOUBLE',
            'HAS_LONGLONG', 'HAS_FLOAT_OVERRIDE', 'HAS_DOUBLE_OVERRIDE', 'HAS_LONGLONG_OVERRIDE']

        typedefs = { 'i1':1, 'i2':2, 'i4':4, 'u1':1, 'u2':2, 'u4':4, 'i8':8, 'u8':8, 'f4':4, 'f8':8 }

        f = open(fname, 'w')

        f.write('#include "types.h"\n\n')

        i = 0
        for s in sizes:
            i += 1
            d = 'INFO sizeof(%s) = ' % s
            x = list(d)
            x = "', '".join(x)
            x = "'%s', '0'+sizeof(%s), '\\n'" % (x, s)
            l = 'char size_info_%d[] = {%s};\n' % (i, x)
            if s in ifdefs: f.write('#ifdef %s\n' % ifdefs[s])
            f.write(l)
            if s in ifdefs: f.write('#endif\n')

        for s in typedefs:
            if s in ifdefs: f.write('#ifdef %s\n' % ifdefs[s])
            f.write('_Static_assert(sizeof(%s) == %d, "INFO %s should have size %d, is not correct\\n");\n' % (s, typedefs[s], s, typedefs[s]))
            if s in ifdefs: f.write('#endif\n')

        for s in syms:
            i += 1
            f.write('#ifdef %s\n' % s)
            f.write('char sym_info_%d[] = "INFO %s is defined\\n\";\n' % (i, s))
            f.write('#else\n')
            f.write('char sym_info_%d[] = "INFO %s is not defined\\n\";\n' % (i, s))
            f.write('#endif\n')

        f.close()

class Config(object):

    def __init__(self, *obj):
        for o in obj:
            if isinstance(o, dict): self.__dict__.update(o)
            else: self.__dict__.update(o.__dict__)

    def format(self, val):
        if isinstance(val, basestring) and '%' in val:
            return val % self.__dict__
        elif isinstance(val, dict):
            return dict(map(lambda (k,v): (k,self.format(v)), val.iteritems()))
        else: return val

    def __getattr__(self, attr):
        return ''

    def expand(self):
        for k,v in self.__dict__.iteritems():
            self.__dict__[k] = self.format(v)

    def dump(self):
        ret = ''
        for k,v in sorted(self.__dict__.iteritems()):
            if isinstance(v, basestring): vv = "'" + v + "'"
            else: vv = str(v)
            ret += ' '.ljust(10) + k.ljust(20) + vv + '\n'
        return ret

