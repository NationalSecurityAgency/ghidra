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
import glob
import re
import fnmatch

from build import Config, BuildUtil

class PCodeTest(BuildUtil):

    defaults = Config()
    list = { }

    def __init__(self, conf):
        super(PCodeTest, self).__init__()
        self.config = Config(PCodeTest.defaults, conf)

        # calculate the toolchain_dir
        self.config.toolchain_dir = self.config.format('%(toolchain_root)s/%(toolchain)s-gcc-%(gcc_version)s')
        if not self.isdir(self.config.toolchain_dir):
            self.config.toolchain_dir = self.config.format('%(toolchain_root)s/%(toolchain)s')

        (self.config.toolchain_family, self.config.install_target) = self.config.toolchain.split('/')
        if not self.config.target: self.config.target = self.config.install_target

        # can default the Processor directory name, usually the
        # initial string of 'language_id' (otherwise unused).

        if self.config.language_id:
            self.config.processor = self.config.language_id.split(':')[0]

        # expand all of the variables with printf escapes

        self.config.expand()

        # save the new PCodeTest in a dictionary for auto-enumeration

        PCodeTest.list[self.config.name] = self

    @classmethod
    def print_all(cls):
        pct = sorted(cls.list.iteritems(), key=lambda x: x[0].lower())
        
        for t,pcodetest in sorted(cls.list.iteritems(), key=lambda x: x[0].lower()):
            print str(pcodetest)
            if pcodetest.config.verbose: print pcodetest.config.dump()

    def __str__(self):
        cb = 'build-all:%-5s' % ('yes' if self.config.build_all else 'no')
        ce = 'can-export:%-5s' % ('yes' if self.config.can_export else 'no')
        ct = 'compiler-type:%-5s' % self.config.toolchain_type
        tc = 'Toolchain:%s' % self.config.toolchain
        return self.config.name.ljust(20) + cb + ce + ct + tc

class PCodeTestBuild(BuildUtil):
    def __init__(self, pcode_test):
        super(PCodeTestBuild, self).__init__()
        self.config = Config(pcode_test.config)
        self.config.cwd = self.getcwd()

    @classmethod
    def factory(cls, pcode_test):
        if pcode_test.config.toolchain_type == 'gcc':
            return PCodeBuildGCC(pcode_test)
        elif pcode_test.config.toolchain_type == 'ccs':
            return PCodeBuildCCS(pcode_test)
        elif pcode_test.config.toolchain_type == 'sdcc':
            return PCodeBuildSDCC(pcode_test)
        else:
            raise Exception(self.config.format('Toolchain type %(toolchain_type)s not known'))

    def which(self, what):
        return self.config.format('%(toolchain_dir)s/%(' + what + ')s')

    def compile(self, input_files, opt_cflag, output_base):
        self.log_err(self.config.format('compile not implemented for %(toolchain_type)s'))

    # generic build a single PCodeTest for all variants
    def main(self):

        # make sure compiler exists and runnable

        if not self.is_executable_file(self.which('compile_exe')):
            self.log_err(self.config.format('build the Toolchain before compilation'))
            return

        # save path to tpp
        tpp_py = os.getcwd() + '/tpp.py'

        # Get a list of strings to filter input files
        available_files = sorted(glob.glob(self.config.format('%(pcodetest_src)s/*')))

        # skip any?
        skip_files = self.config.skip_files
        if len(skip_files) > 0:
            toskip = [x for x in available_files if self.basename(x) in skip_files]
            if len(toskip) != len(skip_files):
                self.log_warn('These files will not be skipped because they are not in the build: %s'
                              % ' '.join([x for x in skip_files if not x in toskip]))
            available_files = [x for x in available_files if not x in toskip]

        # remove float/double/longlong files if not supported
        if not self.config.has_float: available_files = [x for x in available_files if not fnmatch.fnmatch(x, '*FLOAT*')]
        if not self.config.has_double: available_files = [x for x in available_files if not fnmatch.fnmatch(x, '*DOUBLE*')]
        if not self.config.has_longlong: available_files = [x for x in available_files if not fnmatch.fnmatch(x, '*LONGLONG*')]
            
        # compile for each optimization
        for opt_name,opt_cflag in sorted(self.config.variants.iteritems()):

            kind = 'PCodeTest'

            # This is the base name of the binary file, or for small
            # build, the directory name that will hold the small
            # binaries

            out_name = '%s_%s_%s_pcodetest' % (self.config.name, self.config.toolchain_type.upper(), opt_name)
            if self.config.architecture_test: pcodetest_base_name = self.config.architecture_test
            else: pcodetest_base_name = self.config.architecture
            pcodetest_test = '%s_%s_EmulatorTest' % (pcodetest_base_name, opt_name)

            # GNUMake like rule to prevent un-required builds of pcodetests files
            # This does not rebuild if the output directory is newer than the
            # input files. So it needs to know where the build
            # directory would be, before it is recreated.

            build_dir = self.build_dir(self.config.build_root, kind, out_name)
            need_to_build = self.config.force or not self.isdir(build_dir)
            if not need_to_build:
                mtime = self.getmtime(build_dir)
                for f in available_files:
                    if mtime < self.getmtime(f):
                        need_to_build = True
                        break

            if not need_to_build:
                self.log_info('%s up to date (call with --force to force build)' % self.log_prefix(kind, out_name))
                continue

            self.open_log(self.config.build_root, kind, out_name, chdir=True)

            # copy source files to build directory, and go there
            for f in available_files: self.copy(f, '.', verbose=False)

            # if requested, add an info file

            if self.config.add_info: self.mkinfo('INFO.c')

            # make tests, if needed

            for f_test in glob.glob('*.test'):
                f_h = re.sub(r'[.]test', '.h', f_test)
                if self.isfile(f_h) and self.getmtime(f_test) <= self.getmtime(f_h): continue
                out, err = self.run(['python', tpp_py, f_test])
                if err:
                    self.log_err(err)
            out, err = self.run(['python', tpp_py, '--entry', 'pcode_main.c'])
            if err:
                self.log_err(err)

            if self.num_errors > 0:
                self.chdir(self.config.cwd)
                self.log_close()
                continue

            if self.config.small_build:
                # For a small build, build a binary for every
                # _BODY.c file in the smallFiles list.
                smallFiles = sorted(glob.glob('*_BODY.c'))
                self.log_info('**** SMALL BUILD ****')

                # Remove the previous directory, if it was there

                build_dir = '%s/build-PCodeTest-%s/%s' % (self.config.build_root, out_name, out_name)
                try: self.rmtree(build_dir)
                except: pass

                # Each small file ends with _BODY.c and it has a
                # companion without _BODY.

                for body_file in smallFiles:
                    small_name = body_file.replace('_BODY.c', '')
                    companion_file = small_name + '.c'
                    if not self.isfile(companion_file) or not self.isfile(body_file):
                        self.log_info('Skipping %s %s build' % (companion_file, body_file))
                        continue
                    input_files = ['pcode_test.c', 'pcode_main.c', 'builtin.c', companion_file, body_file]
                    self.compile(input_files, opt_cflag, small_name)
                    self.export_file(small_name+'.out', build_dir)
                    
                # export the directory
                target_dir = self.config.export_root+'%s'%out_name
                self.log_info("Exporting %s directory to %s" % (build_dir, target_dir) )
                self.export_file(build_dir, target_dir)
                
            else:
                # compile all the c and h files here
                input_files = sorted(glob.glob('*.[c]'))
                self.compile(input_files, opt_cflag, out_name)

                # export the file
                target_dir = self.config.export_root
                self.log_info("Exporting file to %s" % target_dir)
                output_file = '%s.out' % (out_name)
                self.export_file(output_file, target_dir)
                
            self.chdir(self.config.cwd)
            self.log_close()

class PCodeBuildSDCC(PCodeTestBuild):

    def __init__(self, PCodeTest):
        super(PCodeBuildSDCC, self).__init__(PCodeTest)

    # Set options for compiler depending on needs.
    def cflags(self, output_file):
        f = []
        f += ['-DHAS_FLOAT=1' if self.config.has_float else '-DHAS_FLOAT_OVERRIDE=1']
        f += ['-DHAS_DOUBLE=1' if self.config.has_double else '-DHAS_DOUBLE_OVERRIDE=1']
        f += ['-DHAS_LONGLONG=1' if self.config.has_longlong else '-DHAS_LONGLONG_OVERRIDE=1']
        if self.config.has_shortfloat: f += ['-DHAS_SHORTFLOAT=1']
        if self.config.has_vector: f += ['-DHAS_VECTOR=1']
        if self.config.has_decimal128: f += ['-DHAS_DECIMAL128=1']
        if self.config.has_decimal32: f += ['-DHAS_DECIMAL32=1']
        if self.config.has_decimal64: f += ['-DHAS_DECIMAL64=1']

        f += ['-DNAME=NAME:%s' % output_file]

        f += self.config.ccflags.split()
        f += self.config.add_ccflags.split()

        return f

    def compile(self, input_files, opt_cflag, output_base):

        # Name the output file, and delete it if it exists

        output_file = '%s.out' % (output_base)
        self.remove(output_file)

        # Construct the compile command line and execute it

        cmp = self.which('compile_exe')
        cmd = [cmp] + input_files + self.cflags(output_file)
        if opt_cflag: cmd += [opt_cflag]
        cmd += ['-o', output_file]
        out, err = self.run(cmd)
        if out: self.log_info(out)

        # print error messages, which may just be warnings
        if err: self.log_warn(err)

        # return now if the error preempted the binary

        if not self.is_readable_file(output_file):
            self.log_err('output not created %s' % output_file)
            return

class PCodeBuildCCS(PCodeTestBuild):

    def __init__(self, PCodeTest):
        super(PCodeBuildCCS, self).__init__(PCodeTest)

    # Set options for compiler depending on needs.
    def cflags(self, output_file):
        f = []
        f += ['-DHAS_FLOAT=1' if self.config.has_float else '-DHAS_FLOAT_OVERRIDE=1']
        f += ['-DHAS_DOUBLE=1' if self.config.has_double else '-DHAS_DOUBLE_OVERRIDE=1']
        f += ['-DHAS_LONGLONG=1' if self.config.has_longlong else '-DHAS_LONGLONG_OVERRIDE=1']
        if self.config.has_shortfloat: f += ['-DHAS_SHORTFLOAT=1']
        if self.config.has_vector: f += ['-DHAS_VECTOR=1']
        if self.config.has_decimal128: f += ['-DHAS_DECIMAL128=1']
        if self.config.has_decimal32: f += ['-DHAS_DECIMAL32=1']
        if self.config.has_decimal64: f += ['-DHAS_DECIMAL64=1']

        f += ['-DNAME=NAME:%s' % output_file]

        f += self.config.ccflags.split()
        f += self.config.add_ccflags.split()

        return f

    def compile(self, input_files, opt_cflag, output_base):

        # Name the output file, and delete it if it exists

        output_file = '%s.out' % (output_base)
        self.remove(output_file)

        # Construct the compile command line and execute it

        cmp = self.which('compile_exe')
        cmd = [cmp] + input_files + self.cflags(output_file)  + [opt_cflag]
        cmd += ['-z', '-h', '-e', 'printf5']
        cmd += [self.config.format('%(toolchain_dir)s/tools/compiler/ti-cgt-msp430_16.9.0.LTS/lib/libc.a')]
        cmd += ['-o', output_file]
        out, err = self.run(cmd)
        if out: self.log_info(out)

        # print error messages, which may just be warnings
        if err: self.log_warn(err)

        # return now if the error preempted the binary

        if not self.is_readable_file(output_file):
            self.log_err('output not created %s' % output_file)
            return

class PCodeBuildGCC(PCodeTestBuild):

    def __init__(self, PCodeTest):
        super(PCodeBuildGCC, self).__init__(PCodeTest)
        self.saved_ld_library_path = self.getenv('LD_LIBRARY_PATH', '')

    # add a new option to library path, or reset to saved value
    def set_library_path(self, add):
        if add and self.saved_ld_library_path:
            self.environment('LD_LIBRARY_PATH', '%s:%s' % (self.config.ld_library_path, add))
        elif add:
            self.environment('LD_LIBRARY_PATH', add)
        elif self.saved_ld_library_path:
            self.environment('LD_LIBRARY_PATH', self.saved_ld_library_path)

    # Create all the associated files for a output.
    def associated_info(self, bin, base):

        out, err = self.run(['file', bin])
        if out: self.log_info(out)
        if err:
            self.log_err(err)

        out, err = self.run([self.which('objdump_exe')]
                            + self.config.objdump_option.split()
                            + ['-d', bin], stdout=('%s.d' % base))
        if err: self.log_warn(err)

        out, err = self.run([self.which('objdump_exe')]
                            + self.config.objdump_option.split()
                            + ['-s', '--section', '.comment', bin],
                            stdout=('%s.comment' % base))
        if err: self.log_warn(err)

        out, err = self.run([self.which('objdump_exe')]
                            + self.config.objdump_option.split()
                            + ['-x', '-s', '-j', '.data', '-j', '.rodata', '-t' , bin],
                            stdout=('%s.mem' % base))
        if err: self.log_warn(err)

        out, err = self.run([self.which('readelf_exe'),
                             '--debug-dump=decodedline', bin], 
                            stdout=('%s.li' % base))
        if err: self.log_warn(err)

        out, err = self.run([self.which('nm_exe'), '-a', bin], 
                        stdout=('%s.nm' % base))
        if err: self.log_warn(err)

        out, err = self.run([self.which('readelf_exe'), '-a', bin],
                            stdout=('%s.readelf' % base))
        if err: self.log_warn(err)

        out, err = self.run(['grep', ' U ', '%s.nm' % base])
        if out: self.log_warn('** UNRESOLVED:\n' + out + '**END')
        if err: self.log_warn(err)

    # Set options for compiler depending on needs.
    def cflags(self, output_file):
        f = []
        f += ['-DHAS_FLOAT=1' if self.config.has_float else '-DHAS_FLOAT_OVERRIDE=1']
        f += ['-DHAS_DOUBLE=1' if self.config.has_double else '-DHAS_DOUBLE_OVERRIDE=1']
        f += ['-DHAS_LONGLONG=1' if self.config.has_longlong else '-DHAS_LONGLONG_OVERRIDE=1']
        if self.config.has_shortfloat: f += ['-DHAS_SHORTFLOAT=1']
        if self.config.has_vector: f += ['-DHAS_VECTOR=1']
        if self.config.has_decimal128: f += ['-DHAS_DECIMAL128=1']
        if self.config.has_decimal32: f += ['-DHAS_DECIMAL32=1']
        if self.config.has_decimal64: f += ['-DHAS_DECIMAL64=1']

        f += ['-DNAME=NAME:%s' % output_file]
        # turn off -g because dwarf, not needed
        f += ['-dA', '-w']
        # for xc26: f += ['--no-data-init']
        # or maybe f += ['-Xlinker', '--no-data-init']
        # This helps to alleviate undefined main, etc
        f += ['--entry', 'main']
        f += ['-static', '-Wno-unused-macros', '-nodefaultlibs', '-nostartfiles', '-fno-builtin']
        # can pass this if weak symbols aren't defined
        # f += ['-Xlinker', '--unresolved-symbols=ignore-all']

        f += self.config.ccflags.split()
        f += self.config.add_ccflags.split()

        return f

    def compile(self, input_files, opt_cflag, output_base):

        # Name the output file, and delete it if it exists

        output_file = '%s.out' % (output_base)
        self.remove(output_file)

        # set the library path

        self.set_library_path(self.config.ld_library_path)

        # Construct the compile/link command line and execute it

        cmp = self.which('compile_exe')
        cmd = [cmp] + input_files + self.cflags(output_file)  + [opt_cflag, '-B', self.dirname(cmp), '-o', output_file]
        out, err = self.run(cmd)
        if out: self.log_info(out)

        # print error messages, which may just be warnings
        if err: self.log_warn(err)

        # but return now if the error preempted the binary

        if not self.is_readable_file(output_file):
            self.log_err('output not created %s' % output_file)
            return

        # strip

        if self.config.strip_symbols:
            str = self.which('strip_exe')
            cmd = [str, '-s', output_file]
            out, err = self.run(cmd)
            if out: self.log_info(out)

        # Get associated information (identify file, output-file.d,
        # .li, .nm, and .readelf, identify file, unresolves symbols)

        self.associated_info(output_file, output_base)

        # build a BUILD_EXE version

        if self.config.build_exe:
            cmp = self.which('compile_exe')
            cmd = [cmp] + input_files + self.cflags(output_file)\
                + ['-DBUILD_EXE', opt_cflag, '-B', self.dirname(cmp), '-o', '%s.exe' % output_base]
            out, err = self.run(cmd)
            if err: self.log_warn(err)
            if out: self.log_info(out)
            if self.config.qemu_command:
                build_dir = self.build_dir(self.config.build_root, "pcodetest", output_base)
                self.log_info(self.config.format('%s %s/%s.exe' %(self.config.qemu_command, build_dir, output_base)))
