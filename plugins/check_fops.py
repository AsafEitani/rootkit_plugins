# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import logging
from typing import List

from volatility3.plugins.linux import file, lsmod
from volatility3.framework import interfaces, automagic, plugins, objects
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints, TreeGrid

vollog = logging.getLogger(__name__)


class CheckFops(interfaces.plugins.PluginInterface):
    """Check file operations function pointers for hooks."""

    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(name='kernel', description='Linux kernel',
                                           architectures=["Intel32", "Intel64"]),
        ]

    @staticmethod
    def create_mount_filter(srodata, erodata):
        def filter_func(mount):
            if mount.get_mnt_sb():
                addr = mount.get_mnt_sb().dereference().s_op
                return addr > erodata or addr < srodata

        return filter_func

    def _generator(self, vmlinux, dentries, modules):
        stext = vmlinux.get_absolute_symbol_address("_stext")
        etext = vmlinux.get_absolute_symbol_address("_etext")

        # create cache for file operations structs analysed
        cache = {}

        # iterate through dentries, extract file info and apply path and UID filters
        for task, mount, dentry in dentries:
            if dentry.d_inode <= 0:
                continue
            inode = dentry.d_inode.dereference()
            fops_addr = inode.i_fop
            if fops_addr <= 0:
                continue

            hook_found = False

            # populate cache
            if fops_addr not in cache:
                cache[fops_addr] = {}

                fops = fops_addr.dereference()
                for func in dir(fops):
                    func_addr = getattr(fops, func)
                    if not isinstance(func_addr, objects.Pointer):
                        continue

                    if func_addr == 0:
                        continue

                    # check if the function is not within the kernel text segment
                    if func_addr > etext or func_addr < stext:
                        hook_found = True
                        func_symbols = objects.utility.get_address_symbols(vmlinux, func_addr)
                        owner = objects.utility.find_module_owner_by_address(modules, func_addr)

                        # save in cache
                        cache[fops_addr][func] = (format_hints.Hex(func_addr), func_symbols, owner)

            # file_operations struct was analysed and some hooks were found
            if hook_found:
                # get the current file information
                info = file.ListFiles.get_file_info(task, mount, dentry)
                # info could not be extracted
                if info is None:
                    continue
                mnt_id, inode_id, inode_addr, mode, uid, gid, size, created, modified, accessed, file_path = info

                for func in cache[fops_addr]:
                    func_addr, func_symbols, owner = cache[fops_addr][func]
                    yield 0, (format_hints.Hex(fops_addr), func, format_hints.Hex(func_addr), func_symbols, owner,
                              mnt_id, inode_id, format_hints.Hex(inode_addr),
                              mode, uid, gid, size, created, modified, accessed,
                              file_path)

    def run(self):
        vmlinux = self.context.modules[self.config['kernel']]

        srodata = vmlinux.get_absolute_symbol_address("__start_rodata")
        erodata = vmlinux.get_absolute_symbol_address("__end_rodata")

        automagics = automagic.choose_automagic(automagic.available(self._context), file.ListFiles)
        list_files_plugin = plugins.construct_plugin(self.context, automagics, file.ListFiles, self.config_path,
                                                     self._progress_callback, self.open)
        dentries = list_files_plugin.get_dentries(context=self.context,
                                                  vmlinux_module_name=self.config['kernel'],
                                                  mnt_filter=self.create_mount_filter(srodata, erodata))

        automagics = automagic.choose_automagic(automagic.available(self._context), lsmod.Lsmod)
        list_mounts_plugin = plugins.construct_plugin(self.context, automagics, lsmod.Lsmod, self.config_path,
                                                      self._progress_callback, self.open)
        modules = list(list_mounts_plugin._generator())

        return TreeGrid([('Fops Addr', format_hints.Hex),
                         ("Fops Member", str),
                         ('Member Addr', format_hints.Hex),
                         ("Func Symbols", str),
                         ("Func Owner", str),
                         ('Mount ID', int),
                         ('Inode ID', int),
                         ('Inode Address', format_hints.Hex),
                         ('Mode', str),
                         ('UID', int),
                         ('GID', int),
                         ('Size', int),
                         ('Created', int),
                         ('Modified', int),
                         ('Accessed', int),
                         ('File Path', str)],
                        self._generator(vmlinux, dentries, modules))
