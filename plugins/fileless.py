from typing import List

from volatility3.framework import interfaces, exceptions, symbols
from volatility3.framework.objects import utility
from volatility3.framework.renderers import format_hints, TreeGrid
from volatility3.framework.configuration import requirements


class FilelessProcess(interfaces.plugins.PluginInterface):
    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(name='kernel', description='Linux kernel',
                                           architectures=["Intel32", "Intel64"])
        ]

    @classmethod
    def get_process_info(cls, task):
        comm = utility.array_to_string(task.comm)
        name = ''
        path = ''
        fs_type_name = ''
        nlink = None
        inode = None
        dev = None

        # Make sure we have the needed valid pointers
        if task.mm:
            mm = task.mm.dereference()
            if mm.exe_file:
                exe = mm.exe_file.dereference()
                if exe.f_path.dentry:
                    dentry = exe.f_path.dentry.dereference()

                    # Extract the actual data
                    if dentry.d_name:
                        name = dentry.d_name.name_as_str()
                    if dentry.d_inode:
                        inode_obj = dentry.d_inode.dereference()
                        inode = inode_obj.i_ino
                        nlink = inode_obj.i_nlink
                    if dentry.d_sb:
                        sb = dentry.d_sb.dereference()
                        dev = sb.s_dev
                        if sb.s_type:
                            fs_type = sb.s_type.dereference()
                            if fs_type.name:
                                fs_type_name = utility.pointer_to_string(fs_type.name, 255)

                if exe.f_path.mnt:
                    mount = exe.f_path.mnt.dereference()
                    try:
                        path = symbols.linux.LinuxUtilities.prepend_path(dentry, mount, task.fs.root) or ''
                    except exceptions.PagedInvalidAddressException:
                        path = ''

        return task.pid, comm, name, path, nlink, fs_type_name, inode, dev

    def _generator(self):
        vmlinux = self.context.modules[self.config['kernel']]

        init_task = vmlinux.object_from_symbol(symbol_name="init_task")

        # Note that the init_task itself is not yielded, since "ps" also never shows it.
        for task in init_task.tasks:
            pid, comm, name, path, nlink, fs_type_name, inode, dev = self.get_process_info(task)
            if nlink == 0 or fs_type_name == 'tmpfs':
                yield (0, (pid, comm, name, path, fs_type_name, inode, dev))

    def run(self):
        return TreeGrid([
            ("PID", int),
            ("Name", str),
            ("File Name", str),
            ("Path", str),
            ("FS type", str),
            ("Inode", int),
            ("Device", int)
        ], self._generator())
