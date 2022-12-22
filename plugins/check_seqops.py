# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import logging
from typing import List

from volatility3.plugins.linux import lsmod
from volatility3.framework import exceptions, interfaces, automagic, plugins
from volatility3.framework.objects import utility
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints, TreeGrid

vollog = logging.getLogger(__name__)

SEQ_OPS_SYMBOLS = ["tcp4_seq_ops",
                   "tcp6_seq_ops",
                   "udp_seq_ops",
                   "udp6_seq_ops",
                   "raw_seq_ops",
                   "raw6_seq_ops"]
SEQ_OPS_MEMBERS = ["start", "stop", "next", "show"]


class CheckSeqops(interfaces.plugins.PluginInterface):
    """Check sequence operations function pointers for hooks."""

    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(name='kernel', description='Linux kernel',
                                           architectures=["Intel32", "Intel64"]),
            requirements.PluginRequirement(name='lsmod', plugin=lsmod.Lsmod, version=(2, 0, 0)),
        ]

    def _generator(self, modules):
        vmlinux = self.context.modules[self.config['kernel']]
        stext = vmlinux.get_absolute_symbol_address("_stext")
        etext = vmlinux.get_absolute_symbol_address("_etext")

        for seq_ops_sym in SEQ_OPS_SYMBOLS:
            try:
                seq_ops = vmlinux.object_from_symbol(seq_ops_sym)
            except exceptions.SymbolError:
                vollog.warning(f"Unable to find the {seq_ops_sym} symbol. Skipping.")
                continue

            for member in SEQ_OPS_MEMBERS:
                try:
                    func_addr = getattr(seq_ops, member)
                except AttributeError:
                    vollog.warning(f"{seq_ops_sym} does not have the {member} member."
                                   f" Skipping {seq_ops_sym}->{member} check.")
                    continue
                if func_addr > etext or func_addr < stext:
                    yield (0, (seq_ops_sym,
                               member,
                               format_hints.Hex(func_addr),
                               utility.get_address_symbols(vmlinux, func_addr),
                               utility.find_module_owner_by_address(modules, func_addr)))

    def run(self):
        automagics = automagic.choose_automagic(automagic.available(self._context), lsmod.Lsmod)
        list_mounts_plugin = plugins.construct_plugin(self.context, automagics, lsmod.Lsmod, self.config_path,
                                                      self._progress_callback, self.open)
        modules = list(list_mounts_plugin._generator())
        return TreeGrid([("Struct Name", str), ("Struct Member", str), ("Function Address", format_hints.Hex),
                         ("Function Symbols", str), ("Function Owner", str)], self._generator(modules))
