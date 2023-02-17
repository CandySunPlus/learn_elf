import subprocess
import gdb

class AutoSym(gdb.Command):
  """Load symbols for all execuable files mapped in memory, through elk"""

  def __init__(self) -> None:
    super(AutoSym, self).__init__("autosym", gdb.COMMAND_USER)

  def invoke(self, arg: str, from_tty: bool) -> None:
    pid = gdb.selected_inferior().pid

    if pid == 0:
      print("No inferior.")
      return

    cmd = ["elk", "autosym", str(pid)]
    lines = subprocess.check_output(cmd).decode("utf-8").split("\n")

    for line in lines:
      gdb.execute(line)


AutoSym()

class Dig(gdb.Command):
  def __init__(self) -> None:
    super(Dig, self).__init__("dig", gdb.COMMAND_USER, gdb.COMPLETE_EXPRESSION)

  def invoke(self, arg: str, from_tty: bool) -> None:
    if arg == "":
      print("Usage: dig ADDR")
      return

    addr = int(arg, 0)

    pid = gdb.selected_inferior().pid
    if pid == 0:
      print("No inferior.")
      return

    cmd = ["elk", "dig", "--pid", str(pid), "--addr", str(addr)]

    lines = subprocess.check_output(cmd).decode("utf-8").split("\n")

    for line in lines:
      print(line)

Dig()
