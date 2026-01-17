import logging
import os
from functools import cache
from pathlib import Path

import idaapi
__QT_IS_AVAILABLE: bool = True
try:
    # IDA 9.2+ uses PySide6 while earlier versions use PyQt5
    from PySide6 import QtCore, QtGui, QtWidgets # type: ignore[import-untyped, import-not-found] 
except ImportError:
    try:
        from PyQt5 import QtCore, QtGui, QtWidgets # type: ignore[import-untyped, import-not-found]
    except NotImplementedError:
        __QT_IS_AVAILABLE = False

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO) # This is the level that is actually used
_console_handler = logging.StreamHandler()
_console_handler.setLevel(logging.INFO)
_console_handler.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(module)s.%(funcName)s:%(lineno)d - %(message)s'))
if logger.handlers:
    logger.removeHandler(logger.handlers[0]) # When you importlib.reload() a module, we need to clear out the old logger
logger.addHandler(_console_handler)

def replace_in_path(path: str, old: str, new: str) -> str:
    match os.name:
        # case "posix":
        #     return path.replace(old, new)
        case "nt":
            import re

            logger.debug(f"Replacing '{old}' with '{new}' in '{path}'")
            return re.sub(re.escape(old), re.escape(new), path, flags=re.IGNORECASE)
        case _:
            return path.replace(old, new)


class EnvironmentVarsReplacer:
    @staticmethod
    def get_ida_env_var_list():
        return [
            ("%IDADIR%", idaapi.idadir("")),
            ("%IDAUSR%", idaapi.get_user_idadir()),
            ("%HOME%", os.path.expanduser("~")),
            ("%IDADIR%", "/Applications/IDA Professional 9.0.app"),
            ("%IDADIR%", "/Applications/IDA Professional 9.1.app"),
        ]

    @staticmethod
    def replace_env_vars(path: str) -> str:
        for var, value in EnvironmentVarsReplacer.get_ida_env_var_list():
            path = replace_in_path(path, var, value)
        return path

    @staticmethod
    def restore_env_vars(path: str) -> str:
        for var, value in EnvironmentVarsReplacer.get_ida_env_var_list():
            path = replace_in_path(path, value, var)
        return path


class RecentDroppedFilenames:
    REG_KEY = "DroppedFiles"
    MAX_RECORDS = 50

    @staticmethod
    def read():
        file_list = idaapi.reg_read_strlist(RecentDroppedFilenames.REG_KEY)
        if file_list is None or len(file_list) == 0:
            RecentDroppedFilenames.fill_from_recent_scripts()
            file_list = idaapi.reg_read_strlist(RecentDroppedFilenames.REG_KEY)
            for i in range(len(file_list)):
                file_list[i] = EnvironmentVarsReplacer.restore_env_vars(file_list[i])

        return file_list

    @staticmethod
    def add_file_path(file_path: str):
        file_path = EnvironmentVarsReplacer.restore_env_vars(file_path)
        idaapi.reg_update_filestrlist(
            RecentDroppedFilenames.REG_KEY,
            file_path,
            maxrecs=RecentDroppedFilenames.MAX_RECORDS,
        )

    @staticmethod
    def remove_file_path(file_path: str):
        idaapi.reg_update_filestrlist(
            RecentDroppedFilenames.REG_KEY,
            None,  # type: ignore
            maxrecs=RecentDroppedFilenames.MAX_RECORDS,
            rem=file_path,
        )

    @staticmethod
    def fill_from_recent_scripts():
        for script in idaapi.reg_read_strlist(subkey="RecentScripts"):
            RecentDroppedFilenames.add_file_path(script)

    @staticmethod
    def normalize_list():
        files = RecentDroppedFilenames.read()
        seen = set()
        for i in range(len(files)):
            files[i] = EnvironmentVarsReplacer.restore_env_vars(files[i])
        files = [x for x in files if not (x in seen or seen.add(x))]

        # there is a bug (SUPPORT-6170) in idaapi.reg_write_strlist that prevents using it, so we use _ida_registry directly
        import _ida_registry  # type: ignore

        _ida_registry.reg_write_strlist(
            files,
            RecentDroppedFilenames.REG_KEY,
        )


@cache
def ext_to_icon_id(ext: str) -> int:
    match ext.lower():
        case "h" | "hpp" | "hh" | "hxx" | "c" | "cpp" | "cc" | "cxx":
            return idaapi.get_icon_id_by_name("resources/menu/ProduceHeader.svg")
        case "til":
            return idaapi.get_icon_id_by_name("resources/menu/TilAddType.svg")
        case "sig":
            return idaapi.get_icon_id_by_name("resources/menu/LoadSigFile.svg")
        case "py" | "pyc" | "pyo" | "pyw" | "pyx" | "pyi" | "pyz" | "pyz":
            return 201  # /IDAG/resources/menu/201.svg
        case "idc":
            # return idaapi.get_icon_id_by_name("resources/menu/DumpTypes.svg")
            return idaapi.get_icon_id_by_name("resources/menu/ExecuteLine.svg")
            # return idaapi.get_icon_id_by_name("resources/menu/Execute.svg")
        case "ids" | "idt":
            # return idaapi.get_icon_id_by_name("resources/menu/LoadIdsModule.svg")
            return 0
        case "dbg":
            return 0
        case "tds":
            return 0
        case "pdb":
            return 0
        case _:
            return idaapi.get_icon_id_by_name("resources/menu/LoadFile.svg")


class RecentDroppedFilesChooser(idaapi.Choose):
    def read_items(self):
        files = RecentDroppedFilenames.read()
        # return list of [file name, path]
        return [[Path(file).name, file] for file in files]

    def __init__(self, title: str, *args, **kwargs):
        super().__init__(
            *args,
            title=title,
            cols=[
                ["file name", idaapi.Choose.CHCOL_PATH | 20],
                ["path", idaapi.Choose.CHCOL_PATH | 40],
            ],
            **kwargs,
        )
        self.items = self.read_items()

    def OnGetLine(self, n):
        return self.items[n]

    def OnSelectLine(self, sel: int):
        file_path = self.items[sel][1]
        file_path = Path(EnvironmentVarsReplacer.replace_env_vars(file_path))
        if file_path.exists():
            handle_dropped_file(file_path)

    def OnGetSize(self):
        return len(self.items)

    def OnRefresh(self, sel: int):
        self.items = self.read_items()
        if len(self.items) == 0:
            return [idaapi.Choose.EMPTY_CHOOSER, idaapi.Choose.NO_SELECTION]
        return [idaapi.Choose.ALL_CHANGED] + self.adjust_last_item(sel)

    def OnDeleteLine(self, sel: int):
        RecentDroppedFilenames.remove_file_path(self.items[sel][1])
        self.items = self.read_items()
        if len(self.items) == 0:
            return [idaapi.Choose.ALL_CHANGED, idaapi.Choose.NO_SELECTION]
        return [idaapi.Choose.ALL_CHANGED] + self.adjust_last_item(sel)

    def OnGetIcon(self, n):
        fname: str = self.items[n][0]
        return ext_to_icon_id(fname.rsplit(".", 1)[-1])  # type: ignore


def parse_srclang_file(file_path):
    import ida_srclang

    # TODO: detect compiler from file content
    argv = [
        "-target arm64-apple-darwin",
        "-x c++",
        "-std=c++17",
        "-Werror",
        "-Wno-incompatible-sysroot",
    ]
    ida_srclang.set_parser_argv("clang", " ".join(argv))
    ida_srclang.set_parser_option("clang", "CLANG_SMART_POINTERS", "OSSharedPtr")
    ida_srclang.parse_decls_with_parser_ext(
        "clang", None, str(file_path), idaapi.HTI_FIL
    )


def load_pdb(file_path, only_types=False, base=idaapi.BADADDR):
    """
                  plugin = find_plugin(name: "pdb", load_if_needed: 1);
                  if ( plugin )
                    run_plugin(ptr: plugin, arg: 0LL);


                  PDB_CC_IDA  = 1,
        // load additional pdb. This is semantically the same as
        // PDB_CC_USER (i.e., "File > Load file > PDB file..."), except
        // it won't ask the user for the data; rather it expects it in
        // netnode(PDB_NODE_NAME):
        //   load_addr: netnode(PDB_NODE_NAME).altval(PDB_DLLBASE_NODE_IDX)
        //   dll_name:  netnode(PDB_NODE_NAME).supstr(PDB_DLLNAME_NODE_IDX)


        #define PDB_NODE_NAME             "$ pdb"
        #define PDB_DLLBASE_NODE_IDX       0
        #define PDB_DLLNAME_NODE_IDX       0
        #define PDB_LOADING_WIN32_DBG      1
        #define PDB_TYPESONLY_NODE_IDX     2


        static bool get_details_from_netnode(pdbargs_t *args)
    {
      netnode pdbnode;
      pdbnode.create(PDB_NODE_NAME);

      args->loaded_base = pdbnode.altval(PDB_DLLBASE_NODE_IDX);
      if ( args->loaded_base == 0 )
      {
        msg("PDB: PDB_CC_USER_WITH_DATA called without an imagebase, cannot proceed\n");
    fail:
        // set failure result
        pdbnode.altset(PDB_DLLBASE_NODE_IDX, 0);
        return false;
      }

      // TODO dllname shouldn't be needed when we're reading from debugger memory
      qstring tmp;
      pdbnode.supstr(&tmp, PDB_DLLNAME_NODE_IDX);
      if ( tmp.empty() )
      {
        msg("PDB: PDB_CC_USER_WITH_DATA called without a filename, cannot proceed\n");
        goto fail;
      }

      set_file_by_ext(args, tmp.c_str());

      setflag(args->flags, PDBFLG_LOAD_TYPES, true);
      setflag(args->flags, PDBFLG_LOAD_NAMES, pdbnode.altval(PDB_TYPESONLY_NODE_IDX) == 0);

      return true;
    }

    enum pdb_callcode_t
    {
      // user invoked 'load pdb' command, load pdb for the input file.
      // after invocation, result (boolean) is stored in: netnode(PDB_NODE_NAME).altval(PDB_DLLBASE_NODE_IDX)
      PDB_CC_USER = 0,
      // ida decided to call the plugin itself
      PDB_CC_IDA  = 1,
      // load additional pdb. This is semantically the same as
      // PDB_CC_USER (i.e., "File > Load file > PDB file..."), except
      // it won't ask the user for the data; rather it expects it in
      // netnode(PDB_NODE_NAME):
      //   load_addr: netnode(PDB_NODE_NAME).altval(PDB_DLLBASE_NODE_IDX)
      //   dll_name:  netnode(PDB_NODE_NAME).supstr(PDB_DLLNAME_NODE_IDX)
      PDB_CC_USER_WITH_DATA = 3,
      // load debug info from the COFF file
      // ida decided to call the plugin itself
      //   dbginfo_params_t: netnode(DBGINFO_PARAM_NODE_NAME).supval(DBGINFO_PARAMS_KEY)
      PDB_CC_IDA_COFF = 4,
    };

    """

    n = idaapi.netnode()

    PDB_NODE_NAME = "$ pdb"
    PDB_DLLBASE_NODE_IDX = 0
    PDB_DLLNAME_NODE_IDX = 0
    PDB_TYPESONLY_NODE_IDX = 2
    PDB_CC_USER_WITH_DATA = 3

    n.create(PDB_NODE_NAME)
    n.altset(PDB_DLLBASE_NODE_IDX, 1)  # PDB_DLLBASE_NODE_IDX
    n.supset(PDB_DLLNAME_NODE_IDX, file_path)  # PDB_DLLNAME_NODE_IDX
    n.altset(PDB_TYPESONLY_NODE_IDX, int(only_types))  # PDB_TYPESONLY_NODE_IDX
    idaapi.load_and_run_plugin("pdb", PDB_CC_USER_WITH_DATA)


def load_file(file_path) -> bool:
    logger.debug(f"Shift pressed, mapping the file as a binary: {file_path}")
    li = idaapi.open_linput(str(file_path), False)
    if not li:
        logger.error(f"Failed to open file: {file_path}")
        return False
    address = idaapi.ask_long(idaapi.get_imagebase(), "Base address?")
    if address is None:
        logger.error("User cancelled the base address input")
        return False

    """
                // \\defgroup NEF_ Load file flags
/// Passed as 'neflags' parameter to loader_t::load_file
///@{
#define NEF_SEGS        0x0001            ///< Create segments
#define NEF_RSCS        0x0002            ///< Load resources
#define NEF_NAME        0x0004            ///< Rename entries
#define NEF_MAN         0x0008            ///< Manual load
#define NEF_FILL        0x0010            ///< Fill segment gaps
#define NEF_IMPS        0x0020            ///< Create import segment
#define NEF_FIRST       0x0080            ///< This is the first file loaded
                                          ///< into the database.
#define NEF_CODE        0x0100            ///< for load_binary_file():
                                          ///<   load as a code segment
#define NEF_RELOAD      0x0200            ///< reload the file at the same place:
                                          ///<   - don't create segments
                                          ///<   - don't create fixup info
                                          ///<   - don't import segments
                                          ///<   - etc.
                                          ///<
                                          ///< Load only the bytes into the base.
                                          ///< A loader should have the #LDRF_RELOAD
                                          ///< bit set.
#define NEF_FLAT        0x0400            ///< Autocreate FLAT group (PE)
#define NEF_MINI        0x0800            ///< Create mini database (do not copy
                                          ///< segment bytes from the input file;
                                          ///< use only the file header metadata)
#define NEF_LOPT        0x1000            ///< Display additional loader options dialog
#define NEF_LALL        0x2000            ///< Load all segments without questions
                """
    neflags = (
        idaapi.NEF_CODE  # load as a code segment
        | idaapi.NEF_SEGS  # create segments
        | idaapi.NEF_MAN  # manual load
    )
    success = idaapi.load_binary_file(str(file_path), li, neflags, 0, 0, address, 0)
    idaapi.close_linput(li)
    return success


def handle_dropped_file(file_path: Path, shift_pressed: bool = False) -> bool:
    logger.debug(f"Handling dropped file: {file_path}")

    # note the absence of return statement in each case; we want to add to recent files in all cases except a few
    match file_path.suffix.lower():
        case ".h" | ".hpp" | ".hh" | ".hxx" | ".c" | ".cpp" | ".cc" | ".cxx":
            logger.debug(f"Recognized header file: {file_path}")
            parse_srclang_file(file_path)

        case ".til":
            logger.debug(f"Recognized TIL file: {file_path}")
            idaapi.add_til(str(file_path), 0)

        case ".sig":
            logger.debug(f"Recognized SIG file: {file_path}")
            idaapi.plan_to_apply_idasgn(str(file_path))

        case ".pdb":
            logger.debug(f"Recognized PDB file: {file_path}")
            load_pdb(str(file_path), only_types=True)

        case ".py" | ".pyc" | ".pyo" | ".pyw" | ".pyx" | ".pyi" | ".pyz" | ".pyz":
            logger.debug(f"Recognized Python script file: {file_path}")
            do_run = shift_pressed or (
                idaapi.ask_yn(
                    idaapi.ASKBTN_NO,
                    "AUTOHIDE DATABASE\nDo you want to execute the Python script?",
                )
                == idaapi.ASKBTN_YES
            )
            if do_run:
                execute_python_script(file_path)
            else:
                return False

        case ".idc":
            logger.debug(f"Recognized IDC script file: {file_path}")
            handle_idc(file_path)

        case ".ids" | ".idt":
            logger.debug(f"Recognized IDS/IDT file: {file_path}")
            idaapi.load_ids_module(str(file_path))

        case ".dbg":
            logger.debug(f"Recognized DBG file: {file_path}")
            idaapi.load_dbg_dbginfo(str(file_path))

        case ".tds":
            # raise NotImplementedError(
            #     "TDS file handling is not supported; IDA does not provide an API for it"
            # )
            logger.warning(
                "TDS file handling is not supported; IDA does not provide an API for it"
            )
            return False

        case _:
            if shift_pressed:
                # don't add to recent files, as it's probably a one-time load
                return load_file(str(file_path))
            logger.debug(f"Unrecognized file type: {file_path}")
            return False
    RecentDroppedFilenames.add_file_path(str(file_path))
    return True


def execute_python_script(file_path):
    try:
        source_code = file_path.read_text(encoding="utf-8")
        compiled_code = compile(source_code, str(file_path), "exec")
        exec(compiled_code)
    except Exception as e:
        logger.error(f"Error executing Python script {file_path}: {e}")
        import traceback

        traceback.print_exc()


def handle_idc(file_path):
    print(f"Handling dropped script file: {file_path}")
    v = idaapi.idc_value_t()
    v.clear()
    args = idaapi.idc_value_t()
    args.clear()
    idaapi.exec_idc_script(v, str(file_path), "main", args, 0)

    """
            void __fastcall run_script(const char *a1)
{
  _BOOL8 v2; // x0
  const char *file_ext; // x0
  extlang_t *extlang; // x0
  extlang_t *v5; // x20
  bool (__cdecl *compile_file)(const char *, const char *, qstring *); // x8
  char *array; // x8
  qstring vec; // [xsp+10h] [xbp-30h] BYREF

  memset(&vec, 0, sizeof(vec));
  v2 = qfileexist(file: a1);
  if ( v2 )
  {
    sub_10016ECE4(a1: v2, a9: a1);
    file_ext = get_file_ext(file: a1);
    extlang = (extlang_t *)find_extlang(str: file_ext, kind: FIND_EXTLANG_BY_EXT);
    v5 = extlang;
    if ( extlang )
    {
      compile_file = extlang->compile_file;
      if ( compile_file )
      {
        if ( (extlang->flags & 1) == 0 )
        {
          if ( !compile_file(a1, 0LL, &vec) )
            goto LABEL_13;
LABEL_11:
          --v5->refcnt;
          goto LABEL_18;
        }
      }
    }
    if ( compile_idc_file(file: a1, errbuf: &vec, cpl_flags: 3) && call_idc_func(result: 0LL, fname: "main", args: 0LL, argsnum: 0LL, errbuf: &vec, resolver: 0LL) )
    {
      if ( !v5 )
        goto LABEL_18;
      goto LABEL_11;
    }
    if ( v5 )
LABEL_13:
      --v5->refcnt;
  }
  else
  {
    vec.body.array = (char *)qvector_reserve(&vec, old: 0LL, cnt: 0x16uLL, elsize: 1uLL);
    vec.body.n = 22LL;
    strcpy(vec.body.array, "script does not exist");
  }
  if ( vec.body.n )
    array = vec.body.array;
  else
    array = &byte_100317AA0;
  sub_100007F40("%s: %s", a1, array);
LABEL_18:
  qfree(alloc: vec.body.array);
}
"""


class FileDropFilter(QtCore.QObject):
    def on_drop(self, obj, event: QtGui.QDropEvent):
        if not event.mimeData().hasUrls():
            return False

        shift_pressed = (
            event.keyboardModifiers() == QtCore.Qt.KeyboardModifier.ShiftModifier
        )

        handled_some = False
        for url in event.mimeData().urls():
            file_path = Path(url.toLocalFile())
            if not file_path.exists():
                logger.warning(f"Dropped file does not exist: {file_path}")
                continue

            handled_some |= handle_dropped_file(file_path, shift_pressed=shift_pressed)
        return handled_some

    def eventFilter(self, obj, event):
        v = False
        try:
            if event.type() == QtCore.QEvent.Type.Drop:
                print(f"Drop on {obj} {event.mimeData().urls()}")
                handled = self.on_drop(obj, event)
                if handled:
                    event.acceptProposedAction()
                    return True

            v = super().eventFilter(obj, event)
        except Exception as e:
            print(f"Exception in eventFilter: {e}")
            import traceback

            traceback.print_exc()

        return v


class open_recent_files_ah_t(idaapi.action_handler_t):
    def activate(self, ctx: idaapi.action_ctx_base_t):
        c = RecentDroppedFilesChooser(
            title="Recent dropped files",
            flags=idaapi.Choose.CH_QFLT
            | idaapi.Choose.CH_QFTYP_REGEX
            | idaapi.Choose.CH_NO_STATUS_BAR
            | idaapi.Choose.CH_CAN_DEL,
        )
        c.Show(modal=True)
        return

    def update(self, ctx: idaapi.action_ctx_base_t):
        return idaapi.AST_ENABLE_ALWAYS


def get_main_window():
    windows = QtWidgets.QApplication.allWindows()
    for w in windows:
        if (
            isinstance(w, QtGui.QWindow)
            and w.objectName() == "IDAMainWindowClassWindow"
        ):
            return w

    return None


class drop_all_the_files_plugin_t(idaapi.plugin_t):
    comment = "This plugin allows dropping various file types into IDA: headers, TILs, SIGs, PDBs, scripts"
    help = ""
    wanted_name = "DropAllTheFiles"
    flags = idaapi.PLUGIN_HIDE
    recent_action_name = "DropAllTheFiles:Recent"

    def init(self):
        addon = idaapi.addon_info_t()
        addon.id = "milankovo.drop_all_the_files"
        addon.name = "Drop All The Files"
        addon.producer = "Milanek"
        addon.url = "https://github.com/milankovo/ida-drop-all-the-files"
        addon.version = "1.2.0"
        idaapi.register_addon(addon)

        self.filter = None
        idaapi.register_timer(1_000, self.install_drop_filter)
        self.register_actions()
        return idaapi.PLUGIN_KEEP

    def install_drop_filter(self):
        main_window = get_main_window()
        if main_window:
            self.filter = FileDropFilter()
            main_window.installEventFilter(self.filter)
            logger.info("Installed drop filter OK")
            return -1 # No more tries
        else:
            logger.error("No main window found")
            return 1_000 # Try again in 1 second

    def register_actions(self):
        recent_action = idaapi.action_desc_t(
            self.recent_action_name,
            "Recent dropped files",
            open_recent_files_ah_t(),
            shortcut="Alt-O",
            tooltip="Show recently dropped files",
            icon=64,
        )
        idaapi.register_action(recent_action)

        idaapi.attach_action_to_menu(
            "View/Recent dropped files", self.recent_action_name, idaapi.SETMENU_APP
        )

    def unregister_actions(self):
        idaapi.unregister_action(self.recent_action_name)

    def term(self):
        self.remove_drop_filter()
        self.unregister_actions()
        # RecentDroppedFilenames.normalize_list()

    def remove_drop_filter(self):
        if self.filter is None:
            return

        main_window = get_main_window()
        if not main_window:
            return
        main_window.removeEventFilter(self.filter)
        del self.filter
        self.filter = None

    def run(self, arg):
        pass


def PLUGIN_ENTRY():
    return drop_all_the_files_plugin_t()
