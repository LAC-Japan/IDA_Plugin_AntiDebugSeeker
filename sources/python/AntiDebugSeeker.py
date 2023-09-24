import idaapi
import ida_bytes
import idc
import idautils
import ida_kernwin
import ida_lines
import os
import re
import json

class AntiDebugResults(ida_kernwin.Choose):
    def __init__(self, title, items):
        ida_kernwin.Choose.__init__(self, title, [["Category Name", 20 | ida_kernwin.Choose.CHCOL_PLAIN],
                                                 ["Possible Anti-Debug API", 20 | ida_kernwin.Choose.CHCOL_PLAIN],
                                                 ["Address", 15 | ida_kernwin.Choose.CHCOL_HEX],
                                                 ["Possible Anti-Debug Technique", 25 | ida_kernwin.Choose.CHCOL_PLAIN],
                                                 ["Address", 15 | ida_kernwin.Choose.CHCOL_HEX]])
        self.items = items

    def OnGetSize(self):
        return len(self.items)

    def OnGetLine(self, n):
        return self.items[n]

    def OnDeleteLine(self, n):
        del self.items[n]
        return True

    def OnGetLineAttr(self, n):
        black = 0x000000
        gray = 0xC0C0C0
        if self.items[n][0] == "" and self.items[n][1] == "":
            return [ida_kernwin.Choose.CHCOL_PLAIN | black, ida_kernwin.Choose.CHCOL_PLAIN | black]
        elif n % 2 == 0:
            return [ida_kernwin.Choose.CHCOL_PLAIN | gray, ida_kernwin.Choose.CHCOL_PLAIN | gray]
        else:
            return [ida_kernwin.Choose.CHCOL_PLAIN | gray, ida_kernwin.Choose.CHCOL_PLAIN | gray]

    def OnSelectLine(self, n):
        col2_addr = self.items[n][2]
        col4_addr = self.items[n][4]

        if col2_addr:
            idaapi.jumpto(int(col2_addr, 16))
        if col4_addr:
            idaapi.jumpto(int(col4_addr, 16))

    def OnDblClick(self, n):
        widget = ida_kernwin.find_widget("Anti Debug Detection Results")
        if not widget:
            return

        sel = self.GetEmbSelection()
        if not sel:
            return

        col = sel[0].y
        addr = self.items[n][col]

        if addr:
            idaapi.jumpto(int(addr, 16))
        return 1

    def show(self):
        self.Show()

class ConfigEditorForm(ida_kernwin.Form):
    def __init__(self, file_path):
        self.file_path = file_path
        try:
            with open(file_path, 'r') as f:
                self.file_contents = f.read()
        except Exception as e:
            print("Error reading file: %s" % str(e))
            self.file_contents = ""

        F = ida_kernwin.Form
        F.__init__(self, r"""STARTITEM {id:txtInput}
BUTTON YES* Save
BUTTON CANCEL Cancel
Edit configuration
{FormChangeCb}
<##File contents:{txtInput}>
        """, {
            'txtInput': F.MultiLineTextControl(text=self.file_contents),
            'FormChangeCb': F.FormChangeCb(self.OnFormChange),
        })

    def OnFormChange(self, fid):
        return 1

    def OnButtonOk(self, code=0):
        try:
            with open(self.file_path, 'w') as f:
                f.write(self.GetControlValue(self.txtInput).text)
            return 1
        except Exception as e:
            print("Error writing to file: %s" % str(e))
            return 0

    def OnFormChange(self, fid):
        if fid == -2:
            self.OnButtonOk()
        return 1


class AntiDebugPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "Anti Debug Detection Plugin"
    help = "Detects the use of Anti Debug Technique"
    wanted_name = "AntiDebugSeeker"
    wanted_hotkey = "Ctrl-Shift-D"

    def init(self):
        idaapi.msg("AntiDebugSeeker initialized. Ctrl-Shift-D Start Analysis.\n")
        self.edit_config_hotkey_ctx = ida_kernwin.add_hotkey("Ctrl-Shift-E", self.edit_config)
        self.saved_results = []
        if self.edit_config_hotkey_ctx is None:
            idaapi.msg("Failed to register hotkey for config editor. It might be already in use.\n")
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        if arg == "edit":
            self.edit_config()
        elif arg == "details":
            self.show_anti_debug_details()
        else:
            idaapi.msg("AntiDebugSeeker is running...\n")
            self.detect_anti_debug_functions()

    def save_anti_debug_results(self, result_win):
        self.saved_results = result_win

    def collect_anti_debug_results(self):
        return self.saved_results

    def term(self):
        idaapi.msg("AntiDebugSeeker terminated.\n")
        idaapi.msg("Edit anti_debug.config : Switch Other tab and Press Ctrl+Shift+E.\n")

    def load_anti_debug_descriptions(self, file_name):
        
        plugin_dir = os.path.dirname(os.path.realpath(__file__))
        file_path = os.path.join(plugin_dir, file_name)
        with open(file_path, 'r') as f:
            return json.load(f)

    def edit_config(self):
        plugin_dir = os.path.dirname(os.path.realpath(__file__))
        file_path = os.path.join(plugin_dir, "anti_debug.config")
        editor = ConfigEditorForm(file_path)
        editor.Compile()
        editor.Execute()

    def load_config(self, file_name):
        config_data = {
            "Anti_Debug_API": {},
            "Anti_Debug_Technique": [],
            "default_search_range": None
        }

        plugin_dir = os.path.dirname(os.path.realpath(__file__))
        file_path = os.path.join(plugin_dir, file_name)

        current_section = None
        current_category = None

        with open(file_path, "r") as f:
            for line in f:
                line = line.strip()

                if line.startswith("###") and line.endswith("###"):
                    current_section = line[3:-3]
                    current_category = None
                elif line.startswith("[") and line.endswith("]"):
                    current_category = line[1:-1]
                    if current_section == "Anti_Debug_API":
                        config_data[current_section][current_category] = []
                    elif current_section == "Anti_Debug_Technique":
                        config_data["Anti_Debug_Technique"].append({
                            "name": current_category,
                            "search_keyword": None,
                            "nearby_keyword": None,
                            "nearby_keyword2": None,
                            "search_range": config_data["default_search_range"]
                        })
                elif current_category and line and current_section in ["Anti_Debug_API", "Anti_Debug_Technique"]:
                    if current_section == "Anti_Debug_API":
                        config_data[current_section][current_category].append(line)
                    elif current_section == "Anti_Debug_Technique":
                        entry = config_data["Anti_Debug_Technique"][-1]
                        if line.startswith("search_range="):
                            entry["search_range"] = int(line.split("=")[1])
                        else:
                            if entry["search_keyword"] is None:
                                entry["search_keyword"] = line
                            elif entry["nearby_keyword"] is None:
                                entry["nearby_keyword"] = line
                            elif entry["nearby_keyword2"] is None:
                                entry["nearby_keyword2"] = line
                elif line.startswith("default_search_range=") and current_section == "Anti_Debug_Technique":
                    config_data["default_search_range"] = int(line.split("=")[1])

        return config_data



    def search_asm(self, search_keyword, nearby_keyword=None, nearby_keyword2=None, search_range=None):
        api_names = set(name for _, name in idautils.Names())
        one_keyword_match = []
        matching_sets = []

        def search_keyword_in_code(keyword, ea, disasm_line, end_addr):
            found = False
            keyword_addr = None
            
            keyword_is_int = False
            try:
                keyword_as_int = int(keyword)
                keyword_is_int = True
            except ValueError:
                pass
            
            regex_matched = re.search(r'\b' + re.escape(str(keyword)) + r'(h)?\b', disasm_line)
            comment = ida_bytes.get_cmt(ea, 0)
            
            def check_found(keyword_is_int, regex_matched):
                return (not keyword_is_int) or (keyword_is_int and regex_matched)

            if keyword in api_names:
                keyword_addr = idc.get_name_ea_simple(keyword)

                if keyword_addr != idaapi.BADADDR and ea in list(idautils.CodeRefsTo(keyword_addr, 0)):
                    found = True
                    keyword_addr = ea

            if comment and keyword in comment:
               found = check_found(keyword_is_int, regex_matched)
                
            if keyword in disasm_line:
               found = check_found(keyword_is_int, regex_matched)

            if not found:
                ref_addr = idc.get_operand_value(ea, 0)
                if ref_addr != idaapi.BADADDR:
                    strtype = idaapi.get_str_type(ref_addr)
                    if strtype == 0xFFFFFFFF:
                        return False, None
                    ref_string = ida_bytes.get_strlit_contents(ref_addr, ida_bytes.get_item_size(ref_addr), int(strtype))
                    if ref_string and keyword in ref_string.decode('utf-8', errors='ignore'):
                        found = check_found(keyword_is_int, regex_matched)
                        
            if found:
               if keyword_addr != ea:
                  keyword_addr = ea
                        
            return found, keyword_addr
            
        entry_point = idc.get_inf_attr(idc.INF_START_IP)  
        entry_section = idaapi.getseg(entry_point)
        
        for seg_ea in idautils.Segments():
            if seg_ea != entry_section.start_ea:  
                continue
               
            ea = seg_ea
            end_addr = idc.get_segm_end(seg_ea)

            while ea < end_addr:
                disasm_line = idc.GetDisasm(ea)
                search_found, search_addr = search_keyword_in_code(search_keyword, ea, disasm_line, end_addr)

                if search_found:
                    base_addr = search_addr if search_keyword in api_names else ea
                    if not nearby_keyword and not nearby_keyword2:
                        one_keyword_match.append(hex(base_addr))
                    else:
                        next_ea = base_addr
                        while next_ea - base_addr < search_range and next_ea < end_addr:
                            disasm_next_line = idc.GetDisasm(next_ea)
                            found_nearby, nearby_addr = search_keyword_in_code(nearby_keyword, next_ea, disasm_next_line, end_addr)
                            if found_nearby:
                                if not nearby_keyword2:
                                    matching_sets.append((hex(base_addr), hex(next_ea), None))
                                else:
                                    next_ea2 = next_ea
                                    while next_ea2 - next_ea < search_range and next_ea2 < end_addr:
                                        disasm_next_line2 = idc.GetDisasm(next_ea2)
                                        found_nearby2, nearby_addr2 = search_keyword_in_code(nearby_keyword2, next_ea2, disasm_next_line2, end_addr)
                                        if found_nearby2:
                                            matching_sets.append((hex(base_addr), hex(next_ea), hex(next_ea2)))
                                        next_ea2 = idc.next_head(next_ea2)
                            next_ea = idc.next_head(next_ea)
                ea = idc.next_head(ea)

        if one_keyword_match:
           print(f"[Result] Found {len(one_keyword_match)} match(es) for First_keyword '{search_keyword}' under the rule of specifying one keyword.")
           return one_keyword_match
            
        if matching_sets:
           print(f"[Result] Found {len(matching_sets)} matching set(s).")
           return matching_sets
        else:
            return None, None, None

    def detect_anti_debug_functions(self):
        results = []
        color = 0x98FB98
        color2 = 0xAAD4FF

        def set_item_color(address, color):
            try:
                idaapi.set_item_color(int(address, 16), color)
            except TypeError as e:
                print(f"Error: {e}")

        def add_comment(address, comment_name):
            existing_comment = idaapi.get_cmt(address, 0)
            comment_description = anti_debug_techniques_descriptions.get(comment_name, "")
            comment_text = comment_name if existing_comment is None else existing_comment + " | " + comment_name
            if comment_description:
                comment_text += " - " + comment_description
            idaapi.set_cmt(address, comment_text, 0)

        config_data = self.load_config("anti_debug.config")
        anti_debug_functions = config_data["Anti_Debug_API"]
        search_patterns = config_data["Anti_Debug_Technique"]
        default_search_range = config_data["default_search_range"]
        anti_debug_techniques_descriptions = self.load_anti_debug_descriptions("anti_debug_techniques_descriptions.json")
        
        def is_address_in_target_sections(address, func, entry_section):
           if entry_section is not None:
               section_start = entry_section.start_ea
               section_end = entry_section.end_ea
               if section_start <= address <= section_end:
                   return True

           if func is None:
               return False

           func_start = func.start_ea
           func_end = func.end_ea

           code_section = idaapi.getseg(func_start)
           if code_section is not None and code_section.perm & idaapi.SEGPERM_EXEC:
               return True

           return False

            
        entry_point = idc.get_inf_attr(idc.INF_START_IP)
        entry_section = idaapi.getseg(entry_point)

        for category, functions in anti_debug_functions.items():
            for func_name in functions:
                func_addr = idc.get_name_ea_simple(func_name)

                if func_addr == idaapi.BADADDR:
                    continue

                xrefs = list(idautils.XrefsTo(func_addr))
                
                if xrefs:
                    idaapi.msg(f"{func_name} function found.\n")
                else:
                    continue

                processed_addresses = set()
                for xref in xrefs:
                    address = xref.frm
                    address_str = f"0x{address:X}"
                    containing_func = idaapi.get_func(xref.frm)
                    
                    if address_str in processed_addresses:
                       continue
                    
                    if is_address_in_target_sections(address, containing_func, entry_section):
                        idaapi.msg(f"  {address_str}\n")
                        set_item_color(address_str, color)
                        add_comment(xref.frm, category)
                        results.append([category, func_name, address_str, "", ""])
                        processed_addresses.add(address_str)

        start_addr = idaapi.cvar.inf.min_ea
        end_addr = idaapi.cvar.inf.max_ea

        for pattern in search_patterns:
            search_keyword = pattern["search_keyword"]
            nearby_keyword = pattern.get("nearby_keyword", None)
            nearby_keyword2 = pattern.get("nearby_keyword2", None)
            search_range = pattern.get("search_range", default_search_range)

            asm_address = nearby_address = nearby2_address = None

            if nearby_keyword2:
                result = self.search_asm(search_keyword, nearby_keyword, nearby_keyword2, search_range=search_range)
            elif nearby_keyword:
                result = self.search_asm(search_keyword, nearby_keyword, search_range=search_range)
            else:
                result = self.search_asm(search_keyword)
                
            if result:
                if isinstance(result, list):
                    print(f"Found for pattern {pattern['name']}.")
                    for element in result: 
                        if element is not None:
                           if isinstance(element, tuple):
                               asm_address, nearby_address, nearby2_address = element + (None,) * (3 - len(element))
                               for address in [asm_address, nearby_address, nearby2_address]:
                                   if address is not None:
                                       address_int = int(address, 16)
                                       set_item_color(address, color2) 
                                       
                               if asm_address is not None:
                                   address_int = int(asm_address, 16)
                                   add_comment(address_int, pattern["name"])
                                   results.append(["", "", "", pattern["name"], str(asm_address), ""])

                           elif isinstance(element, str):
                              address_int = int(element, 16)
                              set_item_color(element, color2)
                              add_comment(address_int, pattern["name"])
                              results.append(["", "", "", pattern["name"], str(element), ""])
                              
                elif isinstance(result, tuple):
                    if result == (None, None, None):
                       print(f"Nothing Found for pattern {pattern['name']}.")

        sorted_results = sorted(results, key=lambda x: (int(x[2], 16) if x[2] else int(x[4], 16) if x[4] else float("inf")))
        self.save_anti_debug_results(sorted_results)

        result_win = AntiDebugResults("Anti Debug Detection Results", sorted_results)
        result_win.show()

def PLUGIN_ENTRY():
    return AntiDebugPlugin()
